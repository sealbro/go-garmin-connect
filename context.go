package garmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sealbro/go-garmin-connect/auth"
)

// Context is the HTTP backbone shared by the read/write halves of Client.
// It owns the OAuth2 token lifecycle (refresh-on-401/403, single-flight
// refresh under contention), and decorates every request with the bearer
// header and Garmin's mandatory `di-backend` host hint.
type Context struct {
	httpClient  *http.Client
	authParams  auth.AuthParameters
	tokenCache  auth.TokenCache
	authService *auth.Service

	authLock sync.Mutex

	// profile caches the SocialProfile lookup that wellness endpoints depend on
	// (Garmin keys steps/heartRate/sleep by displayName, not user ID).
	profileMu sync.RWMutex
	profile   *GarminSocialProfile
}

// ContextOption configures a Context.
type ContextOption func(*Context)

// WithMfaProvider supplies an MFA code provider for accounts with MFA enabled.
// Default is auth.NotImplementedMfa, which fails fast.
func WithMfaProvider(p auth.MfaCodeProvider) ContextOption {
	return func(c *Context) {
		c.authService = auth.NewService(authClientFor(c.httpClient), c.authParams, p)
	}
}

// WithTokenCache replaces the default in-memory cache. Use FileTokenCache to
// persist tokens between process restarts.
func WithTokenCache(cache auth.TokenCache) ContextOption {
	return func(c *Context) { c.tokenCache = cache }
}

// NewContext builds a Context from an authenticated http.Client and auth
// parameters. The same http.Client is reused for both authenticated API
// calls (which it should follow redirects on) and the SSO flow — but the
// SSO flow needs a separate non-redirecting client, which we construct
// internally. Callers that want full control over both can use
// auth.NewService directly.
func NewContext(httpClient *http.Client, params auth.AuthParameters, opts ...ContextOption) *Context {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	c := &Context{
		httpClient:  httpClient,
		authParams:  params,
		tokenCache:  auth.NewInMemoryTokenCache(),
		authService: auth.NewService(authClientFor(httpClient), params, nil),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// authClientFor returns a non-redirecting http.Client suitable for the SSO
// flow, reusing the timeout and Transport from the supplied API client when
// possible.
func authClientFor(api *http.Client) *http.Client {
	c := auth.NewNoRedirectClient()
	if api != nil {
		c.Transport = api.Transport
		if api.Timeout > 0 {
			c.Timeout = api.Timeout
		}
	}
	return c
}

const (
	maxAttempts          = 3
	delayAfterFailedAuth = 300 * time.Millisecond
)

// getOrRefreshToken returns a cached token unless force is true, in which
// case it refreshes via the SSO flow. Concurrent refreshes are coalesced via
// authLock to prevent thundering herds when many requests race a 401.
func (c *Context) getOrRefreshToken(ctx context.Context, force bool) (*auth.OAuth2Token, error) {
	if !force {
		if t, err := c.tokenCache.Get(ctx); err != nil {
			return nil, err
		} else if t != nil {
			return t, nil
		}
	}

	c.authLock.Lock()
	defer c.authLock.Unlock()

	// Double-check inside the critical section — another goroutine may have
	// refreshed while we waited.
	if !force {
		if t, err := c.tokenCache.Get(ctx); err != nil {
			return nil, err
		} else if t != nil {
			return t, nil
		}
	}

	tok, err := c.authService.Refresh(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.tokenCache.Set(ctx, tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// GetAndDeserialize is the typed-GET helper used by every read endpoint.
// It returns true if the response decoded successfully; false signals a 204
// No Content (callers receive a zero-value out and can branch on the bool).
func GetAndDeserialize[T any](ctx context.Context, c *Context, urlPath string) (T, error) {
	var out T
	resp, err := c.MakeHTTPGet(ctx, urlPath, nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return out, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("decode %s: %w", urlPath, err)
	}
	return out, nil
}

// MakeHTTPGet issues an authenticated GET. headers may be nil.
func (c *Context) MakeHTTPGet(ctx context.Context, urlPath string, headers map[string]string) (*http.Response, error) {
	return c.makeHTTPRequest(ctx, http.MethodGet, urlPath, headers, nil, "")
}

// MakeHTTPPost serializes body as JSON and POSTs it to urlPath.
func (c *Context) MakeHTTPPost(ctx context.Context, urlPath string, body any, headers map[string]string) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return c.makeHTTPRequest(ctx, http.MethodPost, urlPath, headers, bytes.NewReader(raw), "application/json")
}

// MakeHTTPPut serializes body as JSON and PUTs it to urlPath.
func (c *Context) MakeHTTPPut(ctx context.Context, urlPath string, body any, headers map[string]string) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return c.makeHTTPRequest(ctx, http.MethodPut, urlPath, headers, bytes.NewReader(raw), "application/json")
}

// MakeHTTPDelete issues an authenticated DELETE.
func (c *Context) MakeHTTPDelete(ctx context.Context, urlPath string, headers map[string]string) (*http.Response, error) {
	return c.makeHTTPRequest(ctx, http.MethodDelete, urlPath, headers, nil, "")
}

// MakeHTTPRequest is the lower-level escape hatch used by file uploads. It
// accepts an arbitrary body reader plus content type so callers can post
// multipart/form-data without going through json.Marshal.
func (c *Context) MakeHTTPRequest(ctx context.Context, method, urlPath string, headers map[string]string, body io.Reader, contentType string) (*http.Response, error) {
	return c.makeHTTPRequest(ctx, method, urlPath, headers, body, contentType)
}

// makeHTTPRequest is the request-with-retry workhorse. The body is buffered
// upfront so retries can re-read it after a 401/403-driven token refresh.
func (c *Context) makeHTTPRequest(ctx context.Context, method, urlPath string, headers map[string]string, body io.Reader, contentType string) (*http.Response, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, err
		}
	}

	force := false
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		tok, err := c.getOrRefreshToken(ctx, force)
		if err != nil {
			return nil, err
		}

		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.authParams.BaseURL()+urlPath, reqBody)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if cookies := c.authParams.Cookies(); cookies != "" {
			req.Header.Set("cookie", cookies)
		}
		req.Header.Set("authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("di-backend", "connectapi."+c.authParams.Domain())

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			resp.Body.Close()
			return nil, TooManyRequestsError{}
		case http.StatusOK, http.StatusNoContent, http.StatusCreated, http.StatusAccepted:
			return resp, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			details, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = &RequestError{URL: req.URL.String(), Status: resp.StatusCode, Details: string(details)}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delayAfterFailedAuth):
			}
			force = true
			continue
		default:
			details, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, &RequestError{URL: req.URL.String(), Status: resp.StatusCode, Details: string(details)}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("authentication failed after %d attempts: %w", maxAttempts, lastErr)
	}
	return nil, errors.New("authentication failed: unknown reason")
}
