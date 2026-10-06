package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sealbro/go-garmin-connect/internal/oauth1"
)

// Service drives the Garmin Connect SSO flow:
//
//  1. GET embed URL → capture rotating cookies
//  2. GET signin URL → scrape CSRF token from HTML
//  3. POST signin → receive OAuth1 ticket (or 302 to MFA flow)
//  4. (optional) POST MFA code → receive ticket
//  5. GET preauthorized?ticket=… → exchange for OAuth1 token
//  6. POST exchange/user/2.0 → exchange for OAuth2 token
//
// The Service is stateless apart from the http.Client; per-request mutable
// state (cookies, CSRF) lives on the AuthParameters implementation.
type Service struct {
	httpClient  *http.Client
	params      AuthParameters
	mfaProvider MfaCodeProvider
}

// NewService builds a Service. httpClient must NOT follow redirects
// automatically — the SSO flow distinguishes between successful sign-in and
// MFA redirects by their 302 Location header. Pass nil to get an internal
// client that disables redirects for you.
func NewService(httpClient *http.Client, params AuthParameters, mfa MfaCodeProvider) *Service {
	if httpClient == nil {
		httpClient = newNoRedirectClient()
	}
	if mfa == nil {
		mfa = NotImplementedMfa{}
	}
	return &Service{httpClient: httpClient, params: params, mfaProvider: mfa}
}

// NewNoRedirectClient returns an http.Client suitable for the SSO flow:
// redirects are NOT followed, and the cookie jar is disabled (the auth flow
// captures cookies from headers manually).
func NewNoRedirectClient() *http.Client { return newNoRedirectClient() }

func newNoRedirectClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Refresh runs the full SSO flow and returns a fresh OAuth2 token. On
// failure it returns an *AuthenticationError tagged with the step that
// failed.
func (s *Service) Refresh(ctx context.Context) (*OAuth2Token, error) {
	cookies, err := s.requestCookies(ctx)
	if err != nil {
		return nil, err
	}
	s.params.SetCookies(cookies)

	csrf, err := s.requestCsrf(ctx)
	if err != nil {
		return nil, err
	}
	s.params.SetCsrf(csrf)

	ticket, err := s.getOAuthTicket(ctx)
	if err != nil {
		return nil, err
	}

	consumer := s.params.ConsumerCredentials()
	token1, err := s.getOAuth1Token(ctx, ticket, consumer)
	if err != nil {
		return nil, err
	}

	token2, err := s.getOAuth2Token(ctx, token1, consumer)
	if err != nil {
		return nil, &AuthenticationError{
			Code:    CodeOAuth2TokenNotFound,
			Message: "auth appeared successful but failed to get the OAuth2 token",
			Err:     err,
		}
	}
	return token2, nil
}

func (s *Service) ssoURL() string    { return "https://sso." + s.params.Domain() + "/sso" }
func (s *Service) embedURL() string  { return s.ssoURL() + "/embed" }
func (s *Service) signinURL() string { return s.ssoURL() + "/signin" }
func (s *Service) mfaURL() string    { return s.ssoURL() + "/verifyMFA/loginEnterMfaCode" }

func (s *Service) requestCookies(ctx context.Context) (string, error) {
	q := cloneValues(s.params.QueryParameters())
	q.Set("gauthHost", s.ssoURL())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.embedURL()+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	for k, v := range s.params.Headers() {
		req.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", &AuthenticationError{Code: CodeCookiesNotFound, Message: "failed to fetch cookies from Garmin"}
	}

	var sb strings.Builder
	for _, c := range resp.Header.Values("Set-Cookie") {
		sb.WriteString(c)
		sb.WriteByte(';')
	}
	cookies := sb.String()
	if strings.TrimSpace(cookies) == "" {
		return "", &AuthenticationError{Code: CodeCookiesNotFound, Message: "found cookies but they are empty"}
	}
	return cookies, nil
}

var csrfRegex = regexp.MustCompile(`name="_csrf"\s+value="(.+?)"`)

func findCsrfToken(body string, code AuthErrorCode) (string, error) {
	if body == "" {
		return "", &AuthenticationError{Code: code, Message: "failed to find csrf token: response is empty"}
	}
	m := csrfRegex.FindStringSubmatch(body)
	if len(m) < 2 {
		return "", &AuthenticationError{Code: code, Message: "failed to find regex match for csrf token"}
	}
	if strings.TrimSpace(m[1]) == "" {
		return "", &AuthenticationError{Code: code, Message: "found csrf token but its empty"}
	}
	return m[1], nil
}

func (s *Service) signinQueryParams() url.Values {
	q := cloneValues(s.params.QueryParameters())
	embed := s.embedURL()
	q.Set("gauthHost", embed)
	q.Set("service", embed)
	q.Set("source", embed)
	q.Set("redirectAfterAccountLoginUrl", embed)
	q.Set("redirectAfterAccountCreationUrl", embed)
	return q
}

func (s *Service) requestCsrf(ctx context.Context) (string, error) {
	q := s.signinQueryParams()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.signinURL()+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	for k, v := range s.params.Headers() {
		req.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", &AuthenticationError{Code: CodeCsrfTokenNotFound, Message: "failed to fetch csrf token from Garmin"}
	}
	return findCsrfToken(string(body), CodeCsrfTokenNotFound)
}

const maxRedirects = 3

// handleRedirect manually follows up to maxRedirects 302s. The Service's
// http.Client returns ErrUseLastResponse for redirects so the auth flow can
// distinguish MFA redirects from successful logins; once a redirect is
// confirmed harmless we follow it ourselves.
func (s *Service) handleRedirect(ctx context.Context, resp *http.Response, depth int) (string, error) {
	if depth >= maxRedirects {
		return "", nil
	}
	loc, err := resp.Location()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil)
	if err != nil {
		return "", err
	}
	r2, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer r2.Body.Close()
	if r2.StatusCode == http.StatusFound || r2.StatusCode == http.StatusMovedPermanently {
		return s.handleRedirect(ctx, r2, depth+1)
	}
	body, err := io.ReadAll(r2.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

var ticketRegex = regexp.MustCompile(`embed\?ticket=([^"]+)"`)

func (s *Service) getOAuthTicket(ctx context.Context) (string, error) {
	q := s.signinQueryParams()
	signinURL := s.signinURL() + "?" + q.Encode()

	const tooManyRequestsAttempts = 5
	var resp *http.Response
	var body []byte
	for i := 0; i < tooManyRequestsAttempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, signinURL, strings.NewReader(s.params.FormParameters().Encode()))
		if err != nil {
			return "", err
		}
		for k, v := range s.params.Headers() {
			req.Header.Set(k, v)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("referer", s.signinURL())
		req.Header.Set("NK", "NT")

		r, err := s.httpClient.Do(req)
		if err != nil {
			return "", err
		}
		body, _ = io.ReadAll(r.Body)
		r.Body.Close()
		resp = r
		if r.StatusCode != http.StatusTooManyRequests {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Duration(3*(i+1)) * time.Second):
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
		return "", &AuthenticationError{
			Code:    CodeOAuth1TicketNotFound,
			Message: fmt.Sprintf("garmin authentication failed. %s: %s", resp.Status, string(body)),
		}
	}

	content := string(body)
	mfaRedirect := false
	if resp.StatusCode == http.StatusFound {
		if loc := resp.Header.Get("Location"); strings.Contains(loc, s.mfaURL()) {
			mfaRedirect = true
		}
	}
	mfaCooldown := resp.StatusCode == http.StatusOK && strings.Contains(content, "validateMfaCodeAndPrivacyConsents()")

	if mfaRedirect || mfaCooldown {
		if mfaRedirect {
			redirected, err := s.handleRedirect(ctx, resp, 0)
			if err != nil {
				return "", err
			}
			content = redirected
		}
		csrf, err := findCsrfToken(content, CodeCsrfTokenNotFound)
		if err != nil {
			return "", err
		}
		s.params.SetCsrf(csrf)

		mfaCode, err := s.mfaProvider.GetMfaCode(ctx)
		if err != nil {
			return "", &AuthenticationError{Code: CodeMfaInvalidCode, Message: "MFA provider returned an error", Err: err}
		}
		if mfaCode == "" {
			return "", &AuthenticationError{Code: CodeMfaInvalidCode, Message: "MFA Code provided is empty"}
		}
		content, err = s.completeMfa(ctx, mfaCode)
		if err != nil {
			return "", err
		}
	}

	m := ticketRegex.FindStringSubmatch(content)
	if len(m) < 2 || strings.TrimSpace(m[1]) == "" {
		return "", &AuthenticationError{Code: CodeOAuth1TicketNotFound, Message: "failed to find regex match for ticket"}
	}
	return m[1], nil
}

func (s *Service) completeMfa(ctx context.Context, code string) (string, error) {
	q := s.signinQueryParams()
	mfaURL := s.mfaURL() + "?" + q.Encode()

	form := s.params.MfaParameters()
	form.Set("mfa-code", code)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mfaURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	for k, v := range s.params.Headers() {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusFound {
		// Re-issue the request with auto-following enabled by the SSO server.
		// Drain the body before redirecting, then call handleRedirect.
		// (The body has already been read above, but resp.Header.Location is
		// what we need.)
		// Reconstruct a redirect-capable response for handleRedirect.
		fakeResp := &http.Response{StatusCode: http.StatusFound, Header: resp.Header, Request: resp.Request}
		return s.handleRedirect(ctx, fakeResp, 0)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return string(body), nil
	}
	if string(body) == "error code: 1020" {
		return "", &AuthenticationError{Code: CodeMfaBlockedCloudflare, Message: "MFA: Garmin Authentication Failed. Blocked by CloudFlare."}
	}
	return "", &AuthenticationError{Code: CodeMfaInvalidCode, Message: "MFA: MFA Code rejected by Garmin"}
}

func (s *Service) getOAuth1Token(ctx context.Context, ticket string, c ConsumerCredentials) (oauth1Token, error) {
	requestURL := fmt.Sprintf(
		"https://connectapi.%s/oauth-service/oauth/preauthorized?ticket=%s&login-url=%s&accepts-mfa-tokens=true",
		s.params.Domain(), ticket, s.embedURL(),
	)

	header, err := oauth1.AuthorizationHeader(http.MethodGet, requestURL, oauth1.Credentials{
		ConsumerKey:    c.ConsumerKey,
		ConsumerSecret: c.ConsumerSecret,
	}, false)
	if err != nil {
		return oauth1Token{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return oauth1Token{}, err
	}
	req.Header.Set("User-Agent", s.params.UserAgent())
	req.Header.Set("Authorization", header)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return oauth1Token{}, &AuthenticationError{Code: CodeOAuth1TokenNotFound, Message: "auth appeared successful but failed to get the OAuth1 token", Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return oauth1Token{}, err
	}
	if strings.TrimSpace(string(body)) == "" {
		return oauth1Token{}, &AuthenticationError{Code: CodeOAuth1TokenNotFound, Message: "auth appeared successful but returned OAuth1 Token response is empty"}
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return oauth1Token{}, &AuthenticationError{Code: CodeOAuth1TokenNotFound, Message: "failed to parse OAuth1 response", Err: err}
	}

	tok := oauth1Token{Token: values.Get("oauth_token"), TokenSecret: values.Get("oauth_token_secret")}
	if tok.Token == "" {
		return oauth1Token{}, &AuthenticationError{Code: CodeOAuth1TokenNotFound, Message: fmt.Sprintf("OAuth1 token is empty. response: %s", string(body))}
	}
	if tok.TokenSecret == "" {
		return oauth1Token{}, &AuthenticationError{Code: CodeOAuth1TokenNotFound, Message: fmt.Sprintf("OAuth1 token secret is empty. response: %s", string(body))}
	}
	return tok, nil
}

func (s *Service) getOAuth2Token(ctx context.Context, t oauth1Token, c ConsumerCredentials) (*OAuth2Token, error) {
	requestURL := fmt.Sprintf("https://connectapi.%s/oauth-service/oauth/exchange/user/2.0", s.params.Domain())

	header, err := oauth1.AuthorizationHeader(http.MethodPost, requestURL, oauth1.Credentials{
		ConsumerKey:    c.ConsumerKey,
		ConsumerSecret: c.ConsumerSecret,
		Token:          t.Token,
		TokenSecret:    t.TokenSecret,
	}, true)
	if err != nil {
		return nil, err
	}

	// The C# code submits a single empty key/value pair as the body. Replicate
	// to keep the wire format identical.
	body := strings.NewReader("=")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.params.UserAgent())
	req.Header.Set("Authorization", header)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth2 exchange returned %s: %s", resp.Status, string(raw))
	}

	var out OAuth2Token
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode oauth2 token: %w", err)
	}
	if out.AccessToken == "" {
		return nil, errors.New("oauth2 exchange returned empty access_token")
	}
	return &out, nil
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		for _, vv := range vs {
			out.Add(k, vv)
		}
	}
	return out
}
