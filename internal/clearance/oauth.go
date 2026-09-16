package clearance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Connect OAuth for the agent's DCR client: authorization-code + PKCE on a
// loopback redirect (RFC 8252 §7.3), then rotating refresh tokens
// (auth-core migration 0199). auth-core resolves the project from
// `?project_id=` on authorize and `X-Authio-Project` on the token endpoint,
// so both are sent explicitly — the CLI has no browser Origin.

const (
	ScopeTools = "tools:read tools:call"
	// refreshSkew renews an access token this long before expiry.
	refreshSkew = 60 * time.Second
)

// OAuthClient talks to auth-core for one agent credential.
type OAuthClient struct {
	AuthCoreURL string
	ProjectID   string
	ClientID    string
	Resource    string // RFC 8707 resource indicator (the Clearance origin)
	HTTP        *http.Client
}

func (o *OAuthClient) http() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// tokenResponse is auth-core's token endpoint envelope.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// AuthorizeURL builds the browser URL for the loopback flow.
func (o *OAuthClient) AuthorizeURL(redirectURI, state, challenge, scope string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", o.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("project_id", o.ProjectID)
	if o.Resource != "" {
		q.Set("resource", o.Resource)
	}
	return strings.TrimRight(o.AuthCoreURL, "/") + "/v1/auth/authorize?" + q.Encode()
}

func (o *OAuthClient) token(ctx context.Context, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.AuthCoreURL, "/")+"/v1/auth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Authio-Project", o.ProjectID)
	req.Header.Set("User-Agent", "authio-cli/clearance")
	resp, err := o.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr tokenResponse
	_ = json.Unmarshal(body, &tr)
	if resp.StatusCode >= 400 {
		if tr.Error == "" {
			return nil, fmt.Errorf("token endpoint: %s: %s", resp.Status, bytes.TrimSpace(body))
		}
		return nil, &OAuthError{Code: tr.Error, Description: tr.ErrorDesc, Status: resp.StatusCode}
	}
	if tr.AccessToken == "" {
		return nil, errors.New("token endpoint returned no access_token")
	}
	return &tr, nil
}

// OAuthError is an RFC 6749 §5.2 error from the token endpoint.
type OAuthError struct {
	Code        string
	Description string
	Status      int
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// Exchange redeems an authorization code.
func (o *OAuthClient) Exchange(ctx context.Context, code, redirectURI, verifier string) (*tokenResponse, error) {
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("client_id", o.ClientID)
	f.Set("code", code)
	f.Set("redirect_uri", redirectURI)
	f.Set("code_verifier", verifier)
	return o.token(ctx, f)
}

// Refresh rotates a refresh token.
func (o *OAuthClient) Refresh(ctx context.Context, refreshToken string) (*tokenResponse, error) {
	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("client_id", o.ClientID)
	f.Set("refresh_token", refreshToken)
	return o.token(ctx, f)
}

// LoopbackListener binds 127.0.0.1 on an ephemeral port (or a fixed one)
// and returns the redirect URI to register with the flow.
func LoopbackListener(port int) (net.Listener, string, error) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, "", err
	}
	addr := ln.Addr().(*net.TCPAddr)
	return ln, fmt.Sprintf("http://127.0.0.1:%d/callback", addr.Port), nil
}

// AwaitCallback serves the loopback redirect once and returns the code.
// It refuses a state mismatch and surfaces provider errors.
func AwaitCallback(ctx context.Context, ln net.Listener, state string) (string, error) {
	type result struct {
		code string
		err  error
	}
	ch := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		// The page never reflects a query value: the callback is reachable
		// by anything that can open a browser tab at 127.0.0.1, so treat
		// error/error_description as untrusted and report the detail only
		// on the terminal (where it is data, not markup).
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if e := q.Get("error"); e != "" {
			fmt.Fprint(w, "<h2>Authorization failed</h2><p>The authorization server refused the request. See your terminal for details.</p>")
			ch <- result{err: fmt.Errorf("authorization refused: %s %s", e, q.Get("error_description"))}
			return
		}
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			ch <- result{err: errors.New("state mismatch on loopback callback (possible CSRF); aborting")}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			ch <- result{err: errors.New("callback carried no code")}
			return
		}
		fmt.Fprint(w, "<h2>Signed in.</h2><p>You can close this tab and return to your terminal.</p>")
		ch <- result{code: code}
	})
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	select {
	case r := <-ch:
		return r.code, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// TokenSource returns a valid access token, refreshing (and persisting)
// when the cached one is within refreshSkew of expiry. A refresh failure
// with invalid_grant means the family was revoked or expired — the caller
// should tell the user to log in again.
type TokenSource struct {
	Store *TokenStore
	Cred  *AgentCredential
	OAuth *OAuthClient
	Now   func() time.Time
}

var ErrReloginRequired = errors.New("refresh token rejected; run `authio clearance login` again")

func (t *TokenSource) Token(ctx context.Context) (string, error) {
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	if t.Cred.AccessToken != "" && now().Add(refreshSkew).Before(t.Cred.ExpiresAt) {
		return t.Cred.AccessToken, nil
	}
	if t.Cred.RefreshToken == "" {
		return "", ErrReloginRequired
	}
	tr, err := t.OAuth.Refresh(ctx, t.Cred.RefreshToken)
	if err != nil {
		var oe *OAuthError
		if errors.As(err, &oe) && (oe.Code == "invalid_grant" || oe.Code == "invalid_client") {
			return "", fmt.Errorf("%w (%s)", ErrReloginRequired, oe.Code)
		}
		return "", err
	}
	t.Cred.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		t.Cred.RefreshToken = tr.RefreshToken
	}
	if tr.ExpiresIn > 0 {
		t.Cred.ExpiresAt = now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		t.Cred.ExpiresAt = now().Add(50 * time.Minute)
	}
	if tr.Scope != "" {
		t.Cred.Scope = tr.Scope
	}
	if t.Store != nil {
		if err := t.Store.Save(*t.Cred); err != nil {
			return "", fmt.Errorf("save refreshed credential: %w", err)
		}
	}
	return t.Cred.AccessToken, nil
}
