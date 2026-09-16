package clearance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestTokenStore_RoundTripAndMode(t *testing.T) {
	s := &TokenStore{Dir: t.TempDir()}
	c := AgentCredential{AgentID: "agt_1", ProjectID: "proj_1", ClientID: "dcr_1", RefreshToken: "art_x", AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.Save(c); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.path("agt_1"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	got, err := s.Load("agt_1")
	if err != nil || got.RefreshToken != "art_x" || got.ClientID != "dcr_1" {
		t.Fatalf("load: %v %+v", err, got)
	}
	if _, err := s.Load("agt_nope"); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("want ErrNotLoggedIn, got %v", err)
	}
	if s.path("../evil") == s.Dir+"/../evil.json" {
		t.Fatal("path traversal in agent id")
	}
}

// fakeAuthCore answers /v1/auth/token for refresh_token, asserting the
// project header and form shape, and rotates the refresh token.
func fakeAuthCore(t *testing.T, wantProject string, fail string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Authio-Project") != wantProject {
			t.Errorf("missing X-Authio-Project: %q", r.Header.Get("X-Authio-Project"))
		}
		_ = r.ParseForm()
		if fail != "" {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fail, "error_description": "nope"})
			return
		}
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "art_old" || r.PostForm.Get("client_id") != "dcr_1" {
			t.Errorf("unexpected form: %v", r.PostForm)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "acc_new", "refresh_token": "art_new", "token_type": "Bearer", "expires_in": 3600, "scope": "tools:read tools:call"})
	}))
}

func TestTokenSource_RefreshesRotatesPersists(t *testing.T) {
	ac := fakeAuthCore(t, "proj_1", "")
	defer ac.Close()
	store := &TokenStore{Dir: t.TempDir()}
	cred := &AgentCredential{AgentID: "agt_1", ProjectID: "proj_1", ClientID: "dcr_1", AccessToken: "acc_old", ExpiresAt: time.Now().Add(10 * time.Second), RefreshToken: "art_old"}
	ts := &TokenSource{Store: store, Cred: cred, OAuth: &OAuthClient{AuthCoreURL: ac.URL, ProjectID: "proj_1", ClientID: "dcr_1"}}
	tok, err := ts.Token(context.Background())
	if err != nil || tok != "acc_new" {
		t.Fatalf("token: %v %q", err, tok)
	}
	saved, _ := store.Load("agt_1")
	if saved.RefreshToken != "art_new" || saved.AccessToken != "acc_new" || saved.Scope != "tools:read tools:call" {
		t.Fatalf("not persisted: %+v", saved)
	}
	// still fresh: no second call (server would fail on art_new)
	if tok2, err := ts.Token(context.Background()); err != nil || tok2 != "acc_new" {
		t.Fatalf("cached token: %v %q", err, tok2)
	}
}

func TestTokenSource_InvalidGrantMeansRelogin(t *testing.T) {
	ac := fakeAuthCore(t, "proj_1", "invalid_grant")
	defer ac.Close()
	cred := &AgentCredential{AgentID: "agt_1", ProjectID: "proj_1", ClientID: "dcr_1", RefreshToken: "art_old"}
	ts := &TokenSource{Cred: cred, OAuth: &OAuthClient{AuthCoreURL: ac.URL, ProjectID: "proj_1", ClientID: "dcr_1"}}
	_, err := ts.Token(context.Background())
	if !errors.Is(err, ErrReloginRequired) {
		t.Fatalf("want ErrReloginRequired, got %v", err)
	}
	if msg := Humanize(err, "agt_1"); msg == "" || msg == err.Error() {
		t.Fatalf("Humanize should rewrite: %q", msg)
	}
}

func TestOAuthClient_AuthorizeURL(t *testing.T) {
	oc := &OAuthClient{AuthCoreURL: "https://identity.test/", ProjectID: "proj_1", ClientID: "dcr_1", Resource: "https://clearance.test"}
	u := oc.AuthorizeURL("http://127.0.0.1:4242/callback", "st", "ch", ScopeTools)
	for _, want := range []string{"https://identity.test/v1/auth/authorize?", "client_id=dcr_1", "code_challenge=ch", "code_challenge_method=S256", "project_id=proj_1", "resource=https%3A%2F%2Fclearance.test", "redirect_uri=http%3A%2F%2F127.0.0.1%3A4242%2Fcallback", "scope=tools%3Aread+tools%3Acall", "state=st", "response_type=code"} {
		if !contains(u, want) {
			t.Fatalf("authorize URL missing %q: %s", want, u)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool { return indexOf(s, sub) >= 0 })()
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
