package cmd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// =====================================================================
// pure helpers
// =====================================================================

func TestKeyFamily(t *testing.T) {
	cases := map[string]string{
		"sk_live_abc": "live",
		"pk_live_abc": "live",
		"sk_test_abc": "test",
		"pk_test_abc": "test",
		"whatever":    "",
	}
	for in, want := range cases {
		if got := keyFamily(in); got != want {
			t.Errorf("keyFamily(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"authio 0.1.0", "0.1.0"},
		{" v0.1.0 ", "0.1.0"},
	} {
		if got := normalizeVersion(c.in); got != c.want {
			t.Errorf("normalizeVersion(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestCheckKeyEnvSanity(t *testing.T) {
	mk := func(env string) *projectMe { return &projectMe{Environment: env} }
	cases := []struct {
		key    string
		env    string
		status string
	}{
		{"sk_live_x", "production", statusPass},
		{"sk_test_x", "staging", statusPass},
		{"sk_test_x", "development", statusPass},
		{"sk_live_x", "staging", statusWarn},
		{"sk_test_x", "production", statusWarn},
		{"weird", "production", statusWarn},
	}
	for _, c := range cases {
		got := checkKeyEnvSanity(&credentials.Profile{APIKey: c.key}, mk(c.env))
		if got.Status != c.status {
			t.Errorf("key=%s env=%s → %s want %s (%s)", c.key, c.env, got.Status, c.status, got.Detail)
		}
	}
}

func TestClockSkewClassification(t *testing.T) {
	now := time.Now().UTC()
	mk := func(serverTime time.Time) *apiResult {
		h := http.Header{}
		h.Set("Date", serverTime.Format(http.TimeFormat))
		return &apiResult{header: h, latency: 2 * time.Millisecond}
	}
	if got := checkClockSkew(mk(now)); got.Status != statusPass {
		t.Errorf("in-sync clock → %s want pass (%s)", got.Status, got.Detail)
	}
	if got := checkClockSkew(mk(now.Add(-40 * time.Second))); got.Status != statusWarn {
		t.Errorf("40s skew → %s want warn (%s)", got.Status, got.Detail)
	}
	if got := checkClockSkew(mk(now.Add(-10 * time.Minute))); got.Status != statusFail {
		t.Errorf("10m skew → %s want fail (%s)", got.Status, got.Detail)
	}
}

// =====================================================================
// listen: signature + payload parity with the webhooks worker
// =====================================================================

// verifySig is an independent reimplementation of
// authio_webhooks/internal/signing.Verify, proving the CLI's signature
// is verifiable by the same scheme a real receiver uses.
func verifySig(secret, body, header string) bool {
	var ts, v1 string
	for _, part := range strings.Split(header, ",") {
		if strings.HasPrefix(part, "t=") {
			ts = part[2:]
		} else if strings.HasPrefix(part, "v1=") {
			v1 = part[3:]
		}
	}
	if ts == "" || v1 == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write([]byte(body))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(v1)
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

func TestSignPayloadVerifies(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"hello":"world"}`)
	sig := signPayload(secret, body, time.Unix(1700000000, 0))
	if !strings.HasPrefix(sig, "t=1700000000,v1=") {
		t.Fatalf("unexpected signature format: %s", sig)
	}
	if !verifySig(secret, string(body), sig) {
		t.Fatal("signature did not verify with the correct secret")
	}
	if verifySig("whsec_other", string(body), sig) {
		t.Fatal("signature verified with the wrong secret")
	}
	if verifySig(secret, `{"hello":"tampered"}`, sig) {
		t.Fatal("signature verified over a tampered body")
	}
}

func TestBuildWebhookBodyShape(t *testing.T) {
	var e apiEvent
	e.ID = "evt_1"
	e.Event = "user.created"
	e.CreatedAt = "2026-06-11T22:00:00Z"
	e.Data.ActorType = "api_key"
	e.Data.Metadata = json.RawMessage(`{"k":"v"}`)
	body := buildWebhookBody(e, "proj_1")
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != "evt_1" || got["action"] != "user.created" || got["project_id"] != "proj_1" {
		t.Fatalf("unexpected body: %s", body)
	}
	actor, ok := got["actor"].(map[string]any)
	if !ok || actor["type"] != "api_key" {
		t.Fatalf("actor not embedded: %s", body)
	}
	if md, ok := got["metadata"].(map[string]any); !ok || md["k"] != "v" {
		t.Fatalf("metadata not embedded: %s", body)
	}
}

func TestBuildWebhookBodyEmptyMetadata(t *testing.T) {
	var e apiEvent
	e.ID = "evt_2"
	e.Event = "ping"
	body := buildWebhookBody(e, "proj_2")
	if !strings.Contains(string(body), `"metadata":{}`) {
		t.Fatalf("empty metadata should serialize as {}: %s", body)
	}
}

func TestNewerOrdering(t *testing.T) {
	older := eventPos{ts: "2026-06-11T22:00:00Z", id: "evt_1"}
	newerEvt := apiEvent{ID: "evt_2", CreatedAt: "2026-06-11T22:00:05Z"}
	if !newer(newerEvt, older) {
		t.Fatal("later timestamp should be newer")
	}
	if newer(apiEvent{ID: "evt_0", CreatedAt: "2026-06-11T21:00:00Z"}, older) {
		t.Fatal("earlier timestamp should not be newer")
	}
	// Same timestamp → id tiebreak.
	if !newer(apiEvent{ID: "evt_2", CreatedAt: older.ts}, older) {
		t.Fatal("same ts, higher id should be newer")
	}
	if newer(apiEvent{ID: "evt_0", CreatedAt: older.ts}, older) {
		t.Fatal("same ts, lower id should not be newer")
	}
}

// =====================================================================
// HTTP-backed integration: whoami / env / doctor against a fake API
// =====================================================================

func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/projects/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk_test_demo" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "proj_demo",
			"tenant_id":   "ten_demo",
			"name":        "Staging",
			"environment": "staging",
			"created_at":  "2026-01-01T00:00:00Z",
			"tenant":      map[string]any{"name": "Acme"},
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/v1/auth/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	})
	mux.HandleFunc("/v1/webhooks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]any{})
	})
	// GitHub release lookup → pretend no releases yet (404).
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	return httptest.NewServer(mux)
}

// writeProfile points the credentials store at a temp HOME and writes a
// single profile.
func writeProfile(t *testing.T, apiURL string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := &credentials.Store{Path: filepath.Join(home, ".authio", "credentials.toml")}
	if err := s.Save("default", credentials.Profile{
		APIKey:      "sk_test_demo",
		ProjectID:   "proj_demo",
		APIURL:      apiURL,
		AuthCoreURL: apiURL,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWhoamiIntegration(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	writeProfile(t, srv.URL)
	if err := Whoami([]string{"--json"}); err != nil {
		t.Fatalf("whoami: %v", err)
	}
}

func TestWhoamiNoCreds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := Whoami(nil); err == nil {
		t.Fatal("expected error with no credentials")
	}
}

func TestEnvListAndUse(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	writeProfile(t, srv.URL)
	if err := Env([]string{"list", "--json"}); err != nil {
		t.Fatalf("env list: %v", err)
	}
	if err := Env([]string{"use", "default"}); err != nil {
		t.Fatalf("env use: %v", err)
	}
	if err := Env([]string{"use", "ghost"}); err == nil {
		t.Fatal("expected error switching to unknown profile")
	}
}

func TestDoctorIntegrationAllGreen(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	prev := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = prev }()
	writeProfile(t, srv.URL)
	// No releases (404) + healthy services + test key on staging = no FAILs.
	if err := Doctor("0.1.0", []string{"--json"}); err != nil {
		t.Fatalf("doctor reported failure on a healthy setup: %v", err)
	}
}

func TestDoctorDetectsBadKey(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	prev := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = prev }()
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := &credentials.Store{Path: filepath.Join(home, ".authio", "credentials.toml")}
	_ = s.Save("default", credentials.Profile{APIKey: "sk_test_wrong", APIURL: srv.URL, AuthCoreURL: srv.URL})
	// 401 on /projects/me → credentials check FAILS → non-nil error.
	if err := Doctor("0.1.0", nil); err == nil {
		t.Fatal("expected doctor to fail with an invalid key")
	}
}

func TestListenRequiresForward(t *testing.T) {
	if err := Listen(nil); err == nil {
		t.Fatal("expected error without --forward")
	}
	if err := Listen([]string{"--forward", "ftp://nope"}); err == nil {
		t.Fatal("expected error for non-http forward URL")
	}
}

// signParityVector guards against accidental drift in the signing scheme.
func TestSignParityVector(t *testing.T) {
	got := signPayload("whsec_test", []byte("hello"), time.Unix(1700000000, 0))
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	mac.Write([]byte("1700000000.hello"))
	want := "t=1700000000,v1=" + hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("sign drift: got %s want %s", got, want)
	}
}
