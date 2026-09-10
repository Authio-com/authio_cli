package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tcast/authio_cli/internal/config"
	"github.com/tcast/authio_cli/internal/credentials"
)

// fakeMgmtAPI is a minimal in-memory management API covering the four
// config-as-code surfaces the plan builder reads and writes.
type fakeMgmtAPI struct {
	redirectURIs []map[string]any
	webhooks     []map[string]any
	risk         map[string]any
	sso          map[string][]map[string]any // orgID -> rows

	calls []string // "METHOD path" journal for assertions
}

func (f *fakeMgmtAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/redirect-uris", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "GET /v1/redirect-uris")
		writeJSON(w, 200, map[string]any{"data": f.redirectURIs})
	})
	mux.HandleFunc("POST /v1/redirect-uris", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "POST /v1/redirect-uris")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["id"] = "ruri_new"
		f.redirectURIs = append(f.redirectURIs, body)
		writeJSON(w, 201, body)
	})
	mux.HandleFunc("DELETE /v1/redirect-uris/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "DELETE /v1/redirect-uris/"+r.PathValue("id"))
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /v1/webhooks", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "GET /v1/webhooks")
		writeJSON(w, 200, f.webhooks)
	})
	mux.HandleFunc("POST /v1/webhooks", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "POST /v1/webhooks")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["id"] = "wh_new"
		body["status"] = "active"
		f.webhooks = append(f.webhooks, body)
		out := map[string]any{}
		for k, v := range body {
			out[k] = v
		}
		out["secret"] = "whsec_test_only_once"
		writeJSON(w, 201, out)
	})
	mux.HandleFunc("DELETE /v1/webhooks/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "DELETE /v1/webhooks/"+r.PathValue("id"))
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /v1/risk/policy", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "GET /v1/risk/policy")
		writeJSON(w, 200, f.risk)
	})
	mux.HandleFunc("PUT /v1/risk/policy", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "PUT /v1/risk/policy")
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /v1/organizations/{org}/sso-connections", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "GET /v1/organizations/"+r.PathValue("org")+"/sso-connections")
		rows := f.sso[r.PathValue("org")]
		if rows == nil {
			rows = []map[string]any{}
		}
		writeJSON(w, 200, rows)
	})
	mux.HandleFunc("POST /v1/organizations/{org}/sso-connections", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "POST /v1/organizations/"+r.PathValue("org")+"/sso-connections")
		writeJSON(w, 201, map[string]any{"id": "sso_new"})
	})
	mux.HandleFunc("PATCH /v1/organizations/{org}/sso-connections/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "PATCH /v1/organizations/"+r.PathValue("org")+"/sso-connections/"+r.PathValue("id"))
		writeJSON(w, 200, map[string]any{"id": r.PathValue("id")})
	})
	return httptest.NewServer(mux)
}

func testProfile(url string) *credentials.Profile {
	return &credentials.Profile{
		APIKey:    "sk_test_fake",
		ProjectID: "proj_test",
		APIURL:    url,
	}
}

func inSyncRisk() map[string]any {
	return map[string]any{
		"threshold_step_up": 50,
		"threshold_block":   90,
		"signal_weights":    map[string]int{"new_device": 25},
		"enabled_signals":   []string{"new_device"},
		"defaulted":         false,
	}
}

func TestBuildPlan_NoDrift(t *testing.T) {
	api := &fakeMgmtAPI{
		redirectURIs: []map[string]any{
			{"id": "ruri_1", "uri": "https://app.example.com/cb", "kind": "oauth_callback"},
		},
		webhooks: []map[string]any{
			{"id": "wh_1", "url": "https://app.example.com/hook", "events": []string{"session.revoked"}, "status": "active"},
		},
		risk: inSyncRisk(),
		sso: map[string][]map[string]any{
			"org_1": {{
				"id": "sso_1", "organization_id": "org_1", "protocol": "saml",
				"status": "active", "display_name": "Acme Okta",
				"external_id": "acme-okta", "attribute_map": map[string]string{},
				"jit_provisioning": true, "default_role": "member",
			}},
		},
	}
	srv := api.server(t)
	defer srv.Close()

	jit := true
	cfg := &config.File{
		RedirectURIs: []config.RedirectURI{{URI: "https://app.example.com/cb"}},
		Webhooks:     []config.Webhook{{URL: "https://app.example.com/hook", Events: []string{"session.revoked"}}},
		RiskPolicy: &config.RiskPolicy{
			ThresholdStepUp: 50, ThresholdBlock: 90,
			SignalWeights:  map[string]int{"new_device": 25},
			EnabledSignals: []string{"new_device"},
		},
		SSOConnections: []config.SSOConnection{{
			OrganizationID: "org_1", ExternalID: "acme-okta", Provider: "saml",
			DisplayName: "Acme Okta", Status: "active", JITProvisioning: &jit,
			DefaultRole: "member",
		}},
	}
	actions, err := buildPlan(testProfile(srv.URL), cfg, false)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if len(actions) != 0 {
		for _, a := range actions {
			t.Errorf("unexpected action: %s %s %s (%s)", a.verb, a.resource, a.name, a.detail)
		}
	}
}

func TestBuildPlan_CreatesAndUpdates(t *testing.T) {
	api := &fakeMgmtAPI{
		redirectURIs: []map[string]any{},
		webhooks: []map[string]any{
			// Same URL, different events -> replace.
			{"id": "wh_1", "url": "https://app.example.com/hook", "events": []string{"*"}, "status": "active"},
		},
		risk: inSyncRisk(),
		sso: map[string][]map[string]any{
			"org_1": {{
				"id": "sso_1", "organization_id": "org_1", "protocol": "saml",
				"status": "pending", "display_name": "Old Name",
				"external_id": "acme-okta", "attribute_map": map[string]string{},
				"jit_provisioning": true, "default_role": "member",
			}},
		},
	}
	srv := api.server(t)
	defer srv.Close()

	cfg := &config.File{
		RedirectURIs: []config.RedirectURI{{URI: "https://app.example.com/cb", Kind: "magic_link_redirect"}},
		Webhooks:     []config.Webhook{{URL: "https://app.example.com/hook", Events: []string{"session.revoked"}}},
		RiskPolicy: &config.RiskPolicy{
			ThresholdStepUp: 40, ThresholdBlock: 80, // drift
			SignalWeights:  map[string]int{"new_device": 25},
			EnabledSignals: []string{"new_device"},
		},
		SSOConnections: []config.SSOConnection{{
			OrganizationID: "org_1", ExternalID: "acme-okta", Provider: "saml",
			DisplayName: "New Name", Status: "active",
		}},
	}
	actions, err := buildPlan(testProfile(srv.URL), cfg, false)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	got := map[string]actionVerb{}
	for _, a := range actions {
		got[a.resource+" "+a.name] = a.verb
	}
	want := map[string]actionVerb{
		"redirect_uri https://app.example.com/cb": verbCreate,
		"webhook https://app.example.com/hook":    verbReplace,
		"risk_policy policy":                      verbUpdate,
		"sso_connection org_1/acme-okta":          verbUpdate,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("want %s -> %s, got %q (all: %v)", k, v, got[k], got)
		}
	}
	if len(actions) != len(want) {
		t.Errorf("want %d actions, got %d: %v", len(want), len(actions), got)
	}

	// Execute and verify the API journal: webhook replace = revoke +
	// recreate (secret surfaced once), risk PUT, sso PATCH.
	p := testProfile(srv.URL)
	var webhookNote string
	for _, a := range actions {
		note, err := a.execute(p)
		if err != nil {
			t.Fatalf("execute %s %s: %v", a.verb, a.name, err)
		}
		if a.resource == "webhook" {
			webhookNote = note
		}
	}
	if !strings.Contains(webhookNote, "whsec_test_only_once") {
		t.Errorf("webhook replace must surface the write-only secret once, got %q", webhookNote)
	}
	assertCalled(t, api.calls, "DELETE /v1/webhooks/wh_1")
	assertCalled(t, api.calls, "POST /v1/webhooks")
	assertCalled(t, api.calls, "PUT /v1/risk/policy")
	assertCalled(t, api.calls, "PATCH /v1/organizations/org_1/sso-connections/sso_1")
	assertCalled(t, api.calls, "POST /v1/redirect-uris")
}

func TestBuildPlan_PruneDeletes(t *testing.T) {
	api := &fakeMgmtAPI{
		redirectURIs: []map[string]any{
			{"id": "ruri_keep", "uri": "https://keep.example.com/cb", "kind": "oauth_callback"},
			{"id": "ruri_extra", "uri": "https://extra.example.com/cb", "kind": "oauth_callback"},
		},
		webhooks: []map[string]any{
			{"id": "wh_extra", "url": "https://extra.example.com/hook", "events": []string{"*"}, "status": "active"},
			// Revoked rows are ignored — never "pruned" twice.
			{"id": "wh_gone", "url": "https://gone.example.com/hook", "events": []string{"*"}, "status": "revoked"},
		},
	}
	srv := api.server(t)
	defer srv.Close()

	cfg := &config.File{
		RedirectURIs: []config.RedirectURI{{URI: "https://keep.example.com/cb"}},
	}
	actions, err := buildPlan(testProfile(srv.URL), cfg, true)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	got := map[string]actionVerb{}
	for _, a := range actions {
		got[a.resource+" "+a.name] = a.verb
	}
	if got["redirect_uri https://extra.example.com/cb"] != verbDelete {
		t.Errorf("expected prune delete for extra redirect uri, got %v", got)
	}
	if got["webhook https://extra.example.com/hook"] != verbDelete {
		t.Errorf("expected prune delete for extra webhook, got %v", got)
	}
	if _, ok := got["webhook https://gone.example.com/hook"]; ok {
		t.Errorf("revoked webhook must not be pruned again: %v", got)
	}
	if len(actions) != 2 {
		t.Errorf("want exactly 2 prune actions, got %d: %v", len(actions), got)
	}
}

func TestBuildPlan_WithoutPruneNeverDeletes(t *testing.T) {
	api := &fakeMgmtAPI{
		redirectURIs: []map[string]any{
			{"id": "ruri_keep", "uri": "https://keep.example.com/cb", "kind": "oauth_callback"},
			{"id": "ruri_extra", "uri": "https://extra.example.com/cb", "kind": "oauth_callback"},
		},
	}
	srv := api.server(t)
	defer srv.Close()

	cfg := &config.File{
		RedirectURIs: []config.RedirectURI{{URI: "https://keep.example.com/cb"}},
	}
	actions, err := buildPlan(testProfile(srv.URL), cfg, false)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("additive mode must not delete anything: %v", actions)
	}
}

func assertCalled(t *testing.T, calls []string, want string) {
	t.Helper()
	for _, c := range calls {
		if c == want {
			return
		}
	}
	t.Errorf("expected API call %q, journal: %v", want, calls)
}
