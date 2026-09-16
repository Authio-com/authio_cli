package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tcast/authio_cli/internal/config"
)

const clearanceYAML = `
version: 1
redirect_uris:
  - uri: https://app.example.com/cb
clearance:
  providers:
    filesystem: { type: stdio, command: npx, args: ["-y", "srv"] }
  profiles:
    developer:
      allow: ["valet/github/GET:*"]
      ask: ["exec:git push*"]
  agents:
    dev-helper: { profile: developer }
`

func writeYAML(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "authio.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfig_ClearanceBlockLoadsAndRoundTrips(t *testing.T) {
	cfg, err := config.Load(writeYAML(t, clearanceYAML))
	if err != nil {
		t.Fatalf("clearance block must not break Load: %v", err)
	}
	if !cfg.HasClearance() || cfg.Empty() {
		t.Fatal("HasClearance/Empty wrong")
	}
	doc, err := cfg.ClearanceYAML()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"clearance:", "profiles:", "developer:", "exec:git push*", "dev-helper:", "filesystem:"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("re-serialised block missing %q:\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "redirect_uris") {
		t.Fatal("re-serialised block leaked sibling keys")
	}
	// a file with ONLY a clearance block is not "empty"
	only, err := config.Load(writeYAML(t, "clearance:\n  profiles:\n    p: { allow: [\"x/*\"] }\n"))
	if err != nil || only.Empty() {
		t.Fatalf("clearance-only file: err=%v empty=%v", err, only.Empty())
	}
	none, _ := config.Load(writeYAML(t, "version: 1\nredirect_uris:\n  - uri: https://a.example.com/cb\n"))
	if none.HasClearance() {
		t.Fatal("HasClearance true without a block")
	}
}

// fakeImportAPI answers only the clearance import route (the workspace
// API-key surface — POST /v1/clearance/import, not the dashboard-session
// /v1/session/clearance/import); every other planner is kept quiet by
// giving the file nothing else to manage. applyResp lets a test control
// what the (non-dry-run) apply call returns; nil falls back to a
// reasonable default.
func fakeImportAPI(t *testing.T, dryRunResp map[string]any, dryStatus int, applyResp map[string]any) (*httptest.Server, *[]map[string]any) {
	var seen []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/clearance/import", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, body)
		if r.Header.Get("Authorization") != "Bearer sk_test_fake" {
			w.WriteHeader(401)
			return
		}
		if body["dry_run"] == true {
			w.WriteHeader(dryStatus)
			_ = json.NewEncoder(w).Encode(dryRunResp)
			return
		}
		resp := applyResp
		if resp == nil {
			resp = map[string]any{"profiles_created": []string{"developer"}, "profiles_updated": []string{}, "agents_bound": []string{"dev-helper"}, "unbound_agents": []any{}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux), &seen
}

const clearanceOnlyYAML = "clearance:\n  profiles:\n    developer: { allow: [\"valet/github/GET:*\"] }\n  agents:\n    dev-helper: { profile: developer }\n"

func TestPlanClearance_DriftBecomesOneAction(t *testing.T) {
	srv, seen := fakeImportAPI(t, map[string]any{"profiles_created": []string{"developer"}, "profiles_updated": []string{}, "agents_bound": []string{"dev-helper"}, "unbound_agents": []any{}}, 200, nil)
	defer srv.Close()
	cfg, _ := config.Load(writeYAML(t, clearanceOnlyYAML))
	actions, err := buildPlan(testProfile(srv.URL), cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].resource != "clearance" || actions[0].verb != verbUpdate {
		t.Fatalf("actions = %+v", actions)
	}
	if !strings.Contains(actions[0].detail, "developer") || !strings.Contains(actions[0].detail, "dev-helper") {
		t.Fatalf("detail = %q", actions[0].detail)
	}
	if (*seen)[0]["dry_run"] != true || !strings.Contains((*seen)[0]["yaml"].(string), "clearance:") {
		t.Fatalf("dry run request: %v", (*seen)[0])
	}
	note, err := actions[0].execute(testProfile(srv.URL))
	if err != nil || !strings.Contains(note, "developer") {
		t.Fatalf("execute: %v %q", err, note)
	}
	if (*seen)[1]["dry_run"] != false {
		t.Fatalf("apply must send dry_run: false explicitly, got %v", (*seen)[1]["dry_run"])
	}
}

func TestPlanClearance_TrulyInSyncIsNoAction(t *testing.T) {
	srv, _ := fakeImportAPI(t, map[string]any{"profiles_created": []string{}, "profiles_updated": []string{}, "agents_bound": []string{}, "unbound_agents": []any{}}, 200, nil)
	defer srv.Close()
	cfg, _ := config.Load(writeYAML(t, clearanceOnlyYAML))
	actions, err := buildPlan(testProfile(srv.URL), cfg, false)
	if err != nil || len(actions) != 0 {
		t.Fatalf("expected no actions, got %v %+v", err, actions)
	}
}

// A profile/agent that already exists by name is reported as "update"
// even with no content change (the import endpoint matches by name, not
// content — see the doc comment on planClearance). check must still
// treat that as drift: the server is the source of truth here, not a
// client-side diff.
func TestPlanClearance_AlreadyExistingByNameIsStillDrift(t *testing.T) {
	srv, _ := fakeImportAPI(t, map[string]any{"profiles_created": []string{}, "profiles_updated": []string{"developer"}, "agents_bound": []string{"dev-helper"}, "unbound_agents": []any{}}, 200, nil)
	defer srv.Close()
	cfg, _ := config.Load(writeYAML(t, clearanceOnlyYAML))
	actions, err := buildPlan(testProfile(srv.URL), cfg, false)
	if err != nil || len(actions) != 1 {
		t.Fatalf("expected one action, got %v %+v", err, actions)
	}
	if !strings.Contains(actions[0].detail, "upsert, matched by name") {
		t.Fatalf("detail should explain name-matching, got %q", actions[0].detail)
	}
}

// unbound_agents is a warning, never a silent no-op and never a hard
// failure: an agent named in the file with no matching Connect client id
// yet still needs to surface, so the operator creates it in the
// dashboard rather than wondering why nothing happened.
func TestPlanClearance_UnboundAgentIsAWarningNotSilence(t *testing.T) {
	srv, _ := fakeImportAPI(t, map[string]any{
		"profiles_created": []string{}, "profiles_updated": []string{}, "agents_bound": []string{},
		"unbound_agents": []map[string]string{{"name": "ghost", "profile_id": "developer", "runs_as": "user"}},
	}, 200, nil)
	defer srv.Close()
	cfg, _ := config.Load(writeYAML(t, clearanceOnlyYAML))
	actions, err := buildPlan(testProfile(srv.URL), cfg, false)
	if err != nil || len(actions) != 1 {
		t.Fatalf("expected one action surfacing the warning, got %v %+v", err, actions)
	}
	if !strings.Contains(actions[0].detail, "WARNING") || !strings.Contains(actions[0].detail, "ghost") {
		t.Fatalf("detail should warn about the unbound agent by name, got %q", actions[0].detail)
	}
}

func TestPlanClearance_ServerRejectionSurfaces(t *testing.T) {
	srv, _ := fakeImportAPI(t, map[string]any{"code": "invalid_yaml", "errors": []string{"profiles.developer.allow[0]: bad glob"}}, 422, nil)
	defer srv.Close()
	cfg, _ := config.Load(writeYAML(t, clearanceOnlyYAML))
	_, err := buildPlan(testProfile(srv.URL), cfg, false)
	if err == nil || !strings.Contains(err.Error(), "invalid_yaml") || !strings.Contains(err.Error(), "bad glob") {
		t.Fatalf("expected invalid_yaml error with the engine's per-field message, got %v", err)
	}
	srv2, _ := fakeImportAPI(t, map[string]any{"code": "clearance_engine_unavailable"}, 503, nil)
	defer srv2.Close()
	_, err = buildPlan(testProfile(srv2.URL), cfg, false)
	if err == nil || !strings.Contains(err.Error(), "clearance engine unavailable") {
		t.Fatalf("expected engine-unavailable error, got %v", err)
	}
}
