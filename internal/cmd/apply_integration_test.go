package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/tcast/authio_cli/internal/config"
	"github.com/tcast/authio_cli/internal/credentials"
)

// Integration test against a live environment (normally e2e). Skipped
// unless AUTHIO_E2E_API_KEY + AUTHIO_E2E_MGMT_API_URL are set.
//
// Deliberately never exercises prune: the e2e project is shared and a
// prune plan built from a one-URI fixture would delete everything else.
// Cleanup is a targeted delete of the resources this test created.
func e2eProfile(t *testing.T) *credentials.Profile {
	t.Helper()
	key := os.Getenv("AUTHIO_E2E_API_KEY")
	url := os.Getenv("AUTHIO_E2E_MGMT_API_URL")
	if key == "" || url == "" {
		t.Skip("AUTHIO_E2E_API_KEY / AUTHIO_E2E_MGMT_API_URL not set — skipping live integration test")
	}
	return &credentials.Profile{
		APIKey:    key,
		ProjectID: os.Getenv("AUTHIO_E2E_PROJECT_ID"),
		APIURL:    strings.TrimRight(url, "/"),
	}
}

func nonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestIntegration_ApplyIdempotenceAndDrift(t *testing.T) {
	p := e2eProfile(t)
	uri := fmt.Sprintf("https://cli-itest-%s.example.com/cb", nonce(t))
	t.Cleanup(func() { deleteRedirectURIByURI(t, p, uri) })

	cfg := &config.File{
		RedirectURIs: []config.RedirectURI{{URI: uri, Kind: "oauth_callback"}},
	}

	// 1. Fresh URI -> plan is exactly one create; apply it.
	actions, err := buildPlan(p, cfg, false)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if len(actions) != 1 || actions[0].verb != verbCreate {
		t.Fatalf("want 1 create, got %+v", actions)
	}
	if _, err := actions[0].execute(p); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// 2. Idempotence -> replanning yields no actions.
	actions, err = buildPlan(p, cfg, false)
	if err != nil {
		t.Fatalf("replan: %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf("apply not idempotent, replanned: %+v", actions)
	}

	// 3. Drift detection -> kind change plans a replace.
	cfg.RedirectURIs[0].Kind = "magic_link_redirect"
	actions, err = buildPlan(p, cfg, false)
	if err != nil {
		t.Fatalf("drift plan: %v", err)
	}
	if len(actions) != 1 || actions[0].verb != verbReplace {
		t.Fatalf("want 1 replace on kind drift, got %+v", actions)
	}
}

func TestIntegration_CheckDryRunSurfacesServerValidation(t *testing.T) {
	p := e2eProfile(t)
	// Passes the CLI's structural validation but fails the server's
	// registration rules — check must surface the API's exact code.
	cfg := &config.File{
		RedirectURIs: []config.RedirectURI{{URI: "https://*.cli-itest.example.com/cb"}},
	}
	actions, err := buildPlan(p, cfg, false)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	err = dryRunRedirectURIs(p, actions)
	if err == nil || !strings.Contains(err.Error(), "uri_wildcard_not_allowed") {
		t.Fatalf("want dry_run 422 uri_wildcard_not_allowed, got %v", err)
	}
}

func deleteRedirectURIByURI(t *testing.T, p *credentials.Profile, uri string) {
	t.Helper()
	res, err := apiGet(p, "/v1/redirect-uris")
	if err != nil {
		t.Logf("cleanup list failed: %v", err)
		return
	}
	if res.status != 200 {
		t.Logf("cleanup list failed: status %d", res.status)
		return
	}
	var live struct {
		Data []liveRedirectURI `json:"data"`
	}
	if err := json.Unmarshal(res.body, &live); err != nil {
		t.Logf("cleanup parse failed: %v", err)
		return
	}
	for _, r := range live.Data {
		if r.URI == uri {
			if res, err := apiDelete(p, "/v1/redirect-uris/"+r.ID); err != nil {
				t.Logf("cleanup delete %s failed: %v", r.ID, err)
			} else if res.status != 204 {
				t.Logf("cleanup delete %s failed: status %d", r.ID, res.status)
			}
		}
	}
}
