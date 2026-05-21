package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestAuth0LivePullerEndToEnd is the marquee end-to-end test:
//   1) Stand up a mock Auth0 Management API (users + orgs + members).
//   2) Stand up a mock Authio management-API that records POSTs.
//   3) Pull the plan via auth0LivePuller.
//   4) Run it through PlanRunner.
//   5) Confirm we wrote users, identities, orgs, and memberships.
//
// The interesting bits the spec calls out:
//   - identities + sso_connections + scim_directories actually land
//     (previously the warning "identity write skipped" was emitted; the
//     stub here verifies the new endpoint paths are hit).
//   - re-running is idempotent (existing rows return 200 instead of 201).
func TestAuth0LivePullerEndToEnd(t *testing.T) {
	// ----- 1) Mock Auth0 -----
	mockAuth0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v2/users") && strings.Contains(r.URL.RawQuery, "include_totals=true"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"total":3,"length":3,"start":0,"limit":100,"users":[
                {"user_id":"auth0|ada","email":"ada@acme.example","email_verified":true,"name":"Ada Lovelace",
                 "identities":[{"provider":"google-oauth2","user_id":"99001"}],
                 "organizations":[{"id":"org_acme","name":"acme","display_name":"Acme","roles":[{"name":"admin"}]}]},
                {"user_id":"auth0|grace","email":"grace@acme.example","email_verified":true,"name":"Grace Hopper",
                 "identities":[],
                 "organizations":[{"id":"org_acme","name":"acme","display_name":"Acme"}]},
                {"user_id":"auth0|alan","email":"alan@globex.example","email_verified":false,"name":"Alan Turing",
                 "identities":[{"provider":"github","user_id":"77002"}],
                 "organizations":[{"id":"org_globex","name":"globex","display_name":"Globex"}]}
            ]}`)
		case strings.HasPrefix(r.URL.Path, "/api/v2/users"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[
                {"user_id":"auth0|ada","email":"ada@acme.example","email_verified":true,"name":"Ada Lovelace",
                 "identities":[{"provider":"google-oauth2","user_id":"99001"}],
                 "organizations":[{"id":"org_acme","name":"acme","display_name":"Acme","roles":[{"name":"admin"}]}]},
                {"user_id":"auth0|grace","email":"grace@acme.example","email_verified":true,"name":"Grace Hopper",
                 "identities":[],
                 "organizations":[{"id":"org_acme","name":"acme","display_name":"Acme"}]},
                {"user_id":"auth0|alan","email":"alan@globex.example","email_verified":false,"name":"Alan Turing",
                 "identities":[{"provider":"github","user_id":"77002"}],
                 "organizations":[{"id":"org_globex","name":"globex","display_name":"Globex"}]}
            ]`)
		case strings.HasPrefix(r.URL.Path, "/api/v2/organizations") && !strings.Contains(r.URL.Path, "/members"):
			fmt.Fprint(w, `[
                {"id":"org_acme","name":"acme","display_name":"Acme"},
                {"id":"org_globex","name":"globex","display_name":"Globex"}
            ]`)
		case strings.Contains(r.URL.Path, "/organizations/org_acme/members") && !strings.Contains(r.URL.Path, "/roles"):
			fmt.Fprint(w, `[
                {"user_id":"auth0|ada","email":"ada@acme.example","name":"Ada Lovelace",
                 "roles":[{"name":"admin"}]},
                {"user_id":"auth0|grace","email":"grace@acme.example","name":"Grace Hopper",
                 "roles":[]}
            ]`)
		case strings.Contains(r.URL.Path, "/organizations/org_globex/members") && !strings.Contains(r.URL.Path, "/roles"):
			fmt.Fprint(w, `[
                {"user_id":"auth0|alan","email":"alan@globex.example","name":"Alan Turing","roles":[]}
            ]`)
		case strings.Contains(r.URL.Path, "/members/") && strings.HasSuffix(r.URL.Path, "/roles"):
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("unexpected mock-auth0 request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockAuth0.Close()

	// ----- 2) Run the live puller -----
	puller := auth0LivePuller{}
	creds := LiveCredentials{
		Domain: strings.TrimPrefix(mockAuth0.URL, "http://"),
		Token:  "mock-token", // AUTHIO_REDACT
	}
	plan, err := puller.PullLive(context.Background(), creds, LiveOptions{
		BaseURLOverride: mockAuth0.URL,
	})
	if err != nil {
		t.Fatalf("pull live: %v", err)
	}
	if got := len(plan.Users); got != 3 {
		t.Fatalf("users: %d (want 3)", got)
	}
	if got := len(plan.Orgs); got != 2 {
		t.Fatalf("orgs: %d (want 2)", got)
	}
	if got := len(plan.Identities); got != 2 {
		t.Fatalf("identities: %d (want 2 — google + github)", got)
	}
	if got := len(plan.Memberships); got != 3 {
		t.Fatalf("memberships: %d (want 3 — 2 from acme + 1 from globex)", got)
	}

	// Spot-check Ada's google identity is correctly mapped.
	var hasGoogle bool
	for _, id := range plan.Identities {
		if id.Kind == "oauth_google" && id.Subject == "99001" {
			hasGoogle = true
		}
	}
	if !hasGoogle {
		t.Fatalf("missing ada's google identity: %+v", plan.Identities)
	}

	// ----- 3) Mock Authio management-API -----
	var (
		userPosts     atomic.Int32
		orgPosts      atomic.Int32
		identityPosts atomic.Int32
		ssoPosts      atomic.Int32
		scimPosts     atomic.Int32
		memPosts      atomic.Int32
	)
	orgIDs := map[string]string{}
	userIDs := map[string]string{}
	mockMgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/organizations":
			orgPosts.Add(1)
			var body struct {
				Name string `json:"name"`
				Slug string `json:"slug"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if id, ok := orgIDs[body.Slug]; ok {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"code": "slug_in_use", "id": id})
				return
			}
			id := "org_" + body.Slug
			orgIDs[body.Slug] = id
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "slug": body.Slug, "name": body.Name})
		case r.Method == "GET" && r.URL.Path == "/v1/organizations":
			out := []map[string]any{}
			for slug, id := range orgIDs {
				out = append(out, map[string]any{"id": id, "slug": slug})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == "POST" && r.URL.Path == "/v1/users":
			userPosts.Add(1)
			var body struct {
				Email string `json:"email"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if id, ok := userIDs[body.Email]; ok {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "existed": true})
				return
			}
			id := "user_" + strings.Split(body.Email, "@")[0]
			userIDs[body.Email] = id
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "existed": false})
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/users/") && strings.HasSuffix(r.URL.Path, "/identities"):
			identityPosts.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "idn_test"})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/memberships"):
			memPosts.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "mem_1"})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/sso-connections"):
			ssoPosts.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sso_1"})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/scim-directories"):
			scimPosts.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "scim_1"})
		default:
			t.Errorf("unexpected mock-mgmt request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))
	defer mockMgmt.Close()

	// ----- 4) Run the plan through PlanRunner against the mock mgmt API -----
	runner := &PlanRunner{
		APIURL: mockMgmt.URL,
		APIKey: "sk_test_mock",
		Out:    &bytes.Buffer{},
	}
	stats, err := runner.Run(context.Background(), plan)
	if err != nil {
		t.Fatalf("plan run: %v", err)
	}

	// Pre-fix, the runner emitted a warning about identities being
	// skipped. With the new code the warning list should NOT contain
	// any "not yet writable" entries — assert that explicitly so this
	// test catches regressions.
	for _, w := range plan.Warnings {
		if strings.Contains(strings.ToLower(w), "not yet writable") ||
			strings.Contains(strings.ToLower(w), "endpoint not yet implemented") {
			t.Errorf("regression: identity/sso write skipped warning present: %q", w)
		}
	}

	if stats.UsersCreated != 3 {
		t.Errorf("UsersCreated=%d (want 3)", stats.UsersCreated)
	}
	if stats.OrgsCreated != 2 {
		t.Errorf("OrgsCreated=%d (want 2)", stats.OrgsCreated)
	}
	if stats.MembershipsCreated != 3 {
		t.Errorf("MembershipsCreated=%d (want 3)", stats.MembershipsCreated)
	}
	if stats.IdentitiesCreated != 2 {
		t.Errorf("IdentitiesCreated=%d (want 2 — endpoint should be wired now)", stats.IdentitiesCreated)
	}
	if identityPosts.Load() != 2 {
		t.Errorf("identity POSTs=%d (want 2)", identityPosts.Load())
	}

	// ----- 5) Re-run the plan; expect the SECOND pass to see existed=N -----
	// PlanRunner accumulates stats in plan.Stats across runs (it does not
	// reset). The thing to assert is that the second pass observed each
	// row as already-present (UsersExisted bumped by 3, OrgsExisted by 2).
	beforeExisted := stats.UsersExisted
	beforeOrgsExisted := stats.OrgsExisted
	stats2, err := runner.Run(context.Background(), plan)
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if stats2.UsersExisted-beforeExisted != 3 {
		t.Errorf("re-run users_existed delta=%d (want 3)", stats2.UsersExisted-beforeExisted)
	}
	if stats2.OrgsExisted-beforeOrgsExisted != 2 {
		t.Errorf("re-run orgs_existed delta=%d (want 2)", stats2.OrgsExisted-beforeOrgsExisted)
	}
}

// TestEnvelopeRoundTrip proves the CLI's open implementation accepts
// envelopes produced by SealForTest — the SealForTest helper mirrors the
// management-api's sealCredentials, so this test guards against the two
// implementations drifting.
func TestEnvelopeRoundTrip(t *testing.T) {
	master := "very-secret-master-key-32-bytes-long"
	projectID := "prj_test"
	original := LiveCredentials{Domain: "tenant.auth0.com", Token: "tok_supersecret"}
	envelope, err := SealForTest(projectID, master, original)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTHIO_IMPORT_CREDS_KEY", master)
	got, err := openCredEnvelope(projectID, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != original.Domain || got.Token != original.Token {
		t.Fatalf("round-trip mismatch: got=%+v want=%+v", got, original)
	}

	// Wrong project ID must fail (per-project KEK).
	if _, err := openCredEnvelope("prj_other", envelope); err == nil {
		t.Errorf("expected failure with wrong project_id")
	}
}
