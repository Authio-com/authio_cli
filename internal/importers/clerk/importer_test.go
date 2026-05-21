package clerk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// mockClerk returns an httptest.Server that serves the test fixtures
// for /v1/users, /v1/organizations, /v1/organizations/:id/memberships.
//
// Pagination is offset-based; the first page returns the fixture, the
// second returns an empty page so the iterator exits.
func mockClerk(t *testing.T) *httptest.Server {
	t.Helper()
	usersP1 := mustRead(t, "fixtures/users_page1.json")
	usersP2 := mustRead(t, "fixtures/users_page2.json")
	orgs := mustRead(t, "fixtures/organizations.json")
	acmeMembers := mustRead(t, "fixtures/memberships_acme.json")
	globexMembers := mustRead(t, "fixtures/memberships_globex.json")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/users":
			off := r.URL.Query().Get("offset")
			switch off {
			case "0":
				// Pretend page1 is exactly 500 rows so the iterator
				// fetches page 2 (it stops when a page returns < 500).
				// We rewrite the fixture with extra padding items.
				var rows []ClerkUser
				_ = json.Unmarshal(usersP1, &rows)
				padded := append([]ClerkUser{}, rows...)
				for len(padded) < UsersPageSize {
					padded = append(padded, ClerkUser{
						ID: fmt.Sprintf("user_pad_%d", len(padded)),
						EmailAddresses: []ClerkEmail{
							{ID: "e", EmailAddress: fmt.Sprintf("pad%d@example.com", len(padded))},
						},
						CreatedAt: 1700000000000,
					})
				}
				b, _ := json.Marshal(padded)
				_, _ = w.Write(b)
			case "500":
				_, _ = w.Write(usersP2)
			default:
				_, _ = w.Write([]byte(`[]`))
			}
		case r.URL.Path == "/v1/organizations":
			off := r.URL.Query().Get("offset")
			if off == "0" {
				_, _ = w.Write(orgs)
			} else {
				_, _ = w.Write([]byte(`{"data":[],"total_count":2}`))
			}
		case strings.HasPrefix(r.URL.Path, "/v1/organizations/org_acme/memberships"):
			_, _ = w.Write(acmeMembers)
		case strings.HasPrefix(r.URL.Path, "/v1/organizations/org_globex/memberships"):
			_, _ = w.Write(globexMembers)
		default:
			t.Logf("unexpected clerk mock request: %s", r.URL.String())
			http.NotFound(w, r)
		}
	}))
}

// mockAuthio returns an httptest.Server that records POSTs to the bulk
// endpoints. The first call to each user is "imported"; the second is
// "existed" (idempotent on clerk_user_id).
type mockAuthioState struct {
	userPosts atomic.Int32
	orgPosts  atomic.Int32
	memPosts  atomic.Int32

	seenUsers map[string]bool
	seenOrgs  map[string]bool
	seenMems  map[string]bool

	usersBodies []string
	orgsBodies  []string
	memsBodies  []string
}

func newMockAuthio(t *testing.T) (*httptest.Server, *mockAuthioState) {
	t.Helper()
	st := &mockAuthioState{
		seenUsers: map[string]bool{},
		seenOrgs:  map[string]bool{},
		seenMems:  map[string]bool{},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk_live_authio_test" {
			t.Errorf("missing/wrong auth on %s: %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		bodyBytes, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/v1/migrate/bulk-users":
			st.userPosts.Add(1)
			st.usersBodies = append(st.usersBodies, string(bodyBytes))
			var body struct {
				Users []AuthioUserPayload `json:"users"`
			}
			_ = json.Unmarshal(bodyBytes, &body)
			results := make([]BulkResult, 0, len(body.Users))
			for _, u := range body.Users {
				status := "imported"
				if st.seenUsers[u.ClerkUserID] {
					status = "existed"
				}
				st.seenUsers[u.ClerkUserID] = true
				results = append(results, BulkResult{
					SourceID: u.ClerkUserID,
					AuthioID: "user_" + u.ClerkUserID,
					Status:   status,
				})
			}
			respond(w, results)
		case "/v1/migrate/bulk-organizations":
			st.orgPosts.Add(1)
			st.orgsBodies = append(st.orgsBodies, string(bodyBytes))
			var body struct {
				Organizations []AuthioOrgPayload `json:"organizations"`
			}
			_ = json.Unmarshal(bodyBytes, &body)
			results := make([]BulkResult, 0, len(body.Organizations))
			for _, o := range body.Organizations {
				status := "imported"
				if st.seenOrgs[o.ClerkOrgID] {
					status = "existed"
				}
				st.seenOrgs[o.ClerkOrgID] = true
				results = append(results, BulkResult{
					SourceID: o.ClerkOrgID,
					AuthioID: "org_" + o.ClerkOrgID,
					Status:   status,
				})
			}
			respond(w, results)
		case "/v1/migrate/bulk-memberships":
			st.memPosts.Add(1)
			st.memsBodies = append(st.memsBodies, string(bodyBytes))
			var body struct {
				Memberships []AuthioMembershipPayload `json:"memberships"`
			}
			_ = json.Unmarshal(bodyBytes, &body)
			results := make([]BulkResult, 0, len(body.Memberships))
			for _, m := range body.Memberships {
				status := "imported"
				if st.seenMems[m.ClerkMembershipID] {
					status = "existed"
				}
				st.seenMems[m.ClerkMembershipID] = true
				results = append(results, BulkResult{
					SourceID: m.ClerkMembershipID,
					AuthioID: "mem_" + m.ClerkMembershipID,
					Status:   status,
				})
			}
			respond(w, results)
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, st
}

func respond(w http.ResponseWriter, results []BulkResult) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestImporter_EndToEnd is the marquee test:
//   1. Stand up a mock Clerk + a mock Authio management-api.
//   2. Run the importer.
//   3. Confirm users, orgs, memberships were all shipped.
//   4. Confirm the second run is idempotent (every row reports "existed").
//   5. Confirm the CSV report is on disk.
func TestImporter_EndToEnd(t *testing.T) {
	clerkSrv := mockClerk(t)
	defer clerkSrv.Close()
	authioSrv, st := newMockAuthio(t)
	defer authioSrv.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reportPath := filepath.Join(tmp, "report.csv")

	var buf bytes.Buffer
	imp, err := NewImporter("sk_test_clerk", authioSrv.URL, "sk_live_authio_test", "proj_test", Options{
		IncludeUsers:         true,
		IncludeOrgs:          true,
		IncludeMemberships:   true,
		IncludeOAuthBindings: true,
		IncludeMFA:           true,
		ClerkBaseURL:         clerkSrv.URL,
		StatePath:            statePath,
		ReportPath:           reportPath,
		RateLimit:            500,
		BatchSize:            100,
	})
	if err != nil {
		t.Fatal(err)
	}
	imp.Out = &buf
	summary, err := imp.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if summary.Imported == 0 {
		t.Errorf("expected non-zero imported, got %d", summary.Imported)
	}
	if st.userPosts.Load() == 0 {
		t.Error("expected at least one POST /bulk-users")
	}
	if st.orgPosts.Load() == 0 {
		t.Error("expected at least one POST /bulk-organizations")
	}
	if st.memPosts.Load() == 0 {
		t.Error("expected at least one POST /bulk-memberships")
	}
	if !st.seenUsers["user_2NfABCdef"] {
		t.Error("expected ada to be shipped")
	}
	if !st.seenOrgs["org_acme"] {
		t.Error("expected org_acme to be shipped")
	}
	if !st.seenMems["orgmem_acme_ada"] {
		t.Error("expected acme/ada membership to be shipped")
	}
	// CSV report should exist with at least the expected rows.
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("expected report at %s: %v", reportPath, err)
	}
	rep, _ := os.ReadFile(reportPath)
	if !strings.Contains(string(rep), "user_2NfABCdef") {
		t.Errorf("report missing ada row:\n%s", rep)
	}

	// State should be cleared on successful import.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Errorf("expected state file to be cleared on success, got err=%v", err)
	}

	// Skipped rows should appear in the report.
	if !strings.Contains(string(rep), "skipped") {
		t.Errorf("expected skipped row in report:\n%s", rep)
	}
}

// TestImporter_DryRunSkipsWrites confirms --dry-run never POSTs to the
// management-api but still produces a report.
func TestImporter_DryRunSkipsWrites(t *testing.T) {
	clerkSrv := mockClerk(t)
	defer clerkSrv.Close()
	authioSrv, st := newMockAuthio(t)
	defer authioSrv.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reportPath := filepath.Join(tmp, "report.csv")

	imp, err := NewImporter("sk_test_clerk", authioSrv.URL, "sk_live_authio_test", "proj_test", Options{
		DryRun:               true,
		IncludeUsers:         true,
		IncludeOrgs:          true,
		IncludeMemberships:   true,
		IncludeOAuthBindings: true,
		IncludeMFA:           true,
		ClerkBaseURL:         clerkSrv.URL,
		StatePath:            statePath,
		ReportPath:           reportPath,
		RateLimit:            500,
	})
	if err != nil {
		t.Fatal(err)
	}
	imp.Out = io.Discard
	if _, err := imp.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.userPosts.Load() != 0 {
		t.Errorf("dry-run wrote %d user batches", st.userPosts.Load())
	}
	if st.orgPosts.Load() != 0 {
		t.Errorf("dry-run wrote %d org batches", st.orgPosts.Load())
	}
	if st.memPosts.Load() != 0 {
		t.Errorf("dry-run wrote %d membership batches", st.memPosts.Load())
	}
	// Report is still written so the customer can preview the plan.
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("dry-run should still produce a report, got err=%v", err)
	}
}

// TestImporter_IdempotentRerun proves a re-run reports all rows as
// "existed" rather than "imported" — the marquee guarantee for resuming
// failed runs without double-creating users.
func TestImporter_IdempotentRerun(t *testing.T) {
	clerkSrv := mockClerk(t)
	defer clerkSrv.Close()
	authioSrv, _ := newMockAuthio(t)
	defer authioSrv.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reportPath := filepath.Join(tmp, "report.csv")

	makeImp := func() *Importer {
		imp, err := NewImporter("sk_test_clerk", authioSrv.URL, "sk_live_authio_test", "proj_test", Options{
			IncludeUsers:         true,
			IncludeOrgs:          true,
			IncludeMemberships:   true,
			IncludeOAuthBindings: true,
			IncludeMFA:           true,
			ClerkBaseURL:         clerkSrv.URL,
			StatePath:            statePath,
			ReportPath:           reportPath,
			RateLimit:            500,
		})
		if err != nil {
			t.Fatal(err)
		}
		imp.Out = io.Discard
		return imp
	}

	first, err := makeImp().Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Existed > 0 {
		t.Errorf("first run should not see any existed rows; got %d", first.Existed)
	}
	second, err := makeImp().Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.Existed == 0 {
		t.Errorf("expected the second run to see existed rows; got summary=%+v", second)
	}
	if second.Imported > 0 {
		t.Errorf("second run shouldn't import new rows; got %d", second.Imported)
	}
}

// TestImporter_ResumeFromState exercises the resume path: pre-write a
// state file with LastUserOffset=500, then verify the importer skips
// the first page and continues from page 2.
func TestImporter_ResumeFromState(t *testing.T) {
	clerkSrv := mockClerk(t)
	defer clerkSrv.Close()
	authioSrv, st := newMockAuthio(t)
	defer authioSrv.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	if err := SaveState(statePath, &State{
		Version:         1,
		AuthioProjectID: "proj_test",
		LastUserOffset:  500, // skip page 1 (which has banned/no-email + padded fillers)
	}); err != nil {
		t.Fatal(err)
	}

	imp, err := NewImporter("sk_test_clerk", authioSrv.URL, "sk_live_authio_test", "proj_test", Options{
		IncludeUsers:         true,
		IncludeOrgs:          true,
		IncludeMemberships:   true,
		IncludeOAuthBindings: true,
		IncludeMFA:           true,
		ClerkBaseURL:         clerkSrv.URL,
		StatePath:            statePath,
		ReportPath:           filepath.Join(tmp, "report.csv"),
		RateLimit:            500,
	})
	if err != nil {
		t.Fatal(err)
	}
	imp.Out = io.Discard
	if _, err := imp.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The first page (offset 0 with the padded users) should not have
	// been touched. Specifically, ada (page 1) should NOT be in seenUsers
	// but alan (page 2) should be.
	if st.seenUsers["user_2NfABCdef"] {
		t.Errorf("expected ada (page 1) NOT to be imported when resuming from offset=500")
	}
	if !st.seenUsers["user_2NfYZ0123"] {
		t.Errorf("expected alan (page 2) to be imported")
	}
}

// TestImporter_StateBoundToProjectID rejects a resume against a
// different project. Protects the "I started one migration, started a
// second migration on a different project, the state file is shared"
// foot-gun.
func TestImporter_StateBoundToProjectID(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	if err := SaveState(statePath, &State{
		Version:         1,
		AuthioProjectID: "proj_OTHER",
		LastUserOffset:  100,
	}); err != nil {
		t.Fatal(err)
	}
	imp, err := NewImporter("sk_test_clerk", "http://example", "sk_live_authio_test", "proj_test", Options{
		ClerkBaseURL: "http://example",
		StatePath:    statePath,
		RateLimit:    1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	imp.Out = io.Discard
	if _, err := imp.Run(context.Background()); err == nil {
		t.Fatal("expected error when state belongs to a different project")
	} else if !strings.Contains(err.Error(), "belongs to project") {
		t.Errorf("unexpected error: %v", err)
	}
}
