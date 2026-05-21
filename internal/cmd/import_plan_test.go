package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// loadFixture opens a file under testdata/ and parses with the given provider.
func loadFixture(t *testing.T, name string, parser PlanParser, opts PlanOptions) *ImportPlan {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	defer f.Close()
	plan, err := parser.ParsePlan(context.Background(), f, opts)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return plan
}

func TestAuth0Plan(t *testing.T) {
	plan := loadFixture(t, "auth0.json", auth0PlanParser{}, PlanOptions{MergeDuplicateEmails: true})
	if plan.Provider != "auth0" {
		t.Fatalf("provider: %s", plan.Provider)
	}
	if plan.Stats.SourceUsers != 4 {
		t.Fatalf("source users: %d", plan.Stats.SourceUsers)
	}
	if got := len(plan.Users); got != 3 {
		t.Fatalf("users: %d (want 3 — one blocked dropped)", got)
	}
	wantEmails := map[string]bool{
		"ada@acme.example":    true,
		"grace@acme.example":  true,
		"alan@globex.example": true,
	}
	for _, u := range plan.Users {
		if !wantEmails[u.Email] {
			t.Errorf("unexpected user: %s", u.Email)
		}
		if !u.MigrationPendingEmail {
			t.Errorf("auth0 user %s should have MigrationPendingEmail=true", u.Email)
		}
	}
	if len(plan.Orgs) != 2 {
		t.Fatalf("orgs: %d (want 2)", len(plan.Orgs))
	}
	// Ada has admin role -> owner.
	var foundOwner bool
	for _, m := range plan.Memberships {
		if m.UserExternalID == "auth0:auth0|65f8a1e1" && m.Role == "owner" {
			foundOwner = true
		}
	}
	if !foundOwner {
		t.Fatalf("expected ada admin -> owner role in memberships: %+v", plan.Memberships)
	}
	// Google identity present.
	hasGoogle := false
	for _, id := range plan.Identities {
		if id.Kind == "oauth_google" && id.Subject == "115599887766" {
			hasGoogle = true
		}
	}
	if !hasGoogle {
		t.Fatalf("missing google oauth identity")
	}
}

func TestClerkPlanPreservesMultiOrg(t *testing.T) {
	plan := loadFixture(t, "clerk.json", clerkPlanParser{}, PlanOptions{MergeDuplicateEmails: true})
	// Ada appears in two clerk user rows under the same email; she
	// should merge into one Authio user with 3 memberships (2 from
	// first row, 1 from duplicate row).
	if got := len(plan.Users); got != 2 {
		t.Fatalf("users after merge: %d (want 2)", got)
	}
	var adaCount, linusCount int
	for _, m := range plan.Memberships {
		switch m.UserExternalID {
		case "clerk:user_2abc", "clerk:user_2ghi":
			adaCount++
		case "clerk:user_2def":
			linusCount++
		}
	}
	if adaCount != 3 || linusCount != 1 {
		t.Fatalf("membership counts: ada=%d linus=%d", adaCount, linusCount)
	}
	// Linus owner role.
	for _, m := range plan.Memberships {
		if m.UserExternalID == "clerk:user_2def" && m.Role != "owner" {
			t.Fatalf("linus owner: %+v", m)
		}
	}
}

func TestCognitoPlanCustomAttrsAndGroups(t *testing.T) {
	plan := loadFixture(t, "cognito.json", cognitoPlanParser{}, PlanOptions{MergeDuplicateEmails: true})
	if got := len(plan.Users); got != 2 {
		t.Fatalf("users: %d (want 2 — 2 skipped)", got)
	}
	// First user has custom:tier=enterprise.
	for _, u := range plan.Users {
		if u.Email == "ada@acme.example" {
			custom, _ := u.Metadata["custom"].(map[string]any)
			if custom["tier"] != "enterprise" {
				t.Fatalf("custom attrs missing: %+v", u.Metadata)
			}
			if !u.MfaEnrolled {
				t.Fatalf("ada should be MfaEnrolled")
			}
		}
	}
	if len(plan.Orgs) != 2 {
		t.Fatalf("orgs: %d", len(plan.Orgs))
	}
	// Google federated identity.
	hasGoogle := false
	for _, id := range plan.Identities {
		if id.Kind == "oauth_google" && id.Subject == "1099887766" {
			hasGoogle = true
		}
	}
	if !hasGoogle {
		t.Fatalf("expected google federated identity")
	}
}

func TestFirebasePlanDefaultOrgAndTenants(t *testing.T) {
	plan := loadFixture(t, "firebase.json", firebasePlanParser{}, PlanOptions{
		MergeDuplicateEmails: true,
		DefaultOrgName:       "Default",
	})
	if got := len(plan.Users); got != 3 {
		t.Fatalf("users: %d (want 3)", got)
	}
	// Two orgs: default + globex-prod tenant.
	if got := len(plan.Orgs); got != 2 {
		t.Fatalf("orgs: %d (want 2)", got)
	}
	// Custom claims preserved on Ada.
	for _, u := range plan.Users {
		if u.Email == "ada@acme.example" {
			claims, _ := u.Metadata["claims"].(map[string]any)
			if claims["role"] != "admin" {
				t.Fatalf("claims dropped: %+v", u.Metadata)
			}
		}
	}
	// Tenanted user lands in globex-prod org.
	var tenantOrgExt string
	for _, o := range plan.Orgs {
		if o.Name == "globex-prod" {
			tenantOrgExt = o.ExternalID
		}
	}
	var foundTenanted bool
	for _, m := range plan.Memberships {
		if m.OrgExternalID == tenantOrgExt && m.UserExternalID == "firebase:fbuser-004" {
			foundTenanted = true
		}
	}
	if !foundTenanted {
		t.Fatalf("expected tenanted user in globex-prod org: %+v", plan.Memberships)
	}
}

func TestSupabasePlanWithOrgsTable(t *testing.T) {
	plan := loadFixture(t, "supabase.json", supabasePlanParser{}, PlanOptions{
		MergeDuplicateEmails: true,
		OrgsTablePath:        filepath.Join("testdata", "supabase-orgs.json"),
		DefaultOrgName:       "Default",
	})
	if got := len(plan.Users); got != 2 {
		t.Fatalf("users: %d (want 2 — 1 banned dropped)", got)
	}
	if got := len(plan.Orgs); got != 1 {
		t.Fatalf("orgs: %d (want 1 — only acme from orgs-table)", got)
	}
	var ownerCount, memberCount int
	for _, m := range plan.Memberships {
		switch m.Role {
		case "owner":
			ownerCount++
		case "member":
			memberCount++
		}
	}
	if ownerCount != 1 || memberCount != 1 {
		t.Fatalf("orgs-table memberships: owner=%d member=%d", ownerCount, memberCount)
	}
}

func TestSupabasePlanWithoutOrgsTable(t *testing.T) {
	plan := loadFixture(t, "supabase.json", supabasePlanParser{}, PlanOptions{
		MergeDuplicateEmails: true,
		DefaultOrgName:       "Default",
	})
	if got := len(plan.Orgs); got != 1 {
		t.Fatalf("orgs: %d (want 1 default)", got)
	}
	if plan.Orgs[0].Name != "Default" {
		t.Fatalf("default org name: %q", plan.Orgs[0].Name)
	}
	if got := len(plan.Memberships); got != 2 {
		t.Fatalf("memberships: %d (want 2 — both users -> default)", got)
	}
}

func TestWorkOSMergeDuplicateEmails(t *testing.T) {
	plan := loadFixture(t, "workos.json", workosPlanParser{}, PlanOptions{MergeDuplicateEmails: true})

	// 5 source users, 3 distinct emails => 3 Authio users, 2 merged.
	if plan.Stats.SourceUsers != 5 {
		t.Fatalf("source users: %d (want 5)", plan.Stats.SourceUsers)
	}
	if got := len(plan.Users); got != 3 {
		t.Fatalf("authio users: %d (want 3)", got)
	}
	if plan.Stats.MergedUsers != 2 {
		t.Fatalf("merged users: %d (want 2)", plan.Stats.MergedUsers)
	}

	// Ada's record should accumulate all 3 source IDs.
	var ada *UserRecord
	for i := range plan.Users {
		if plan.Users[i].Email == "ada@acme.example" {
			ada = &plan.Users[i]
		}
	}
	if ada == nil {
		t.Fatalf("ada not found")
	}
	if len(ada.SourceExternalIDs) != 3 {
		t.Fatalf("ada source ids: %v (want 3)", ada.SourceExternalIDs)
	}

	// Memberships: ada has 3 (acme, globex, skunkworks); grace 1; linus 1.
	adaMems := 0
	for _, m := range plan.Memberships {
		if m.UserExternalID == ada.ExternalID {
			adaMems++
		}
	}
	if adaMems != 3 {
		t.Fatalf("ada memberships: %d (want 3)", adaMems)
	}

	// SSO and SCIM mapped.
	if len(plan.SsoConnections) != 2 {
		t.Fatalf("sso connections: %d", len(plan.SsoConnections))
	}
	if len(plan.ScimDirectories) != 1 {
		t.Fatalf("scim directories: %d", len(plan.ScimDirectories))
	}

	// Marquee warning present.
	var mergeWarn bool
	for _, w := range plan.Warnings {
		if strings.Contains(w, "merged") && strings.Contains(w, "duplicate-email") {
			mergeWarn = true
		}
	}
	if !mergeWarn {
		t.Fatalf("expected merge warning, got: %v", plan.Warnings)
	}
}

func TestStytchB2BPlan(t *testing.T) {
	plan := loadFixture(t, "stytch.json", stytchPlanParser{}, PlanOptions{MergeDuplicateEmails: true})
	if got := len(plan.Orgs); got != 2 {
		t.Fatalf("orgs: %d", got)
	}
	// Ada appears in both orgs but should merge to 1 Authio user.
	if got := len(plan.Users); got != 3 {
		t.Fatalf("users: %d (want 3 — ada merged across orgs)", got)
	}
	if plan.Stats.MergedUsers < 1 {
		t.Fatalf("expected merged users for Ada cross-org, got %d", plan.Stats.MergedUsers)
	}
	if len(plan.SsoConnections) != 1 {
		t.Fatalf("sso: %d", len(plan.SsoConnections))
	}
}

func TestDescopePlan(t *testing.T) {
	plan := loadFixture(t, "descope.json", descopePlanParser{}, PlanOptions{MergeDuplicateEmails: true})
	if got := len(plan.Orgs); got != 2 {
		t.Fatalf("orgs: %d", got)
	}
	if got := len(plan.Users); got != 2 {
		t.Fatalf("users: %d (want 2 — disabled dropped)", got)
	}
	// Ada has memberships in both tenants.
	adaMems := 0
	for _, m := range plan.Memberships {
		if m.UserExternalID == "descope:ada@acme.example" {
			adaMems++
		}
	}
	if adaMems != 2 {
		t.Fatalf("ada memberships: %d", adaMems)
	}
	if len(plan.SsoConnections) != 1 {
		t.Fatalf("sso: %d", len(plan.SsoConnections))
	}
}

// =====================================================================
// PlanRunner: writes via mgmt API are idempotent and ordered.
// =====================================================================

func TestPlanRunnerWritesIdempotently(t *testing.T) {
	orgs := map[string]string{} // slug -> id
	users := map[string]string{} // email -> id
	var (
		orgPosts atomic.Int32
		userPosts atomic.Int32
		memPosts  atomic.Int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/organizations":
			orgPosts.Add(1)
			var body struct {
				Name string `json:"name"`
				Slug string `json:"slug"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if id, ok := orgs[body.Slug]; ok {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"code": "slug_in_use", "id": id})
				return
			}
			id := "org_" + body.Slug
			orgs[body.Slug] = id
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "slug": body.Slug, "name": body.Name})
		case r.Method == "GET" && r.URL.Path == "/v1/organizations":
			rows := []map[string]any{}
			for slug, id := range orgs {
				rows = append(rows, map[string]any{"id": id, "slug": slug})
			}
			_ = json.NewEncoder(w).Encode(rows)
		case r.Method == "POST" && r.URL.Path == "/v1/users":
			userPosts.Add(1)
			var body struct {
				Email string `json:"email"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if id, ok := users[body.Email]; ok {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "existed": true})
				return
			}
			id := "user_" + strings.Split(body.Email, "@")[0]
			users[body.Email] = id
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "existed": false})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/memberships"):
			memPosts.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "mem_1"})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/scim-directories"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "scim_1"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))
	defer srv.Close()

	// Tiny plan.
	plan := &ImportPlan{
		Provider: "test",
		Users: []UserRecord{
			{ExternalID: "x:ada", Email: "ada@acme.example", SourceExternalIDs: []string{"x:ada"}},
			{ExternalID: "x:grace", Email: "grace@acme.example", SourceExternalIDs: []string{"x:grace"}},
		},
		Orgs: []OrgRecord{
			{ExternalID: "x:org:acme", Name: "Acme", Slug: "acme"},
		},
		Memberships: []MembershipRecord{
			{UserExternalID: "x:ada", OrgExternalID: "x:org:acme", Role: "admin", Status: "active"},
			{UserExternalID: "x:grace", OrgExternalID: "x:org:acme", Role: "member", Status: "active"},
		},
		ScimDirectories: []ScimDirectoryRecord{
			{OrgExternalID: "x:org:acme", Name: "Acme SCIM"},
		},
	}

	runner := &PlanRunner{APIURL: srv.URL, APIKey: "sk_test", Out: &bytes.Buffer{}}

	// First run.
	stats1, err := runner.Run(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if stats1.OrgsCreated != 1 || stats1.UsersCreated != 2 || stats1.MembershipsCreated != 2 {
		t.Fatalf("first run stats: %+v", stats1)
	}

	// Second run — everything should be idempotent (existed/conflict).
	stats2, err := runner.Run(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if stats2.OrgsExisted != 1 || stats2.UsersExisted != 2 {
		t.Fatalf("second run: orgs=%d users_existed=%d (want 1, 2): %+v",
			stats2.OrgsExisted, stats2.UsersExisted, stats2)
	}
}

func TestPlanRunnerDryRun(t *testing.T) {
	plan := &ImportPlan{
		Provider: "test",
		Users:    []UserRecord{{ExternalID: "x:u1", Email: "u1@x.com", SourceExternalIDs: []string{"x:u1"}}},
		Orgs:     []OrgRecord{{ExternalID: "x:o1", Name: "O", Slug: "o"}},
		Memberships: []MembershipRecord{{UserExternalID: "x:u1", OrgExternalID: "x:o1", Role: "member", Status: "active"}},
	}
	runner := &PlanRunner{DryRun: true, Out: &bytes.Buffer{}}
	stats, err := runner.Run(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if stats.OrgsCreated != 1 || stats.UsersCreated != 1 || stats.MembershipsCreated != 1 {
		t.Fatalf("dry-run stats: %+v", stats)
	}
}

func TestPlanRunnerEmitsJSONProgress(t *testing.T) {
	plan := &ImportPlan{
		Provider: "test",
		Users:    []UserRecord{{ExternalID: "x:u1", Email: "u1@x.com", SourceExternalIDs: []string{"x:u1"}}},
		Orgs:     []OrgRecord{{ExternalID: "x:o1", Name: "O", Slug: "o"}},
	}
	buf := &bytes.Buffer{}
	runner := &PlanRunner{DryRun: true, EmitJSON: true, Out: buf}
	if _, err := runner.Run(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	// Expect at least 3 lines: begin + 1 org + 1 user + done.
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected ≥4 NDJSON lines, got %d:\n%s", len(lines), buf.String())
	}
	// All lines parse as JSON.
	for i, l := range lines {
		var x map[string]any
		if err := json.Unmarshal([]byte(l), &x); err != nil {
			t.Fatalf("line %d not JSON: %s err=%v", i, l, err)
		}
	}
}

func TestPlanParserForUnknown(t *testing.T) {
	if _, err := PlanParserFor("facebook"); err == nil {
		t.Fatal("expected error for unknown provider")
	}
	for _, p := range []string{"auth0", "clerk", "cognito", "firebase", "supabase", "workos", "stytch", "descope"} {
		if _, err := PlanParserFor(p); err != nil {
			t.Fatalf("provider %s: %v", p, err)
		}
	}
}
