package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkOSLivePullerTargetOrgScope(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user_management/users":
			fmt.Fprint(w, `{"data":[
				{"id":"user_acme","email":"ada@acme.example","email_verified":true,"first_name":"Ada","last_name":"Lovelace"},
				{"id":"user_globex","email":"bob@globex.example","email_verified":true,"first_name":"Bob","last_name":"Jones"}
			],"list_metadata":{}}`)
		case r.URL.Path == "/organizations":
			fmt.Fprint(w, `{"data":[
				{"id":"org_acme","name":"Acme Corp","slug":"acme","domain":"acme.example"},
				{"id":"org_globex","name":"Globex Inc","slug":"globex","domain":"globex.example"}
			],"list_metadata":{}}`)
		case r.URL.Path == "/user_management/organization_memberships":
			orgID := r.URL.Query().Get("organization_id")
			switch orgID {
			case "org_acme":
				fmt.Fprint(w, `{"data":[
					{"id":"mem_1","user_id":"user_acme","organization_id":"org_acme","role":{"slug":"admin"},"status":"active"}
				],"list_metadata":{}}`)
			case "org_globex":
				fmt.Fprint(w, `{"data":[
					{"id":"mem_2","user_id":"user_globex","organization_id":"org_globex","role":{"slug":"member"},"status":"active"}
				],"list_metadata":{}}`)
			default:
				http.NotFound(w, r)
			}
		case r.URL.Path == "/connections", r.URL.Path == "/directories":
			fmt.Fprint(w, `{"data":[],"list_metadata":{}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mock.Close()

	targetOrg := "org_y0dp0era82vmnxdx"
	plan, err := workosLivePuller{}.PullLive(context.Background(), LiveCredentials{
		APIKey: "sk_test_mock",
	}, LiveOptions{
		BaseURLOverride:            mock.URL,
		TargetOrganizationID:       targetOrg,
		SourceWorkOSOrganizationID: "org_acme",
	})
	if err != nil {
		t.Fatalf("pull live: %v", err)
	}
	if len(plan.Orgs) != 0 {
		t.Fatalf("orgs: %d (want 0 — target org mode skips org creation)", len(plan.Orgs))
	}
	if len(plan.Users) != 1 {
		t.Fatalf("users: %d (want 1 from filtered WorkOS org)", len(plan.Users))
	}
	if len(plan.Memberships) != 1 {
		t.Fatalf("memberships: %d (want 1)", len(plan.Memberships))
	}
	if plan.Memberships[0].OrgExternalID != TargetOrgExternalID {
		t.Fatalf("membership org ext: %q (want %q)", plan.Memberships[0].OrgExternalID, TargetOrgExternalID)
	}
	foundTargetWarning := false
	for _, w := range plan.Warnings {
		if strings.Contains(w, targetOrg) {
			foundTargetWarning = true
			break
		}
	}
	if !foundTargetWarning {
		t.Fatalf("expected warning mentioning target org %s, got %v", targetOrg, plan.Warnings)
	}
}
