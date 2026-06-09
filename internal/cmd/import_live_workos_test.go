package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkOSLivePullerMembershipsPerOrg(t *testing.T) {
	memCalls := map[string]int{}
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user_management/users":
			if r.URL.Query().Get("organization_id") != "" {
				t.Errorf("users request must not include organization_id: %s", r.URL.String())
			}
			fmt.Fprint(w, `{"data":[
				{"id":"user_acme_ada","email":"ada@acme.example","email_verified":true,"first_name":"Ada","last_name":"Lovelace"},
				{"id":"user_globex_ada","email":"ada@acme.example","email_verified":true,"first_name":"Ada","last_name":"Lovelace"}
			],"list_metadata":{}}`)
		case r.URL.Path == "/organizations":
			fmt.Fprint(w, `{"data":[
				{"id":"org_acme","name":"Acme Corp","slug":"acme","domain":"acme.example"},
				{"id":"org_globex","name":"Globex Inc","slug":"globex","domain":"globex.example"}
			],"list_metadata":{}}`)
		case r.URL.Path == "/user_management/organization_memberships":
			orgID := r.URL.Query().Get("organization_id")
			if orgID == "" {
				http.Error(w, `{"message":"At least one of organization_id or user_id must be provided.","code":"missing_user_id_or_organization_id"}`, http.StatusBadRequest)
				return
			}
			memCalls[orgID]++
			switch orgID {
			case "org_acme":
				fmt.Fprint(w, `{"data":[
					{"id":"mem_1","user_id":"user_acme_ada","organization_id":"org_acme","role":{"slug":"admin"},"status":"active"}
				],"list_metadata":{}}`)
			case "org_globex":
				fmt.Fprint(w, `{"data":[
					{"id":"mem_2","user_id":"user_globex_ada","organization_id":"org_globex","role":{"slug":"member"},"status":"active"}
				],"list_metadata":{}}`)
			default:
				t.Errorf("unexpected organization_id=%q", orgID)
				http.NotFound(w, r)
			}
		case r.URL.Path == "/connections":
			fmt.Fprint(w, `{"data":[],"list_metadata":{}}`)
		case r.URL.Path == "/directories":
			fmt.Fprint(w, `{"data":[],"list_metadata":{}}`)
		default:
			t.Errorf("unexpected mock-workos request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}))
	defer mock.Close()

	plan, err := workosLivePuller{}.PullLive(context.Background(), LiveCredentials{
		APIKey: "sk_test_mock",
	}, LiveOptions{
		BaseURLOverride: mock.URL,
	})
	if err != nil {
		t.Fatalf("pull live: %v", err)
	}
	if memCalls["org_acme"] != 1 || memCalls["org_globex"] != 1 {
		t.Fatalf("membership calls per org: %+v (want 1 each)", memCalls)
	}
	if got := len(plan.Users); got != 1 {
		t.Fatalf("users after merge: %d (want 1)", got)
	}
	if got := len(plan.Orgs); got != 2 {
		t.Fatalf("orgs: %d (want 2)", got)
	}
	if got := len(plan.Memberships); got != 2 {
		t.Fatalf("memberships: %d (want 2)", got)
	}
	for _, w := range plan.Warnings {
		if strings.Contains(strings.ToLower(w), "membership") && strings.Contains(strings.ToLower(w), "unknown") {
			t.Fatalf("unexpected membership warning: %q", w)
		}
	}
}
