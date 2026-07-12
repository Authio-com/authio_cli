package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tcast/authio_cli/internal/credentials"
)

func TestOrgsCreateRequiresName(t *testing.T) {
	err := Orgs([]string{"create"})
	if err == nil || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("expected --name usage error, got %v", err)
	}
}

func TestWebhooksCreateRequiresURL(t *testing.T) {
	err := Webhooks([]string{"create"})
	if err == nil || !strings.Contains(err.Error(), "--url") {
		t.Fatalf("expected --url usage error, got %v", err)
	}
}

func TestKeysUnknownSubcommand(t *testing.T) {
	err := Keys([]string{"list"})
	if err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("expected unknown subcommand error, got %v", err)
	}
}

func TestApiRequestJSONRoundTrip(t *testing.T) {
	var gotMethod, gotAuth, gotCT string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"org_1","name":"Acme","slug":"acme"}`))
	}))
	defer srv.Close()

	p := &credentials.Profile{
		APIKey: "sk_test_abcdefghijklmnopqrstuvwxyz012345",
		APIURL: srv.URL,
	}
	res, err := apiPost(p, "/v1/organizations", map[string]any{"name": "Acme"})
	if err != nil {
		t.Fatal(err)
	}
	if res.status != 201 {
		t.Fatalf("status=%d", res.status)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method=%s", gotMethod)
	}
	if !strings.HasPrefix(gotAuth, "Bearer sk_test_") {
		t.Fatalf("auth=%q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type=%q", gotCT)
	}
	if gotBody["name"] != "Acme" {
		t.Fatalf("body=%v", gotBody)
	}
}
