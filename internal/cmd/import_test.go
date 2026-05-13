package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseAuth0ExportArray(t *testing.T) {
	p := writeTemp(t, "users.json", `[
	  {"user_id":"auth0|a","email":"a@x.com","email_verified":true,"name":"A"},
	  {"user_id":"auth0|b","email":"b@x.com","email_verified":false,"name":"B"}
	]`)
	users, err := parseAuth0Export(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2, got %d", len(users))
	}
	if users[0].Email != "a@x.com" || !users[0].EmailVerified {
		t.Fatalf("first user wrong: %+v", users[0])
	}
}

func TestParseAuth0ExportNDJSON(t *testing.T) {
	p := writeTemp(t, "users.ndjson", `{"user_id":"auth0|a","email":"a@x.com","email_verified":true,"name":"A"}
{"user_id":"auth0|b","email":"b@x.com","email_verified":false,"name":"B"}
{"user_id":"auth0|c","email":"c@x.com","email_verified":true,"name":"C"}`)
	users, err := parseAuth0Export(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 {
		t.Fatalf("expected 3, got %d", len(users))
	}
}

func TestParseAuth0ExportEmpty(t *testing.T) {
	p := writeTemp(t, "users.ndjson", "\n\n   \n")
	users, err := parseAuth0Export(p)
	if err != nil {
		t.Fatalf("expected ok empty, got %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("expected 0, got %d", len(users))
	}
}

func TestImportRejectsUnknownProvider(t *testing.T) {
	if err := Import([]string{"facebook", "--file", "x.json"}); err == nil {
		t.Fatal("expected error")
	}
}
