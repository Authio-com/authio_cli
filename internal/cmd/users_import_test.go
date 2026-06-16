package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseUsersCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.csv")
	csv := "email,name,external_id,role\nalice@example.com,Alice,ext_1,member\n"
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := parseUsersImportFile(path, "csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0].Email != "alice@example.com" || rows[0].Name != "Alice" {
		t.Fatalf("%+v", rows[0])
	}
}

func TestParseUsersJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	raw := `{"users":[{"email":"bob@example.com","name":"Bob"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := parseUsersImportFile(path, "json")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Email != "bob@example.com" {
		t.Fatalf("%+v", rows)
	}
}

func TestUsersImportDryRunFlags(t *testing.T) {
	f, err := parseUsersImportFlags([]string{
		"--file", "x.csv",
		"--org", "org_test",
		"--email-verified",
		"--dry-run",
		"--duplicate-policy", "update",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !f.DryRun || !f.EmailVerified || f.OrgID != "org_test" || f.DuplicatePolicy != "update" {
		t.Fatalf("%+v", f)
	}
}
