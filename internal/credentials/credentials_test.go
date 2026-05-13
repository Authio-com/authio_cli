package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "credentials.toml")}
	in := Profile{
		APIKey:      "sk_live_abc",
		ProjectID:   "proj_x",
		APIURL:      "https://api.example",
		AuthCoreURL: "https://auth.example",
	}
	if err := s.Save("default", in); err != nil {
		t.Fatal(err)
	}
	out, err := s.Load("default")
	if err != nil {
		t.Fatal(err)
	}
	if *out != in {
		t.Fatalf("round-trip mismatch: %+v vs %+v", *out, in)
	}
}

func TestFileMode0600(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "credentials.toml")}
	if err := s.Save("default", Profile{APIKey: "sk_live_x"}); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %o", stat.Mode().Perm())
	}
}

func TestMultipleProfiles(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "credentials.toml")}
	if err := s.Save("default", Profile{APIKey: "sk_live_def"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("staging", Profile{APIKey: "sk_test_stg", ProjectID: "proj_stg"}); err != nil {
		t.Fatal(err)
	}
	d, err := s.Load("default")
	if err != nil {
		t.Fatal(err)
	}
	if d.APIKey != "sk_live_def" {
		t.Fatal("default lost on staging save")
	}
	g, err := s.Load("staging")
	if err != nil {
		t.Fatal(err)
	}
	if g.APIKey != "sk_test_stg" || g.ProjectID != "proj_stg" {
		t.Fatalf("staging mismatch: %+v", *g)
	}
}

func TestLoadMissing(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "credentials.toml")}
	if _, err := s.Load("default"); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("expected missing-credentials error, got %v", err)
	}
}
