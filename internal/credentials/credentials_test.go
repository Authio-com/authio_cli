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
	if err := os.WriteFile(s.Path, []byte("[default]\napi_key = \"old\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
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

func TestSaveReplacesFileAtomicallyWithoutTempArtifacts(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "credentials.toml")}
	if err := s.Save("default", Profile{APIKey: "sk_live_x"}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "credentials.toml" {
		t.Fatalf("unexpected files after atomic save: %v", entries)
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

func TestNamesOrder(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "credentials.toml")}
	// Missing file → empty, no error.
	if names, err := s.Names(); err != nil || len(names) != 0 {
		t.Fatalf("expected empty names for missing file, got %v %v", names, err)
	}
	for _, n := range []string{"staging", "default", "prod"} {
		if err := s.Save(n, Profile{APIKey: "sk_test_" + n}); err != nil {
			t.Fatal(err)
		}
	}
	names, err := s.Names()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"default", "prod", "staging"}
	if len(names) != len(want) {
		t.Fatalf("got %v want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("got %v want %v", names, want)
		}
	}
}

func TestActiveProfile(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "credentials.toml")}
	// Default before anything is set.
	if got := s.ActiveProfile(); got != "default" {
		t.Fatalf("expected default, got %q", got)
	}
	if err := s.Save("staging", Profile{APIKey: "sk_test_x"}); err != nil {
		t.Fatal(err)
	}
	// Switching to an unknown profile must fail.
	if err := s.SetActiveProfile("nope"); err == nil {
		t.Fatal("expected error switching to unknown profile")
	}
	if err := s.SetActiveProfile("staging"); err != nil {
		t.Fatal(err)
	}
	if got := s.ActiveProfile(); got != "staging" {
		t.Fatalf("expected staging, got %q", got)
	}
	// The config sidecar must not clobber the credentials file.
	if _, err := s.Load("staging"); err != nil {
		t.Fatalf("credentials lost after SetActiveProfile: %v", err)
	}
}
