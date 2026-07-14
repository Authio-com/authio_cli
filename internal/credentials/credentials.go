// Package credentials persists and loads ~/.authio/credentials.toml.
//
// File format (TOML-ish but parsed by hand to avoid an external dep):
//
//	[default]
//	api_key = "sk_live_..."
//	project_id = "proj_..."
//	api_url = "https://authiomanagement-api-production.up.railway.app"
//	auth_core_url = "https://authioauth-core-production.up.railway.app"
//
// File mode is 0600. We store profiles by name; "default" is the implicit
// profile when none is specified via --profile.
package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
)

type Profile struct {
	APIKey      string
	ProjectID   string
	APIURL      string
	AuthCoreURL string
}

type Store struct {
	Path string
}

func DefaultStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &Store{Path: filepath.Join(home, ".authio", "credentials.toml")}, nil
}

func (s *Store) Save(profile string, p Profile) error {
	if profile == "" {
		profile = "default"
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	existing, _ := os.ReadFile(s.Path)
	out := merge(string(existing), profile, p)
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.Path); err != nil {
		return err
	}
	// Rename preserves the temp file's mode, and the explicit chmod also
	// repairs credentials files created by older releases with wider modes.
	return os.Chmod(s.Path, fileMode)
}

func (s *Store) Load(profile string) (*Profile, error) {
	if profile == "" {
		profile = "default"
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no credentials at %s — run `authio login`", s.Path)
		}
		return nil, err
	}
	profiles := parse(string(b))
	p, ok := profiles[profile]
	if !ok {
		return nil, fmt.Errorf("profile %q not found in %s", profile, s.Path)
	}
	return p, nil
}

// Names returns the profile names present in the credentials file, with
// "default" first (when present) and the rest alphabetical. A missing
// file yields an empty slice and no error — callers treat "nothing
// configured" the same as "file absent".
func (s *Store) Names() ([]string, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	profiles := parse(string(b))
	var rest []string
	hasDefault := false
	for name := range profiles {
		if name == "default" {
			hasDefault = true
			continue
		}
		rest = append(rest, name)
	}
	sort.Strings(rest)
	out := make([]string, 0, len(profiles))
	if hasDefault {
		out = append(out, "default")
	}
	return append(out, rest...), nil
}

// configPath is the sidecar file holding CLI-wide preferences that are
// not credentials — currently just the active profile. Kept separate
// from credentials.toml so a `authio env use` never has to rewrite (and
// risk corrupting) the secret-bearing file.
func (s *Store) configPath() string {
	return filepath.Join(filepath.Dir(s.Path), "config.toml")
}

// ActiveProfile returns the profile selected via `authio env use`,
// defaulting to "default" when none has been chosen.
func (s *Store) ActiveProfile() string {
	b, err := os.ReadFile(s.configPath())
	if err != nil {
		return "default"
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "active_profile") {
			eq := strings.Index(line, "=")
			if eq < 0 {
				continue
			}
			v := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
			if v != "" {
				return v
			}
		}
	}
	return "default"
}

// SetActiveProfile persists the chosen profile. The profile must already
// exist in the credentials file.
func (s *Store) SetActiveProfile(profile string) error {
	if profile == "" {
		profile = "default"
	}
	names, err := s.Names()
	if err != nil {
		return err
	}
	found := false
	for _, n := range names {
		if n == profile {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("profile %q not found in %s — run `authio login --profile %s` first", profile, s.Path, profile)
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), dirMode); err != nil {
		return err
	}
	body := fmt.Sprintf("active_profile = %q\n", profile)
	return os.WriteFile(s.configPath(), []byte(body), fileMode)
}

// =====================================================================
// minimal TOML-ish parser/serializer
// =====================================================================

func parse(s string) map[string]*Profile {
	out := map[string]*Profile{}
	var current string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			out[current] = &Profile{}
			continue
		}
		if current == "" {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
		switch key {
		case "api_key":
			out[current].APIKey = val
		case "project_id":
			out[current].ProjectID = val
		case "api_url":
			out[current].APIURL = val
		case "auth_core_url":
			out[current].AuthCoreURL = val
		}
	}
	return out
}

func merge(existing, profile string, p Profile) string {
	profiles := parse(existing)
	profiles[profile] = &p
	var b strings.Builder
	// Stable order: default first, then alphabetical.
	names := []string{"default"}
	for name := range profiles {
		if name != "default" {
			names = append(names, name)
		}
	}
	first := true
	for _, name := range names {
		pr, ok := profiles[name]
		if !ok {
			continue
		}
		if !first {
			b.WriteString("\n")
		}
		first = false
		fmt.Fprintf(&b, "[%s]\n", name)
		write := func(k, v string) {
			if v != "" {
				fmt.Fprintf(&b, "%s = %q\n", k, v)
			}
		}
		write("api_key", pr.APIKey)
		write("project_id", pr.ProjectID)
		write("api_url", pr.APIURL)
		write("auth_core_url", pr.AuthCoreURL)
	}
	return b.String()
}
