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
	if err := os.MkdirAll(filepath.Dir(s.Path), dirMode); err != nil {
		return err
	}
	existing, _ := os.ReadFile(s.Path)
	out := merge(string(existing), profile, p)
	return os.WriteFile(s.Path, []byte(out), fileMode)
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
