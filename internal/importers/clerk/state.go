package clerk

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// State is the resumable checkpoint persisted to disk between batches.
// On a re-run with the same Authio project + Clerk secret, the importer
// resumes from State.LastUserOffset / LastOrgOffset.
//
// Stored at: $HOME/.authio/clerk-import-state.json
//
// We key the file by Authio project ID so multiple concurrent imports
// across projects don't collide.
type State struct {
	Version         int       `json:"version"`
	AuthioProjectID string    `json:"authio_project_id"`
	ClerkBaseURL    string    `json:"clerk_base_url"`
	StartedAt       time.Time `json:"started_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// Pagination cursors.
	LastUserOffset int `json:"last_user_offset"`
	LastOrgOffset  int `json:"last_org_offset"`

	// Outcome counters across this state's lifetime (cumulative; survive
	// resume).
	UsersSeen         int `json:"users_seen"`
	UsersImported     int `json:"users_imported"`
	UsersExisted      int `json:"users_existed"`
	UsersSkipped      int `json:"users_skipped"`
	UsersErrored      int `json:"users_errored"`
	OrgsSeen          int `json:"orgs_seen"`
	OrgsImported      int `json:"orgs_imported"`
	OrgsExisted       int `json:"orgs_existed"`
	OrgsErrored       int `json:"orgs_errored"`
	MembershipsSeen   int `json:"memberships_seen"`
	MembershipsCreated int `json:"memberships_created"`
	MembershipsExisted int `json:"memberships_existed"`
	MembershipsErrored int `json:"memberships_errored"`

	UsersDone bool `json:"users_done"`
	OrgsDone  bool `json:"orgs_done"`
	Completed bool `json:"completed"`
}

// StateFilePath returns the on-disk path for the given home directory.
// homeDir == "" picks os.UserHomeDir().
func StateFilePath(homeDir string) (string, error) {
	if homeDir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		homeDir = h
	}
	return filepath.Join(homeDir, ".authio", "clerk-import-state.json"), nil
}

// LoadState reads the state file. Returns (nil, nil) when the file does
// not exist.
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// SaveState writes the state file atomically (write-then-rename so a
// kill-9 mid-write doesn't truncate it).
func SaveState(path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	s.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ClearState removes the file once an import completes successfully.
func ClearState(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
