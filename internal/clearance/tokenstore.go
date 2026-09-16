package clearance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AgentCredential is what `authio clearance login` saves per agent: the
// Connect client the agent is bound to and its rotating refresh token. It
// lives beside ~/.authio/credentials.toml, one JSON file per agent, mode
// 0600, because the project-key TOML has a fixed schema and this is a
// different kind of secret (a user-delegated OAuth grant, not an sk_ key).
type AgentCredential struct {
	AgentID      string    `json:"agent_id"`
	ProjectID    string    `json:"project_id"`
	ClientID     string    `json:"client_id"`
	AuthCoreURL  string    `json:"auth_core_url"`
	ClearanceURL string    `json:"clearance_url"`
	Scope        string    `json:"scope"`
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
	SavedAt      time.Time `json:"saved_at"`
}

// TokenStore persists AgentCredentials under dir (default ~/.authio/clearance).
type TokenStore struct{ Dir string }

func DefaultTokenStore() (*TokenStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &TokenStore{Dir: filepath.Join(home, ".authio", "clearance")}, nil
}

func (s *TokenStore) path(agentID string) string {
	return filepath.Join(s.Dir, safeName(agentID)+".json")
}

func safeName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

func (s *TokenStore) Save(c AgentCredential) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	c.SavedAt = time.Now()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".cred-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.path(c.AgentID)); err != nil {
		return err
	}
	return os.Chmod(s.path(c.AgentID), 0o600)
}

// ErrNotLoggedIn is returned when no credential exists for the agent.
var ErrNotLoggedIn = errors.New("not logged in")

func (s *TokenStore) Load(agentID string) (*AgentCredential, error) {
	b, err := os.ReadFile(s.path(agentID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: run `authio clearance login --agent %s`", ErrNotLoggedIn, agentID)
		}
		return nil, err
	}
	var c AgentCredential
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("corrupt credential %s: %w", s.path(agentID), err)
	}
	return &c, nil
}

func (s *TokenStore) Delete(agentID string) error {
	err := os.Remove(s.path(agentID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
