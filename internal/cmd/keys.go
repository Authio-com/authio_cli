package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// Keys handles `authio keys <subcommand>`.
//
//	authio keys rotate [--profile name] [--name label]
//
// Creates a replacement workspace secret key, updates credentials.toml,
// then revokes the previous key. Uses existing /v1/api-keys endpoints
// (create + delete) — the roll endpoint cannot rotate the key that is
// currently authenticating the request.
func Keys(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: authio keys rotate [--profile name] [--name label]")
	}
	switch args[0] {
	case "rotate", "roll":
		return keysRotate(args[1:])
	default:
		return fmt.Errorf("unknown keys subcommand %q (try `authio keys rotate`)", args[0])
	}
}

func keysRotate(args []string) error {
	name := "cli-rotated"
	profileName := resolveProfileName(args)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				i++ // already consumed by resolveProfileName
			}
		}
	}
	if !strings.Contains(name, time.Now().Format("20060102")) {
		name = fmt.Sprintf("%s-%s", name, time.Now().UTC().Format("20060102-150405"))
	}

	p, profileName, err := loadProfile(profileName)
	if err != nil {
		return err
	}

	meRes, err := apiGet(p, "/v1/projects/me")
	if err != nil {
		return fmt.Errorf("reach management API: %w", err)
	}
	if meRes.status == 401 {
		return fmt.Errorf("credentials for profile %q are invalid or revoked — run `authio login --profile %s`", profileName, profileName)
	}
	if meRes.status != 200 {
		return fmt.Errorf("GET /v1/projects/me returned %d: %s", meRes.status, string(meRes.body))
	}
	var me projectMe
	if err := json.Unmarshal(meRes.body, &me); err != nil {
		return fmt.Errorf("decode /v1/projects/me: %w", err)
	}
	if me.APIKeyID == "" {
		return errors.New("management API did not return api_key_id — update management-api and retry")
	}

	prefix := "sk_live_"
	if keyFamily(p.APIKey) == "test" {
		prefix = "sk_test_"
	}

	createRes, err := apiPost(p, "/v1/api-keys", map[string]any{
		"prefix": prefix,
		"name":   name,
		"scopes": []string{},
		"kind":   "workspace",
	})
	if err != nil {
		return fmt.Errorf("create API key: %w", err)
	}
	if createRes.status != 201 {
		return fmt.Errorf("POST /v1/api-keys returned %d: %s", createRes.status, string(createRes.body))
	}
	var minted struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(createRes.body, &minted); err != nil {
		return fmt.Errorf("decode create response: %w", err)
	}
	if minted.Secret == "" {
		return errors.New("create API key response missing secret")
	}

	store, err := credentials.DefaultStore()
	if err != nil {
		return err
	}
	updated := *p
	updated.APIKey = minted.Secret
	if updated.ProjectID == "" {
		updated.ProjectID = me.ID
	}
	if err := store.Save(profileName, updated); err != nil {
		return fmt.Errorf("save rotated credentials: %w", err)
	}

	delRes, err := apiDelete(&updated, "/v1/api-keys/"+me.APIKeyID)
	if err != nil {
		return fmt.Errorf("revoke previous key (new key saved): %w", err)
	}
	if delRes.status != 204 && delRes.status != 404 {
		return fmt.Errorf(
			"new key saved, but revoking previous key returned %d: %s",
			delRes.status, string(delRes.body),
		)
	}

	fmt.Println()
	fmt.Printf("  Rotated API key for profile %q\n", profileName)
	fmt.Printf("  New key:  %s (%s)\n", maskKeyShort(minted.Secret), familyLabel(keyFamily(minted.Secret)))
	fmt.Printf("  Revoked:  %s\n", me.APIKeyID)
	fmt.Printf("  Saved to: %s\n", store.Path)
	fmt.Println()
	return nil
}
