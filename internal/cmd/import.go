package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// Import handles `authio import <provider> --file <path>` and progressively
// uploads users into the customer's Authio project. We never import password
// hashes — users get a magic-link enrollment invitation on their first
// attempted sign-in.
func Import(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: authio import <provider> --file <path> [--profile <name>] [--dry-run]")
	}
	provider := strings.ToLower(args[0])
	rest := args[1:]
	switch provider {
	case "auth0":
		return importAuth0(rest)
	case "clerk", "cognito", "firebase", "supabase":
		return fmt.Errorf("authio import %s: not implemented yet — see https://authiodocs-production.up.railway.app/quickstart/migrate", provider)
	}
	return fmt.Errorf("unknown provider %q (auth0, clerk, cognito, firebase, supabase)", provider)
}

// =====================================================================
// auth0 — reads a Management API user-export JSON or NDJSON file
// =====================================================================

// Auth0User is the subset of fields we read from an Auth0 user export. The
// official format wraps a JSON array of these. Some exports also use NDJSON.
type Auth0User struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Nickname      string `json:"nickname"`
}

func importAuth0(args []string) error {
	var (
		path     = ""
		profile  = "default"
		dryRun   = false
		throttle = 50 * time.Millisecond
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file":
			if i+1 < len(args) {
				path = args[i+1]
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				profile = args[i+1]
				i++
			}
		case "--dry-run":
			dryRun = true
		}
	}
	if path == "" {
		return errors.New("--file <path> is required")
	}

	users, err := parseAuth0Export(path)
	if err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	fmt.Printf("  Parsed %d users from %s\n", len(users), path)

	if dryRun {
		for i, u := range users {
			if i >= 5 {
				fmt.Printf("  ... %d more\n", len(users)-5)
				break
			}
			fmt.Printf("    would import %s (%s)\n", u.Email, u.UserID)
		}
		return nil
	}

	store, err := credentials.DefaultStore()
	if err != nil {
		return err
	}
	creds, err := store.Load(profile)
	if err != nil {
		return err
	}
	if creds.APIURL == "" {
		creds.APIURL = defaultMgmtAPI
	}

	cursorPath := path + ".authio-import.cursor"
	startAt := readCursor(cursorPath)
	if startAt > 0 {
		fmt.Printf("  Resuming from index %d\n", startAt)
	}

	created, existed, failed := 0, 0, 0
	for i := startAt; i < len(users); i++ {
		u := users[i]
		if u.Email == "" {
			failed++
			continue
		}
		body, _ := json.Marshal(map[string]any{
			"email":          strings.ToLower(strings.TrimSpace(u.Email)),
			"name":           u.Name,
			"email_verified": u.EmailVerified,
		})
		req, _ := http.NewRequest(http.MethodPost, creds.APIURL+"/v1/users", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+creds.APIKey)
		req.Header.Set("User-Agent", "authio-cli-import-auth0/0.1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Printf("    err  %s — %v\n", u.Email, err)
			failed++
			writeCursor(cursorPath, i)
			time.Sleep(throttle)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case 200:
			existed++
		case 201:
			created++
		default:
			failed++
			fmt.Printf("    err  %s — %d %s\n", u.Email, resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		writeCursor(cursorPath, i+1)
		if (i+1)%25 == 0 {
			fmt.Printf("  ... %d / %d processed (created=%d, existed=%d, failed=%d)\n",
				i+1, len(users), created, existed, failed)
		}
		time.Sleep(throttle)
	}
	fmt.Printf("  Done. created=%d existed=%d failed=%d\n", created, existed, failed)
	if failed == 0 {
		_ = os.Remove(cursorPath)
	}
	return nil
}

func parseAuth0Export(path string) ([]Auth0User, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(b)
	// Try JSON array first.
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var users []Auth0User
		if err := json.Unmarshal(trimmed, &users); err != nil {
			return nil, err
		}
		return users, nil
	}
	// NDJSON: one user per line.
	var users []Auth0User
	for _, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var u Auth0User
		if err := json.Unmarshal(line, &u); err != nil {
			return nil, fmt.Errorf("line %s: %w", string(line[:min(80, len(line))]), err)
		}
		users = append(users, u)
	}
	return users, nil
}

func readCursor(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(string(bytes.TrimSpace(b)), "%d", &n)
	return n
}

func writeCursor(path string, n int) {
	_ = os.WriteFile(path, []byte(fmt.Sprintf("%d\n", n)), 0o644)
}
