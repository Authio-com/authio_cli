package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Import handles `authio import <provider> --file <path> [flags]`.
//
// Flags supported by every provider:
//
//	--file <path>          required; export file from the source IdP
//	--profile <name>       credentials profile (default: "default")
//	--api-url <url>        override management-api URL
//	--rate-limit-rps <n>   cap requests/sec (default: 50)
//	--dry-run              parse + count without POSTing
//	--force                resume even if the source file size changed
//
// Resumability: each run writes <file>.authio-import.cursor next to the
// source. Re-running picks up from cursor.LastIndex; the cursor key is
// (provider, file, fileSize) so file edits trip a clear error unless you
// pass --force.
//
// Magic-link enrollment for newly-created users happens server-side via
// the existing /v1/users endpoint; the importer never sees password
// material — Authio is passwordless by design.
func Import(args []string) error {
	if len(args) == 0 {
		return errors.New(importUsage())
	}
	provider := strings.ToLower(args[0])
	rest := args[1:]
	for _, a := range rest {
		if a == "--help" || a == "-h" {
			return printProviderHelp(provider)
		}
	}
	switch provider {
	case "auth0":
		return runProviderImport(auth0Parser{}, rest)
	case "clerk":
		return runProviderImport(clerkParser{}, rest)
	case "cognito":
		return runProviderImport(cognitoParser{}, rest)
	case "firebase":
		return runProviderImport(firebaseParser{}, rest)
	case "supabase":
		return runProviderImport(supabaseParser{}, rest)
	case "help", "--help", "-h":
		fmt.Println(importUsage())
		return nil
	}
	return fmt.Errorf("unknown provider %q (auth0, clerk, cognito, firebase, supabase)", provider)
}

func importUsage() string {
	return `usage: authio import <provider> --file <path> [flags]

PROVIDERS
  auth0       Auth0 Management-API user export (JSON array or NDJSON)
  clerk       Clerk Backend-API user export
  cognito     AWS Cognito list-users JSON
  firebase    Firebase auth:export JSON
  supabase    Supabase auth.users JSON dump

FLAGS
  --file <path>           required
  --profile <name>        credentials profile (default: "default")
  --api-url <url>         override management-api URL
  --rate-limit-rps <n>    cap requests/sec (default: 50)
  --dry-run               parse + count without POSTing
  --force                 resume even if the source file size changed

DETAILS
  authio import <provider> --help    show provider-specific notes`
}

func printProviderHelp(provider string) error {
	switch strings.ToLower(provider) {
	case "auth0":
		fmt.Println(auth0Parser{}.Help())
	case "clerk":
		fmt.Println(clerkParser{}.Help())
	case "cognito":
		fmt.Println(cognitoParser{}.Help())
	case "firebase":
		fmt.Println(firebaseParser{}.Help())
	case "supabase":
		fmt.Println(supabaseParser{}.Help())
	default:
		fmt.Println(importUsage())
	}
	return nil
}

// =====================================================================
// backward-compat: kept so internal/cmd/import_test.go's existing
// TestParseAuth0ExportArray / NDJSON / Empty tests keep passing.
// New code should use auth0Parser{}.Parse(...) directly.
// =====================================================================

// Auth0User mirrors the original synchronous shape returned by the legacy
// parseAuth0Export helper.
type Auth0User struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Nickname      string `json:"nickname"`
}

// parseAuth0Export reads the file and returns the full slice in memory.
// Only used by the original test; the live importer streams.
func parseAuth0Export(path string) ([]Auth0User, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var users []Auth0User
		if err := json.Unmarshal(trimmed, &users); err != nil {
			return nil, err
		}
		return users, nil
	}
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

// _ = context.Background to keep context import in this file even if
// future helpers move out — the parsers call ctx.Err() during streaming.
var _ = context.Background
