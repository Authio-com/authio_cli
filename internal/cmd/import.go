package cmd

import (
	"fmt"
	"strings"
)

// Import handles `authio import <provider> [flags]`.
//
// Supported (planned) providers:
//
//	auth0     reads a Management-API user export, mints invitations
//	clerk     reads a Clerk user export
//	cognito   AWS Cognito user pool export
//	firebase  Firebase Auth user JSON export
//	supabase  Supabase auth.users export
//
// All importers run in *progressive* mode: existing users get a magic-link
// invitation to enroll a passkey on first attempted login. Authio never
// imports password hashes — that's the point.
func Import(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: authio import <provider> [--file path] [--project proj_..]")
	}
	provider := strings.ToLower(args[0])
	switch provider {
	case "auth0", "clerk", "cognito", "firebase", "supabase":
		fmt.Printf("authio import %s: Phase 3.5 ships the actual importer. Plan:\n", provider)
		fmt.Printf("  1. Read a %s user export.\n", provider)
		fmt.Println("  2. For each user, ensure a project-scoped Authio user exists (idempotent).")
		fmt.Println("  3. Send a passkey-enrollment invitation via authio_auth-core.")
		fmt.Println("  4. Emit progress to stdout + a resumable cursor file.")
		return nil
	}
	return fmt.Errorf("unknown provider %q (auth0, clerk, cognito, firebase, supabase)", provider)
}
