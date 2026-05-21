package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tcast/authio_cli/internal/credentials"
	"github.com/tcast/authio_cli/internal/importers/clerk"
)

// clerkNativeFlags is the parsed flag set for
//
//	authio import clerk --secret-key sk_live_clerk_xxx --authio-project proj_xxx [other flags]
//
// We accept the new dedicated-flag dialect AS WELL AS the legacy
// --input <file> / --live-token <token> dialect. The new dialect is
// detected by the presence of --secret-key.
type clerkNativeFlags struct {
	SecretKey            string
	AuthioProject        string
	Profile              string
	AuthioAPIKey         string // overrides credentials.toml
	AuthioAPIURL         string
	DryRun               bool
	IncludeUsers         bool
	IncludeOrgs          bool
	IncludeMemberships   bool
	IncludeOAuthBindings bool
	IncludeMFA           bool
	SendWelcomeEmail     bool
	RateLimit            float64
	BatchSize            int
	ResumeFrom           string
	ReportPath           string
	ClerkBaseURL         string
}

func defaultClerkNativeFlags() *clerkNativeFlags {
	return &clerkNativeFlags{
		Profile:              "default",
		IncludeUsers:         true,
		IncludeOrgs:          true,
		IncludeMemberships:   true,
		IncludeOAuthBindings: true,
		IncludeMFA:           true,
		RateLimit:            clerk.DefaultRateLimit,
		BatchSize:            100,
	}
}

// hasClerkNativeFlag returns true when the legacy auth0/clerk dispatch
// should be bypassed in favor of the new --secret-key dialect.
func hasClerkNativeFlag(args []string) bool {
	for _, a := range args {
		if a == "--secret-key" {
			return true
		}
	}
	return false
}

func parseClerkNativeFlags(args []string) (*clerkNativeFlags, error) {
	f := defaultClerkNativeFlags()
	// Track which include-* flags the user explicitly set so we can
	// distinguish "default true" from "explicitly disabled". The flag
	// parser supports both `--include-users` (toggle) and
	// `--include-users=false` (explicit).
	setIncludes := map[string]bool{}
	setIncludeAt := func(name string, val bool) {
		setIncludes[name] = true
		switch name {
		case "users":
			f.IncludeUsers = val
		case "orgs":
			f.IncludeOrgs = val
		case "memberships":
			f.IncludeMemberships = val
		case "oauth-bindings":
			f.IncludeOAuthBindings = val
		case "mfa":
			f.IncludeMFA = val
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		// Allow --foo=value as well as --foo value.
		if eq := strings.IndexByte(a, '='); eq > 0 && strings.HasPrefix(a, "--") {
			value := a[eq+1:]
			a = a[:eq]
			switch a {
			case "--include-users":
				setIncludeAt("users", parseBoolFlag(value))
			case "--include-orgs":
				setIncludeAt("orgs", parseBoolFlag(value))
			case "--include-memberships":
				setIncludeAt("memberships", parseBoolFlag(value))
			case "--include-oauth-bindings":
				setIncludeAt("oauth-bindings", parseBoolFlag(value))
			case "--include-mfa":
				setIncludeAt("mfa", parseBoolFlag(value))
			case "--send-welcome-email":
				f.SendWelcomeEmail = parseBoolFlag(value)
			case "--rate-limit":
				if n, err := strconv.ParseFloat(value, 64); err == nil && n > 0 {
					f.RateLimit = n
				}
			case "--batch-size":
				if n, err := strconv.Atoi(value); err == nil && n > 0 {
					f.BatchSize = n
				}
			case "--secret-key":
				f.SecretKey = value
			case "--authio-project":
				f.AuthioProject = value
			case "--profile":
				f.Profile = value
			case "--api-key":
				f.AuthioAPIKey = value
			case "--api-url":
				f.AuthioAPIURL = value
			case "--resume-from":
				f.ResumeFrom = value
			case "--report":
				f.ReportPath = value
			case "--clerk-base-url":
				f.ClerkBaseURL = value
			}
			continue
		}
		switch a {
		case "--secret-key":
			if i+1 < len(args) {
				f.SecretKey = args[i+1]
				i++
			}
		case "--authio-project":
			if i+1 < len(args) {
				f.AuthioProject = args[i+1]
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				f.Profile = args[i+1]
				i++
			}
		case "--api-key":
			if i+1 < len(args) {
				f.AuthioAPIKey = args[i+1]
				i++
			}
		case "--api-url", "--management-api-url":
			if i+1 < len(args) {
				f.AuthioAPIURL = args[i+1]
				i++
			}
		case "--dry-run":
			f.DryRun = true
		case "--include-users":
			setIncludeAt("users", true)
		case "--include-orgs":
			setIncludeAt("orgs", true)
		case "--include-memberships":
			setIncludeAt("memberships", true)
		case "--include-oauth-bindings":
			setIncludeAt("oauth-bindings", true)
		case "--include-mfa":
			setIncludeAt("mfa", true)
		case "--no-users":
			setIncludeAt("users", false)
		case "--no-orgs":
			setIncludeAt("orgs", false)
		case "--no-memberships":
			setIncludeAt("memberships", false)
		case "--no-oauth-bindings":
			setIncludeAt("oauth-bindings", false)
		case "--no-mfa":
			setIncludeAt("mfa", false)
		case "--send-welcome-email":
			f.SendWelcomeEmail = true
		case "--rate-limit":
			if i+1 < len(args) {
				if n, err := strconv.ParseFloat(args[i+1], 64); err == nil && n > 0 {
					f.RateLimit = n
				}
				i++
			}
		case "--batch-size":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					f.BatchSize = n
				}
				i++
			}
		case "--resume-from":
			if i+1 < len(args) {
				f.ResumeFrom = args[i+1]
				i++
			}
		case "--report":
			if i+1 < len(args) {
				f.ReportPath = args[i+1]
				i++
			}
		case "--clerk-base-url":
			if i+1 < len(args) {
				f.ClerkBaseURL = args[i+1]
				i++
			}
		}
	}
	if f.SecretKey == "" {
		return nil, errors.New("--secret-key sk_live_... is required")
	}
	if f.AuthioProject == "" {
		return nil, errors.New("--authio-project proj_... is required (run `authio login` to learn yours)")
	}
	return f, nil
}

func parseBoolFlag(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// runClerkNativeImport executes the dedicated Clerk importer that lives
// in internal/importers/clerk. It resolves the Authio API key from
// --api-key / --profile (default) just like the legacy importers do.
func runClerkNativeImport(args []string) error {
	flags, err := parseClerkNativeFlags(args)
	if err != nil {
		return err
	}

	apiURL := flags.AuthioAPIURL
	apiKey := flags.AuthioAPIKey
	if !flags.DryRun && (apiKey == "" || apiURL == "") {
		store, err := credentials.DefaultStore()
		if err != nil {
			return err
		}
		creds, err := store.Load(flags.Profile)
		if err != nil {
			return fmt.Errorf("api-key not provided and profile lookup failed: %w", err)
		}
		if apiKey == "" {
			apiKey = creds.APIKey
		}
		if apiURL == "" {
			apiURL = creds.APIURL
		}
		// Warn (don't error) when the saved project differs from the
		// requested one. The customer can be intentional about this
		// (e.g. one Authio account that owns multiple destination
		// projects).
		if creds.ProjectID != "" && creds.ProjectID != flags.AuthioProject {
			fmt.Fprintf(os.Stderr, "  note: --authio-project %s differs from logged-in project %s; using --authio-project\n",
				flags.AuthioProject, creds.ProjectID)
		}
	}
	if apiURL == "" {
		apiURL = defaultMgmtAPI
	}

	// Dry-run still needs a placeholder API key to satisfy NewImporter's
	// invariant; we never use it since the network calls are bypassed.
	if flags.DryRun && apiKey == "" {
		apiKey = "dry-run"
	}

	imp, err := clerk.NewImporter(flags.SecretKey, apiURL, apiKey, flags.AuthioProject, clerk.Options{
		DryRun:               flags.DryRun,
		IncludeUsers:         flags.IncludeUsers,
		IncludeOrgs:          flags.IncludeOrgs,
		IncludeMemberships:   flags.IncludeMemberships,
		IncludeOAuthBindings: flags.IncludeOAuthBindings,
		IncludeMFA:           flags.IncludeMFA,
		SendWelcomeEmail:     flags.SendWelcomeEmail,
		RateLimit:            flags.RateLimit,
		BatchSize:            flags.BatchSize,
		ResumeFrom:           flags.ResumeFrom,
		ReportPath:           flags.ReportPath,
		ClerkBaseURL:         flags.ClerkBaseURL,
	})
	if err != nil {
		return err
	}
	if _, err := imp.Run(context.Background()); err != nil {
		return err
	}
	return nil
}

// clerkNativeHelp returns the help text for the new flag dialect.
// Printed when `authio import clerk --help` runs AND --secret-key is
// not present (the plan-mode help is the legacy default).
func clerkNativeHelp() string {
	return `clerk: live import from Clerk Backend API.

USAGE
  authio import clerk \
    --secret-key sk_live_clerk_xxx \
    --authio-project proj_xxx \
    [--dry-run] [--include-users] [--include-orgs] [--include-memberships]
    [--include-oauth-bindings] [--include-mfa]
    [--rate-limit 50] [--batch-size 100]
    [--resume-from PATH] [--report PATH]
    [--profile NAME] [--api-key KEY] [--api-url URL]

FLAGS
  --secret-key KEY            Clerk Backend API secret key (sk_live_...).
                              Required. Read once, never logged.
  --authio-project PROJ_ID    Destination Authio project (proj_...).
  --dry-run                   Fetch + transform but skip Authio writes.
  --include-users             Import users.                          default: true
  --include-orgs              Import organizations.                  default: true
  --include-memberships       Import organization memberships.       default: true
  --include-oauth-bindings    Link Clerk OAuth accounts as Authio identities. default: true
  --include-mfa               Import TOTP/SMS factors + passkeys.    default: true
  --no-users / --no-orgs / --no-memberships / --no-oauth-bindings / --no-mfa
                              Disable a category.
  --send-welcome-email        Queue a "your account moved" email per imported user.
  --rate-limit FLOAT          Clerk + Authio writes/sec cap.          default: 50
  --batch-size INT            Rows per bulk POST.                    default: 100
  --resume-from PATH          Read state from PATH instead of the default
                              ($HOME/.authio/clerk-import-state.json).
  --report PATH               Write the CSV report to PATH.
  --profile NAME              Credentials profile from ~/.authio/credentials.toml.
  --api-key KEY               Override the Authio API key.
  --api-url URL               Override the Authio management-api URL.

WHAT IS IMPORTED
  * users.email + email_verified (+ email_verified_at)
  * users.phone_e164 (+ phone_verified_at) for verified primary phone
  * users.name (first_name + last_name -> Username fallback)
  * users.avatar_url (Clerk image_url)
  * users.created_at, last_sign_in_at
  * users.metadata.clerk_user_id (idempotency key on re-runs)
  * users.metadata.clerk_public_metadata + clerk_private_metadata
  * Clerk external_accounts -> Authio identities (oauth_google, oauth_github, ...)
  * Clerk passkeys -> webauthn_credentials (CBOR pub-key is interop-compatible)
  * Clerk TOTP, backup codes, SMS -> Authio MFA factors

WHAT IS NOT IMPORTED
  * password_hash (Clerk's bcrypt hashes — Authio is passwordless;
    users enroll a passkey or magic-link on first sign-in attempt).
  * sessions (users re-auth on next visit).
  * Clerk Email Templates and webhooks (manually recreate in Authio).

RESUME
  State file is written after every batch. A killed run can be resumed
  with the same command line. On a clean exit the state file is
  removed; partial runs leave it behind for inspection.

REPORT
  At the end of every run a CSV report is written next to the state
  file with per-row outcomes (imported / existed / skipped / error).
`
}
