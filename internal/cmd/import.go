package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// Import dispatches `authio import <provider> [flags]`.
//
// Two flag dialects are supported in the same surface:
//
//	Legacy streaming (per-user POST + cursor; only auth0|clerk|cognito|firebase|supabase):
//	  authio import <provider> --file <path> [--profile name] [--dry-run] [--force] [--rate-limit-rps N]
//
//	Plan-based (all 8 providers, what the migration wizard uses):
//	  authio import <provider> --input <path>
//	     --management-api-url <url>   (or rely on --profile)
//	     --api-key <key>              (or rely on --profile)
//	     [--orgs-table <file>]   only for providers without native orgs
//	     [--dry-run]              prints the ImportPlan as JSON
//	     [--json]                 stream NDJSON progress events (used by dashboard)
//	     [--default-org-name N]   name for the synthetic org for org-less providers
//
// The two dialects are picked apart by which flag is present: `--input`
// (or `--plan`) triggers plan-mode. Plain `--file` keeps the legacy path.
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

	// Dedicated Clerk importer (T4.1): when --secret-key is present we
	// route to the rich internal/importers/clerk package which preserves
	// passkeys, MFA factors, phone numbers, and CSV reports out of the
	// box. Other dialects (--input, --live-token) keep flowing through
	// the cross-provider plan runner.
	if provider == "clerk" && hasClerkNativeFlag(rest) {
		return runClerkNativeImport(rest)
	}

	// Plan-mode opt-in: `--input`, `--plan`, or `--live-token`. The first
	// two read a file, the third triggers a live admin-API pull.
	planMode := false
	liveMode := false
	for _, a := range rest {
		if a == "--input" || a == "--plan" {
			planMode = true
		}
		if a == "--live-token" {
			planMode = true
			liveMode = true
		}
	}
	_ = liveMode // reserved — runPlanImport detects live mode from flags.
	switch provider {
	case "workos", "stytch", "descope":
		planMode = true
	case "help", "--help", "-h":
		fmt.Println(importUsage())
		return nil
	}

	if planMode {
		pp, err := PlanParserFor(provider)
		if err != nil {
			return err
		}
		return runPlanImport(pp, rest)
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
	}
	return fmt.Errorf("unknown provider %q (auth0|clerk|cognito|firebase|supabase|workos|stytch|descope)", provider)
}

func importUsage() string {
	return `usage: authio import <provider> [flags]

CLERK (dedicated importer — T4.1 — recommended)
  authio import clerk \
    --secret-key sk_live_clerk_xxx \
    --authio-project proj_xxx \
    [--dry-run] [--include-users] [--include-orgs]
    [--include-memberships] [--include-oauth-bindings] [--include-mfa]
    [--rate-limit 50] [--resume-from PATH] [--report PATH]
  See ` + "`" + `authio import clerk --help` + "`" + ` for the full flag set.

PROVIDERS (plan-mode — full orgs/memberships/identities graph)
  auth0       Auth0 user export bundle
  clerk       Clerk Backend-API user list (or curl'd JSON)
  cognito     AWS Cognito list-users + groups bundle
  firebase    firebase auth:export JSON
  supabase    auth.users JSON dump (optional --orgs-table for org graph)
  workos      WorkOS bundle (users, orgs, memberships, sso, directories)
              — merges duplicate-email accounts across WorkOS orgs into
                one Authio user with multi-org memberships.
  stytch      Stytch B2B (orgs+members) or Consumer (flat) export
  descope     Descope users + tenants + sso bundle

FLAGS (plan-mode)
  --input <path>             required
  --management-api-url <url> override; falls back to --profile creds
  --api-key <key>            override; falls back to --profile creds
  --orgs-table <file>        optional org graph (supabase, firebase)
  --default-org-name <name>  for providers without native orgs (default: "Default")
  --dry-run                  print the ImportPlan as JSON; no writes
  --json                     stream NDJSON progress events (machine-readable)
  --profile <name>           credentials profile (default: "default")

FLAGS (legacy streaming)
  --file <path>              required
  --profile <name>           credentials profile
  --api-url <url>            override
  --rate-limit-rps <n>       cap requests/sec (default: 50)
  --dry-run                  parse + count without POSTing
  --force                    resume even if file size changed

DETAILS
  authio import <provider> --help    show provider-specific notes`
}

func printProviderHelp(provider string) error {
	switch strings.ToLower(provider) {
	case "auth0":
		fmt.Println(auth0PlanParser{}.Help())
	case "clerk":
		// The dedicated importer (T4.1) is the recommended path for
		// Clerk migrations. Print its help first, then a footer
		// pointing at the legacy --input/--live-token plan-mode for
		// operators who still need file-based imports.
		fmt.Println(clerkNativeHelp())
		fmt.Println()
		fmt.Println("LEGACY MODE (file or live-token-only plan import)")
		fmt.Println(clerkPlanParser{}.Help())
	case "cognito":
		fmt.Println(cognitoPlanParser{}.Help())
	case "firebase":
		fmt.Println(firebasePlanParser{}.Help())
	case "supabase":
		fmt.Println(supabasePlanParser{}.Help())
	case "workos":
		fmt.Println(workosPlanParser{}.Help())
	case "stytch":
		fmt.Println(stytchPlanParser{}.Help())
	case "descope":
		fmt.Println(descopePlanParser{}.Help())
	default:
		fmt.Println(importUsage())
	}
	return nil
}

// =====================================================================
// plan-mode flag parsing + dispatch
// =====================================================================

type planFlags struct {
	Input          string
	ManagementURL  string
	APIKey         string
	OrgsTable      string
	DefaultOrgName string
	DryRun         bool
	JSON           bool
	Profile        string
	// Live-mode pulls the plan from a provider's Admin API instead of
	// reading a file. When Live.Provider is set, --input is ignored
	// (the file is implicitly "whatever the provider returns now").
	Live LiveCredentials
	LiveBaseURLOverride string
	LiveMaxPages        int
}

func parsePlanFlags(args []string) (*planFlags, error) {
	f := &planFlags{Profile: "default"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input", "--plan", "--file":
			if i+1 < len(args) {
				f.Input = args[i+1]
				i++
			}
		case "--management-api-url", "--api-url":
			if i+1 < len(args) {
				f.ManagementURL = args[i+1]
				i++
			}
		case "--api-key":
			if i+1 < len(args) {
				f.APIKey = args[i+1]
				i++
			}
		case "--orgs-table":
			if i+1 < len(args) {
				f.OrgsTable = args[i+1]
				i++
			}
		case "--default-org-name":
			if i+1 < len(args) {
				f.DefaultOrgName = args[i+1]
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				f.Profile = args[i+1]
				i++
			}
		case "--dry-run":
			f.DryRun = true
		case "--json":
			f.JSON = true
		case "--live-token":
			if i+1 < len(args) {
				// We don't know the provider here yet — the caller stuffs
				// the token into a provider-appropriate field.
				f.Live.Token = args[i+1]
				i++
			}
		case "--auth0-domain":
			if i+1 < len(args) {
				f.Live.Domain = args[i+1]
				i++
			}
		case "--stytch-project-id":
			if i+1 < len(args) {
				f.Live.ProjectID = args[i+1]
				i++
			}
		case "--stytch-secret":
			if i+1 < len(args) {
				f.Live.ProjectSecret = args[i+1]
				i++
			}
		case "--descope-project-id":
			if i+1 < len(args) {
				f.Live.ProjectID = args[i+1]
				i++
			}
		case "--supabase-ref":
			if i+1 < len(args) {
				f.Live.ProjectRef = args[i+1]
				i++
			}
		case "--live-base-url":
			if i+1 < len(args) {
				f.LiveBaseURLOverride = args[i+1]
				i++
			}
		case "--max-pages":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &f.LiveMaxPages)
				i++
			}
		}
	}
	if f.Input == "" && f.Live.Token == "" {
		return nil, errors.New("--input <path> or --live-token <token> is required")
	}
	return f, nil
}

func runPlanImport(parser PlanParser, args []string) error {
	flags, err := parsePlanFlags(args)
	if err != nil {
		return err
	}

	var plan *ImportPlan
	if flags.Live.Token != "" {
		// Live mode — pull from provider Admin API.
		// Stash the token into the provider-specific creds field.
		creds := flags.Live
		switch strings.ToLower(parser.Name()) {
		case "auth0":
			// creds.Token already populated.
			if creds.Domain == "" {
				return errors.New("--auth0-domain is required when using --live-token with auth0")
			}
		case "clerk":
			creds.SecretKey = creds.Token
			creds.Token = ""
		case "workos":
			creds.APIKey = creds.Token
			creds.Token = ""
		case "descope":
			creds.MgmtKey = creds.Token
			creds.Token = ""
			if creds.ProjectID == "" {
				return errors.New("--descope-project-id is required when using --live-token with descope")
			}
		case "stytch":
			if creds.ProjectID == "" || creds.ProjectSecret == "" {
				return errors.New("--stytch-project-id and --stytch-secret are required when using --live-token with stytch")
			}
		case "supabase":
			creds.PAT = creds.Token
			creds.Token = ""
			if creds.ProjectRef == "" {
				return errors.New("--supabase-ref is required when using --live-token with supabase")
			}
		}
		puller, err := LivePullerFor(parser.Name())
		if err != nil {
			return err
		}
		plan, err = puller.PullLive(context.Background(), creds, LiveOptions{
			BaseURLOverride: flags.LiveBaseURLOverride,
			MaxPages:        flags.LiveMaxPages,
		})
		if err != nil {
			return err
		}
	} else {
		f, err := os.Open(flags.Input)
		if err != nil {
			return fmt.Errorf("open --input %s: %w", flags.Input, err)
		}
		defer f.Close()

		opts := PlanOptions{
			OrgsTablePath:        flags.OrgsTable,
			DefaultOrgName:       flags.DefaultOrgName,
			MergeDuplicateEmails: true,
		}
		plan, err = parser.ParsePlan(context.Background(), f, opts)
		if err != nil {
			return err
		}
	}

	if flags.DryRun {
		// Print the plan as JSON for inspection / the dashboard preview.
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	}

	// Resolve credentials.
	apiURL := flags.ManagementURL
	apiKey := flags.APIKey
	if apiKey == "" || apiURL == "" {
		store, err := credentials.DefaultStore()
		if err != nil {
			return err
		}
		creds, err := store.Load(flags.Profile)
		if err != nil {
			return fmt.Errorf("--api-key not provided and profile lookup failed: %w", err)
		}
		if apiKey == "" {
			apiKey = creds.APIKey
		}
		if apiURL == "" {
			apiURL = creds.APIURL
		}
	}
	if apiURL == "" {
		apiURL = defaultMgmtAPI
	}
	apiURL = strings.TrimRight(apiURL, "/")

	runner := &PlanRunner{
		APIURL:   apiURL,
		APIKey:   apiKey,
		EmitJSON: flags.JSON,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
	_, err = runner.Run(context.Background(), plan)
	return err
}

// =====================================================================
// backward-compat: kept so internal/cmd/import_test.go's existing
// TestParseAuth0ExportArray / NDJSON / Empty tests keep passing.
// =====================================================================

type Auth0User struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Nickname      string `json:"nickname"`
}

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

var _ = context.Background
