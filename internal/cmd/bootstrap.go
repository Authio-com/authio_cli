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

// Bootstrap dispatches `authio bootstrap <subcommand>`.
//
// Today the only subcommand is `mint`, which calls the
// authio_management-api admin endpoint at
// POST /v1/admin/bootstrap-tokens to mint a single-use, hashed
// bootstrap token. The plaintext is printed to stdout exactly once;
// the CLI does NOT persist the plaintext to ~/.authio or anywhere
// else (that would defeat the single-use property).
//
// Auth: the call carries a `sk_live_…` key as a Bearer token. The
// key must belong to the platform admin project
// (AUTHIO_ADMIN_PROJECT_ID on the management-api). Source order:
//
//  1. --api-key flag
//  2. AUTHIO_API_KEY env var
//  3. ~/.authio/credentials.toml (`--profile`, default `default`)
//
// The API URL follows the same order via --api-url / AUTHIO_MGMT_API_URL
// / the saved profile.
func Bootstrap(args []string) error {
	if len(args) == 0 {
		return errors.New(bootstrapUsage())
	}
	switch args[0] {
	case "mint":
		return bootstrapMint(args[1:])
	case "help", "--help", "-h":
		fmt.Println(bootstrapUsage())
		return nil
	}
	return errors.New("unknown bootstrap subcommand: " + args[0])
}

func bootstrapUsage() string {
	return `usage: authio bootstrap <subcommand>

SUBCOMMANDS
  mint [--hours N] [--purpose bootstrap|dashboard_operator]
       [--api-url URL] [--api-key sk_live_...] [--profile name]

      Mint a single-use bootstrap token. Requires a sk_live_ key in
      the platform admin project. The plaintext is printed once;
      hand it to the operator who will run /v1/auth/bootstrap-consume
      (or /v1/dashboard/operators/bootstrap-consume). The CLI does
      not cache the plaintext.

      Defaults: --hours 24 (max 168), --purpose bootstrap.

      Auth resolution order: --api-key, $AUTHIO_API_KEY, the saved
      profile (default "default"). API URL: --api-url,
      $AUTHIO_MGMT_API_URL, the saved profile, then ` + defaultMgmtAPI + `.`
}

type bootstrapMintFlags struct {
	Hours   int
	Purpose string
	APIURL  string
	APIKey  string
	Profile string
}

func parseBootstrapMintFlags(args []string) (*bootstrapMintFlags, error) {
	f := &bootstrapMintFlags{
		Hours:   24,
		Purpose: "bootstrap",
		Profile: "default",
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--hours":
			if i+1 >= len(args) {
				return nil, errors.New("--hours requires a value")
			}
			var n int
			if _, err := fmt.Sscanf(args[i+1], "%d", &n); err != nil || n <= 0 {
				return nil, fmt.Errorf("--hours: %q is not a positive integer", args[i+1])
			}
			f.Hours = n
			i++
		case "--purpose":
			if i+1 >= len(args) {
				return nil, errors.New("--purpose requires a value")
			}
			f.Purpose = args[i+1]
			i++
		case "--api-url":
			if i+1 >= len(args) {
				return nil, errors.New("--api-url requires a value")
			}
			f.APIURL = args[i+1]
			i++
		case "--api-key":
			if i+1 >= len(args) {
				return nil, errors.New("--api-key requires a value")
			}
			f.APIKey = args[i+1]
			i++
		case "--profile":
			if i+1 >= len(args) {
				return nil, errors.New("--profile requires a value")
			}
			f.Profile = args[i+1]
			i++
		case "--help", "-h":
			fmt.Println(bootstrapUsage())
			return nil, errSilent
		default:
			return nil, fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	switch f.Purpose {
	case "bootstrap", "dashboard_operator":
	default:
		return nil, fmt.Errorf("--purpose must be 'bootstrap' or 'dashboard_operator' (got %q)", f.Purpose)
	}
	if f.Hours > 168 {
		return nil, fmt.Errorf("--hours must be <= 168 (got %d)", f.Hours)
	}
	return f, nil
}

// errSilent is returned when the command printed its own help and
// wants to exit cleanly without main() printing it as an error.
var errSilent = errors.New("")

func bootstrapMint(args []string) error {
	f, err := parseBootstrapMintFlags(args)
	if err != nil {
		if errors.Is(err, errSilent) {
			return nil
		}
		return err
	}

	apiKey := f.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("AUTHIO_API_KEY")
	}
	apiURL := f.APIURL
	if apiURL == "" {
		apiURL = os.Getenv("AUTHIO_MGMT_API_URL")
	}
	if apiKey == "" || apiURL == "" {
		// Fall back to the saved profile only for fields the caller
		// didn't override. The profile may be absent (CI machines
		// commonly only have AUTHIO_API_KEY exported) — that's fine,
		// just continue with whatever we already resolved.
		if store, err := credentials.DefaultStore(); err == nil {
			if prof, err := store.Load(f.Profile); err == nil {
				if apiKey == "" {
					apiKey = prof.APIKey
				}
				if apiURL == "" {
					apiURL = prof.APIURL
				}
			}
		}
	}
	if apiKey == "" {
		return errors.New("no API key resolved: pass --api-key, set $AUTHIO_API_KEY, or run `authio login` first")
	}
	if apiURL == "" {
		apiURL = defaultMgmtAPI
	}
	apiURL = strings.TrimRight(apiURL, "/")

	body, _ := json.Marshal(map[string]any{
		"hours":   f.Hours,
		"purpose": f.Purpose,
	})
	req, err := http.NewRequest(http.MethodPost, apiURL+"/v1/admin/bootstrap-tokens", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "authio-cli/0.1 bootstrap-mint")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("mint bootstrap token: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("mint bootstrap token: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		ID        string `json:"id"`
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
		Purpose   string `json:"purpose"`
		Warning   string `json:"warning"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	// Print the plaintext exactly once. We do NOT touch
	// ~/.authio/credentials.toml or any other on-disk state — the
	// single-use property of the token depends on the operator
	// transmitting it out-of-band immediately.
	fmt.Println()
	fmt.Println("  ✓ Bootstrap token minted.")
	fmt.Println()
	fmt.Printf("    id:         %s\n", out.ID)
	fmt.Printf("    purpose:    %s\n", out.Purpose)
	fmt.Printf("    expires_at: %s\n", out.ExpiresAt)
	fmt.Println()
	fmt.Printf("    token:      %s\n", out.Token)
	fmt.Println()
	if out.Warning != "" {
		fmt.Println("  " + out.Warning)
		fmt.Println()
	}
	return nil
}
