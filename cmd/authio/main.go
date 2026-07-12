// Command authio is the Authio CLI. Commands:
//
//	authio login                          OAuth + passkey login to your account
//	authio init                           Scaffold an example app linked to your project
//	authio keys rotate                    Create a replacement sk_ and revoke the old one
//	authio orgs create                    Create an organization
//	authio webhooks create                Register a webhook endpoint
//	authio dev                             Local proxy with mock JWKS for offline dev
//	authio logs tail                      Tail audit + delivery logs
//	authio webhook listen <url>           Tunnel webhooks to a local URL (Stripe-listen-style)
//	authio import auth0|clerk|cognito|firebase|supabase ...
//	                                       Bulk-import existing users from another auth provider
//	authio bootstrap mint                  Mint a single-use bootstrap token (admin only)
//	authio version                        Print version info
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/tcast/authio_cli/internal/cmd"
)

// version is overridable at build time via
// `-ldflags "-X main.version=<tag>"` (see scripts/install.sh + the
// release workflow). Defaults to the in-tree dev version.
var version = "0.1.0-alpha.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "authio:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printRootHelp()
		return nil
	}
	switch args[0] {
	case "login":
		return cmd.Login(args[1:])
	case "whoami":
		return cmd.Whoami(args[1:])
	case "doctor":
		return cmd.Doctor(version, args[1:])
	case "env":
		return cmd.Env(args[1:])
	case "keys":
		return cmd.Keys(args[1:])
	case "orgs", "organizations":
		return cmd.Orgs(args[1:])
	case "webhooks":
		return cmd.Webhooks(args[1:])
	case "listen":
		return cmd.Listen(args[1:])
	case "init":
		return cmd.Init(args[1:])
	case "dev":
		return cmd.Dev(args[1:])
	case "logs":
		return cmd.Logs(args[1:])
	case "webhook":
		return cmd.Webhook(args[1:])
	case "import":
		return cmd.Import(args[1:])
	case "users":
		return cmd.Users(args[1:])
	case "migrate":
		return cmd.Migrate(args[1:])
	case "bootstrap":
		return cmd.Bootstrap(args[1:])
	case "version", "--version", "-v":
		fmt.Println("authio", version)
		return nil
	case "help", "--help", "-h":
		printRootHelp()
		return nil
	}
	return errors.New("unknown command: " + args[0] + " (try `authio help`)")
}

func printRootHelp() {
	fmt.Println(`authio — the Authio CLI

USAGE
  authio <command> [args...]

COMMANDS
  login                Authenticate this CLI to your Authio account
  whoami               Show the active environment, tenant, and key
  doctor               Diagnose your local setup (--json for machine output)
  env <subcommand>     Show/list/switch the active environment (list|use)
  keys rotate          Create a replacement sk_ and revoke the previous key
  orgs create          Create an organization (--name required)
  webhooks create      Register a webhook endpoint (--url required)
  listen --forward URL Forward live events to a local endpoint (Stripe-style)
  init                 Scaffold an example app linked to your project
  dev                  Run a local auth-core proxy with mock JWKS
  logs tail            Tail audit + webhook delivery logs
  webhook listen URL   (legacy) ngrok workflow — prefer 'authio listen'
  import <provider>    Bulk-import users from another auth platform
                       Providers: auth0, clerk, cognito, firebase, supabase
  users <subcommand>   User utilities (import from CSV/JSON)
  migrate <subcommand> Live-credentials importer (run|plan).
                       Used by the dashboard wizard's API-token path.
  bootstrap mint       Mint a single-use bootstrap token (admin only)
  version              Print version info
  help                 Show this help`)
}
