// Command authio is the Authio CLI. Commands:
//
//	authio login                          OAuth + passkey login to your account
//	authio init                           Scaffold an example app linked to your project
//	authio dev                             Local proxy with mock JWKS for offline dev
//	authio logs tail                      Tail audit + delivery logs
//	authio webhook listen <url>           Tunnel webhooks to a local URL (Stripe-listen-style)
//	authio import auth0|clerk|cognito|firebase|supabase ...
//	                                       Bulk-import existing users from another auth provider
//	authio version                        Print version info
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/tcast/authio_cli/internal/cmd"
)

const version = "0.1.0-alpha.0"

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
  init                 Scaffold an example app linked to your project
  dev                  Run a local auth-core proxy with mock JWKS
  logs tail            Tail audit + webhook delivery logs
  webhook listen URL   Tunnel webhook deliveries to a local URL
  import <provider>    Bulk-import users from another auth platform
                       Providers: auth0, clerk, cognito, firebase, supabase
  version              Print version info
  help                 Show this help`)
}
