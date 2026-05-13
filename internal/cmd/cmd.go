// Package cmd holds the CLI subcommand implementations.
package cmd

import "fmt"

func Login(_ []string) error {
	fmt.Println("authio login: opens https://app.authio.com/cli for passkey + device-code auth (Phase 3.5).")
	return nil
}

func Init(_ []string) error {
	fmt.Println("authio init: Phase 3.5 will scaffold a Next.js / Express / FastAPI starter linked to your project.")
	return nil
}

func Dev(_ []string) error {
	fmt.Println("authio dev: Phase 3.5 will run a local auth-core proxy with mock JWKS.")
	return nil
}

func Logs(args []string) error {
	if len(args) == 0 || args[0] != "tail" {
		return fmt.Errorf("usage: authio logs tail")
	}
	fmt.Println("authio logs tail: Phase 3.5 streams from authio_audit's query API.")
	return nil
}

func Webhook(args []string) error {
	if len(args) < 2 || args[0] != "listen" {
		return fmt.Errorf("usage: authio webhook listen <local-url>")
	}
	fmt.Printf("authio webhook listen %s: Phase 3.5 tunnels deliveries to %s.\n", args[1], args[1])
	return nil
}
