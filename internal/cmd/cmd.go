// Package cmd holds the CLI subcommand implementations.
package cmd

import (
	"errors"
	"fmt"

	"github.com/tcast/authio_cli/internal/credentials"
)

// Logs is `authio logs tail`. Phase 3.5 streams from authio_audit's query
// API; for now, we resolve the saved credentials and show how to query the
// audit log via curl. This is a stop-gap until the streaming endpoint
// lands.
func Logs(args []string) error {
	if len(args) == 0 || args[0] != "tail" {
		return errors.New("usage: authio logs tail [--profile name]")
	}
	profile := "default"
	for i := 1; i < len(args); i++ {
		if args[i] == "--profile" && i+1 < len(args) {
			profile = args[i+1]
			i++
		}
	}
	store, err := credentials.DefaultStore()
	if err != nil {
		return err
	}
	c, err := store.Load(profile)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("  Tailing audit events for project", c.ProjectID)
	fmt.Println()
	fmt.Println("  Live streaming endpoint lands in Phase 3.5. For now, fetch a recent")
	fmt.Println("  page directly:")
	fmt.Println()
	fmt.Printf("    curl '%s/v1/audit-events?limit=50' \\\n", c.APIURL)
	fmt.Printf("      -H 'Authorization: Bearer %s'\n", maskKey(c.APIKey))
	fmt.Println()
	return nil
}

// Webhook handles `authio webhook listen <url>` — currently a placeholder
// that documents the recommended `ngrok http` workflow until we wire a
// first-party tunnel.
func Webhook(args []string) error {
	if len(args) < 2 || args[0] != "listen" {
		return errors.New("usage: authio webhook listen <local-url>")
	}
	target := args[1]
	fmt.Println()
	fmt.Println("  Phase 3.5 ships a first-party tunnel. For now, the workflow is:")
	fmt.Println()
	fmt.Println("    1. ngrok http", target)
	fmt.Println("    2. POST /v1/webhooks with the public ngrok URL (or use the dashboard)")
	fmt.Println("    3. Trigger an action (e.g. create an org) — your local server receives the POST.")
	fmt.Println()
	return nil
}

// Init scaffolds an example app — points at create-authio-app.
func Init(_ []string) error {
	fmt.Println()
	fmt.Println("  authio init has been replaced by:")
	fmt.Println()
	fmt.Println("    npx create-authio-app my-app")
	fmt.Println()
	fmt.Println("  See https://authiodocs-production.up.railway.app/quickstart/create-authio-app")
	fmt.Println()
	return nil
}

func maskKey(s string) string {
	if len(s) < 12 {
		return "<key>"
	}
	return s[:8] + "…" + s[len(s)-4:]
}
