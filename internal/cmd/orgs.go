package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Orgs handles `authio orgs <subcommand>`.
//
//	authio orgs create --name Acme [--slug acme] [--domain acme.com] [--profile name] [--json]
func Orgs(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: authio orgs create --name <name> [--slug s] [--domain d]")
	}
	switch args[0] {
	case "create":
		return orgsCreate(args[1:])
	default:
		return fmt.Errorf("unknown orgs subcommand %q (try `authio orgs create`)", args[0])
	}
}

func orgsCreate(args []string) error {
	var (
		name, slug, domain string
		asJSON             bool
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "--slug":
			if i+1 < len(args) {
				slug = args[i+1]
				i++
			}
		case "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "--json":
			asJSON = true
		case "--profile":
			if i+1 < len(args) {
				i++
			}
		}
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("usage: authio orgs create --name <name> [--slug s] [--domain d]")
	}

	profileName := resolveProfileName(args)
	p, profileName, err := loadProfile(profileName)
	if err != nil {
		return err
	}

	body := map[string]any{"name": name}
	if slug != "" {
		body["slug"] = slug
	}
	if domain != "" {
		body["domain"] = domain
	}

	res, err := apiPost(p, "/v1/organizations", body)
	if err != nil {
		return fmt.Errorf("create organization: %w", err)
	}
	if res.status == 401 {
		return fmt.Errorf("credentials for profile %q are invalid or revoked — run `authio login --profile %s`", profileName, profileName)
	}
	if res.status != 201 {
		return fmt.Errorf("POST /v1/organizations returned %d: %s", res.status, string(res.body))
	}

	if asJSON {
		fmt.Println(string(res.body))
		return nil
	}

	var org struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(res.body, &org); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Println()
	fmt.Printf("  Created organization %s\n", org.Name)
	fmt.Printf("  ID:   %s\n", org.ID)
	fmt.Printf("  Slug: %s\n", org.Slug)
	fmt.Println()
	return nil
}
