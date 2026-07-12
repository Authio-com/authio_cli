package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Webhooks handles `authio webhooks <subcommand>`.
//
//	authio webhooks create --url https://… [--events a,b] [--description d] [--org org_…] [--profile name] [--json]
//
// Distinct from the legacy `authio webhook listen` (ngrok helper).
func Webhooks(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: authio webhooks create --url <https-url> [--events e1,e2] [--description d]")
	}
	switch args[0] {
	case "create", "add":
		return webhooksCreate(args[1:])
	default:
		return fmt.Errorf("unknown webhooks subcommand %q (try `authio webhooks create`)", args[0])
	}
}

func webhooksCreate(args []string) error {
	var (
		url, description, orgID, eventsRaw string
		asJSON                             bool
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--url":
			if i+1 < len(args) {
				url = args[i+1]
				i++
			}
		case "--description", "--desc":
			if i+1 < len(args) {
				description = args[i+1]
				i++
			}
		case "--events":
			if i+1 < len(args) {
				eventsRaw = args[i+1]
				i++
			}
		case "--org", "--organization-id", "--organization":
			if i+1 < len(args) {
				orgID = args[i+1]
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
	if strings.TrimSpace(url) == "" {
		return errors.New("usage: authio webhooks create --url <https-url> [--events e1,e2] [--description d]")
	}

	profileName := resolveProfileName(args)
	p, profileName, err := loadProfile(profileName)
	if err != nil {
		return err
	}

	events := []string{"*"}
	if eventsRaw != "" {
		events = nil
		for _, part := range strings.Split(eventsRaw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				events = append(events, part)
			}
		}
		if len(events) == 0 {
			events = []string{"*"}
		}
	}

	body := map[string]any{
		"url":    url,
		"events": events,
	}
	if description != "" {
		body["description"] = description
	}
	if orgID != "" {
		body["organization_id"] = orgID
	}

	res, err := apiPost(p, "/v1/webhooks", body)
	if err != nil {
		return fmt.Errorf("create webhook: %w", err)
	}
	if res.status == 401 {
		return fmt.Errorf("credentials for profile %q are invalid or revoked — run `authio login --profile %s`", profileName, profileName)
	}
	if res.status != 201 {
		return fmt.Errorf("POST /v1/webhooks returned %d: %s", res.status, string(res.body))
	}

	if asJSON {
		fmt.Println(string(res.body))
		return nil
	}

	var wh struct {
		ID     string   `json:"id"`
		URL    string   `json:"url"`
		Secret string   `json:"secret"`
		Events []string `json:"events"`
	}
	if err := json.Unmarshal(res.body, &wh); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Println()
	fmt.Printf("  Created webhook endpoint\n")
	fmt.Printf("  ID:     %s\n", wh.ID)
	fmt.Printf("  URL:    %s\n", wh.URL)
	fmt.Printf("  Events: %s\n", strings.Join(wh.Events, ", "))
	fmt.Printf("  Secret: %s\n", wh.Secret)
	fmt.Println()
	fmt.Println("  Store the signing secret now — it is only shown once.")
	fmt.Println()
	return nil
}
