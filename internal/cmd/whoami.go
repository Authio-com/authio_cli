package cmd

import (
	"encoding/json"
	"fmt"
)

// Whoami resolves the active profile, calls GET /v1/projects/me, and
// prints who the current key authenticates as: tenant, environment, key
// family (test/live) and the management API it targets.
//
//	authio whoami [--profile name] [--json]
func Whoami(args []string) error {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
	}
	name := resolveProfileName(args)
	p, name, err := loadProfile(name)
	if err != nil {
		return err
	}

	res, err := apiGet(p, "/v1/projects/me")
	if err != nil {
		return fmt.Errorf("reach management API: %w", err)
	}
	if res.status == 401 {
		return fmt.Errorf("credentials for profile %q are invalid or revoked — run `authio login --profile %s`", name, name)
	}
	if res.status != 200 {
		return fmt.Errorf("GET /v1/projects/me returned %d: %s", res.status, string(res.body))
	}
	var me projectMe
	if err := json.Unmarshal(res.body, &me); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	family := keyFamily(p.APIKey)
	if asJSON {
		out := map[string]any{
			"profile":      name,
			"tenant":       me.Tenant.Name,
			"tenant_id":    me.TenantID,
			"environment":  describeEnv(me.Environment),
			"project_id":   me.ID,
			"project_name": me.Name,
			"key_family":   family,
			"key":          maskKeyShort(p.APIKey),
			"api_url":      p.APIURL,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Println()
	fmt.Printf("  Profile:      %s\n", name)
	fmt.Printf("  Tenant:       %s\n", orDash(me.Tenant.Name))
	fmt.Printf("  Environment:  %s (%s)\n", describeEnv(me.Environment), me.Name)
	fmt.Printf("  Key:          %s (%s)\n", maskKeyShort(p.APIKey), familyLabel(family))
	fmt.Printf("  Project ID:   %s\n", me.ID)
	fmt.Printf("  API:          %s\n", p.APIURL)
	fmt.Println()
	return nil
}

func familyLabel(family string) string {
	switch family {
	case "live":
		return "live key"
	case "test":
		return "test key"
	default:
		return "unknown key type"
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
