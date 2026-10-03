package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tcast/authio_cli/internal/credentials"
)

// Env surfaces and switches the active Authio environment for CLI
// operations.
//
//	authio env [show]          show the active profile's environment
//	authio env list [--json]   list configured profiles + their environment
//	authio env use <profile>   make a profile active for future commands
//
// Design note (environments / A3): an Authio api key is environment-
// scoped — a `sk_test_` key only ever sees its non-production project's
// data, a `sk_live_` key only its production project's. The CLI
// therefore models "environments" as named credential profiles: each
// profile holds one environment-scoped key, and `env use` selects which
// one subsequent commands target. `env list` resolves each profile
// against `/v1/projects/me` to show its real environment + tenant.
//
// Since AUT-71 management-api also exposes a read-only, sk_-authed
// `GET /v1/environments` that lists every environment in the key's
// tenant. `env list` calls it with the active profile and prints the
// tenant's environments below the profile table, marking which ones a
// local profile already covers — so a user with only one key can still
// see the siblings they have no key for yet.
func Env(args []string) error {
	sub := "show"
	var rest []string
	if len(args) > 0 {
		sub = args[0]
		rest = args[1:]
	}
	switch sub {
	case "show", "current":
		return envShow(rest)
	case "list", "ls":
		return envList(rest)
	case "use", "switch":
		return envUse(rest)
	default:
		return errors.New("usage: authio env [show|list|use <profile>]")
	}
}

func envShow(args []string) error {
	name := resolveProfileName(args)
	p, name, err := loadProfile(name)
	if err != nil {
		return err
	}
	res, err := apiGet(p, "/v1/projects/me")
	if err != nil {
		return fmt.Errorf("reach management API: %w", err)
	}
	if res.status != 200 {
		return fmt.Errorf("GET /v1/projects/me returned %d: %s", res.status, string(res.body))
	}
	var me projectMe
	if err := json.Unmarshal(res.body, &me); err != nil {
		return err
	}
	fmt.Println()
	fmt.Printf("  Active profile: %s\n", name)
	fmt.Printf("  Environment:    %s (%s)\n", describeEnv(me.Environment), me.Name)
	fmt.Printf("  Tenant:         %s\n", orDash(me.Tenant.Name))
	fmt.Printf("  Key family:     %s\n", familyLabel(keyFamily(p.APIKey)))
	fmt.Println()
	return nil
}

type envListItem struct {
	Profile     string `json:"profile"`
	Active      bool   `json:"active"`
	Environment string `json:"environment"`
	ProjectID   string `json:"project_id,omitempty"`
	ProjectName string `json:"project_name"`
	Tenant      string `json:"tenant"`
	KeyFamily   string `json:"key_family"`
	Error       string `json:"error,omitempty"`
}

// tenantEnvironment is one row of GET /v1/environments.
type tenantEnvironment struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Environment  string `json:"environment"`
	IsProduction bool   `json:"is_production"`
	Slug         string `json:"slug"`
	Purpose      string `json:"purpose"`
	Current      bool   `json:"current"`
	// Profile is filled in locally: the name of a configured profile whose
	// key belongs to this environment, or "" when none does.
	Profile string `json:"profile,omitempty"`
}

type envListOutput struct {
	Profiles           []envListItem       `json:"profiles"`
	TenantEnvironments []tenantEnvironment `json:"tenant_environments,omitempty"`
	TenantError        string              `json:"tenant_environments_error,omitempty"`
}

// fetchTenantEnvironments lists the tenant's environments through the
// active profile's key. A 404 means the management API predates the
// route; that is reported as a soft error, not a failure.
func fetchTenantEnvironments(store *credentials.Store, active string) ([]tenantEnvironment, string) {
	if active == "" {
		return nil, "no active profile"
	}
	p, err := store.Load(active)
	if err != nil {
		return nil, err.Error()
	}
	res, err := apiGet(p, "/v1/environments")
	if err != nil {
		return nil, "unreachable"
	}
	switch res.status {
	case 200:
	case 401:
		return nil, "invalid/revoked key"
	case 403:
		return nil, "key lacks projects:read"
	case 404:
		return nil, "not supported by this management API"
	default:
		return nil, fmt.Sprintf("http %d", res.status)
	}
	var body struct {
		Environments []tenantEnvironment `json:"environments"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, "unparseable response"
	}
	return body.Environments, ""
}

func envList(args []string) error {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
	}
	store, err := credentials.DefaultStore()
	if err != nil {
		return err
	}
	names, err := store.Names()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("no profiles configured — run `authio login`")
	}
	active := store.ActiveProfile()

	items := make([]envListItem, 0, len(names))
	for _, name := range names {
		item := envListItem{Profile: name, Active: name == active}
		p, err := store.Load(name)
		if err != nil {
			item.Error = err.Error()
			items = append(items, item)
			continue
		}
		item.KeyFamily = keyFamily(p.APIKey)
		res, err := apiGet(p, "/v1/projects/me")
		if err != nil {
			item.Error = "unreachable"
		} else if res.status == 401 {
			item.Error = "invalid/revoked key"
		} else if res.status != 200 {
			item.Error = fmt.Sprintf("http %d", res.status)
		} else {
			var me projectMe
			if json.Unmarshal(res.body, &me) == nil {
				item.Environment = describeEnv(me.Environment)
				item.ProjectID = me.ID
				item.ProjectName = me.Name
				item.Tenant = me.Tenant.Name
			}
		}
		items = append(items, item)
	}

	// Sibling environments, via the active profile's key.
	tenantEnvs, tenantErr := fetchTenantEnvironments(store, active)
	profileByProject := make(map[string]string, len(items))
	for _, it := range items {
		if it.ProjectID != "" && it.Error == "" {
			profileByProject[it.ProjectID] = it.Profile
		}
	}
	for i := range tenantEnvs {
		tenantEnvs[i].Profile = profileByProject[tenantEnvs[i].ID]
	}

	if asJSON {
		out := envListOutput{Profiles: items, TenantEnvironments: tenantEnvs, TenantError: tenantErr}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Println()
	for _, it := range items {
		marker := "  "
		if it.Active {
			marker = "* "
		}
		if it.Error != "" {
			fmt.Printf("%s%-16s %s\n", marker, it.Profile, "("+it.Error+")")
			continue
		}
		fmt.Printf("%s%-16s %-12s %-12s %s\n",
			marker, it.Profile, it.Environment, familyShort(it.KeyFamily), orDash(it.Tenant))
	}
	fmt.Println()
	fmt.Println("  * = active. Switch with `authio env use <profile>`.")

	if len(tenantEnvs) > 0 {
		fmt.Println()
		fmt.Println("  Environments in this tenant:")
		for _, e := range tenantEnvs {
			marker := "  "
			if e.Current {
				marker = "> "
			}
			profile := "no profile — mint a key in the dashboard"
			if e.Profile != "" {
				profile = "profile: " + e.Profile
			}
			fmt.Printf("  %s%-20s %-12s %s\n", marker, e.Name, describeEnv(e.Environment), profile)
		}
		fmt.Println()
		fmt.Println("  > = the environment the active key belongs to.")
	} else if tenantErr != "" {
		fmt.Println()
		fmt.Printf("  (could not list tenant environments: %s)\n", tenantErr)
	}
	fmt.Println()
	return nil
}

func envUse(args []string) error {
	if len(args) == 0 || args[0] == "" {
		return errors.New("usage: authio env use <profile>")
	}
	target := args[0]
	store, err := credentials.DefaultStore()
	if err != nil {
		return err
	}
	if err := store.SetActiveProfile(target); err != nil {
		return err
	}
	// Best-effort: confirm what they switched to.
	if p, err := store.Load(target); err == nil {
		if res, err := apiGet(p, "/v1/projects/me"); err == nil && res.status == 200 {
			var me projectMe
			if json.Unmarshal(res.body, &me) == nil {
				fmt.Printf("✓ Active environment is now %q → %s (%s)\n", target, describeEnv(me.Environment), me.Name)
				return nil
			}
		}
	}
	fmt.Printf("✓ Active profile is now %q\n", target)
	return nil
}

func familyShort(family string) string {
	switch family {
	case "live":
		return "live"
	case "test":
		return "test"
	default:
		return "—"
	}
}
