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
// data, a `sk_live_` key only its production project's. There is no
// sk_-authed route to enumerate a tenant's *other* environments (that
// surface is `/v1/session/environments`, which requires a dashboard
// session, not an api key). So the CLI models "environments" as named
// credential profiles: each profile holds one environment-scoped key,
// and `env use` selects which one subsequent commands target. `env list`
// resolves each profile against `/v1/projects/me` to show its real
// environment + tenant.
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
	ProjectName string `json:"project_name"`
	Tenant      string `json:"tenant"`
	KeyFamily   string `json:"key_family"`
	Error       string `json:"error,omitempty"`
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
				item.ProjectName = me.Name
				item.Tenant = me.Tenant.Name
			}
		}
		items = append(items, item)
	}

	if asJSON {
		b, _ := json.MarshalIndent(items, "", "  ")
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
