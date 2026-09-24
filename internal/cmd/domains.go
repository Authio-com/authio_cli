package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Domains handles `authio domains <subcommand>`.
//
// The project comes from the secret key. There is no project id argument,
// so a key cannot be aimed at a different tenant.
func Domains(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: authio domains list|create|verify|branding")
	}
	switch args[0] {
	case "list":
		return domainsList(args[1:])
	case "create":
		return domainsCreate(args[1:])
	case "verify":
		return domainsVerify(args[1:])
	case "branding":
		return domainsBranding(args[1:])
	default:
		return fmt.Errorf("unknown domains subcommand %q (try `authio domains list`)", args[0])
	}
}

func domainsList(args []string) error {
	p, _, err := loadProfile(resolveProfileName(args))
	if err != nil {
		return err
	}
	res, err := apiGet(p, "/v1/custom-domains")
	if err != nil {
		return fmt.Errorf("list domains: %w", err)
	}
	if res.status != 200 {
		return apiStatusError("GET /v1/custom-domains", res.status, res.body)
	}
	if flagSet(args, "--json") {
		fmt.Println(string(res.body))
		return nil
	}
	var rows []struct {
		ID         string `json:"id"`
		Domain     string `json:"domain"`
		Status     string `json:"status"`
		CertStatus string `json:"cert_status"`
	}
	if err := json.Unmarshal(res.body, &rows); err != nil {
		fmt.Println(string(res.body))
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("No custom domains.")
		return nil
	}
	for _, row := range rows {
		cert := row.CertStatus
		if cert == "" {
			cert = "-"
		}
		fmt.Printf("%s  %s  status=%s  cert=%s\n", row.ID, row.Domain, row.Status, cert)
	}
	return nil
}

func domainsCreate(args []string) error {
	domain := flagValue(args, "--domain")
	if domain == "" {
		return errors.New("usage: authio domains create --domain auth.example.com [--org org_] [--json]")
	}
	p, _, err := loadProfile(resolveProfileName(args))
	if err != nil {
		return err
	}
	body := map[string]any{"domain": domain}
	if org := flagValue(args, "--org"); org != "" {
		body["organization_id"] = org
	}
	res, err := apiPost(p, "/v1/custom-domains", body)
	if err != nil {
		return fmt.Errorf("create domain: %w", err)
	}
	if res.status != 201 {
		return apiStatusError("POST /v1/custom-domains", res.status, res.body)
	}
	if flagSet(args, "--json") {
		fmt.Println(string(res.body))
		return nil
	}
	return printDomainCreate(res.body)
}

func domainsVerify(args []string) error {
	id := flagValue(args, "--id")
	if id == "" || strings.Contains(id, "/") {
		return errors.New("usage: authio domains verify --id dom_ [--json]")
	}
	p, _, err := loadProfile(resolveProfileName(args))
	if err != nil {
		return err
	}
	res, err := apiPost(p, "/v1/custom-domains/"+id+"/verify", map[string]any{})
	if err != nil {
		return fmt.Errorf("verify domain: %w", err)
	}
	if res.status != 200 {
		return apiStatusError("POST /v1/custom-domains/"+id+"/verify", res.status, res.body)
	}
	if flagSet(args, "--json") {
		fmt.Println(string(res.body))
		return nil
	}
	fmt.Println(string(res.body))
	return nil
}

func domainsBranding(args []string) error {
	id := flagValue(args, "--id")
	if id == "" || strings.Contains(id, "/") {
		return errors.New("usage: authio domains branding --id dom_ [--display-name name] [--color #112233] [--logo https://...] [--tagline text]")
	}
	branding := map[string]any{}
	if v := flagValue(args, "--display-name"); v != "" {
		branding["display_name"] = v
	}
	if v := flagValue(args, "--color"); v != "" {
		branding["primary_color"] = v
	}
	if v := flagValue(args, "--logo"); v != "" {
		branding["logo_url"] = v
	}
	if v := flagValue(args, "--tagline"); v != "" {
		branding["tagline"] = v
	}
	if len(branding) == 0 {
		return errors.New("pass at least one of --display-name, --color, --logo, --tagline")
	}
	p, _, err := loadProfile(resolveProfileName(args))
	if err != nil {
		return err
	}
	res, err := apiPatch(p, "/v1/custom-domains/"+id+"/branding", map[string]any{"branding": branding})
	if err != nil {
		return fmt.Errorf("update branding: %w", err)
	}
	if res.status != 200 {
		return apiStatusError("PATCH /v1/custom-domains/"+id+"/branding", res.status, res.body)
	}
	if flagSet(args, "--json") {
		fmt.Println(string(res.body))
		return nil
	}
	fmt.Printf("Updated branding for %s\n", id)
	return nil
}

func printDomainCreate(body []byte) error {
	var created struct {
		ID         string `json:"id"`
		Domain     string `json:"domain"`
		Status     string `json:"status"`
		CertStatus string `json:"cert_status"`
		Target     string `json:"target_cname"`
		DNS        []struct {
			Type  string `json:"type"`
			Host  string `json:"host"`
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"dns_instructions"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		fmt.Println(string(body))
		return nil
	}
	fmt.Printf("Created %s (%s)\n", created.Domain, created.ID)
	fmt.Printf("  status=%s  cert=%s\n", created.Status, created.CertStatus)
	if created.Target != "" {
		fmt.Printf("  CNAME target: %s\n", created.Target)
	}
	for _, rec := range created.DNS {
		host := rec.Host
		if host == "" {
			host = rec.Name
		}
		fmt.Printf("  %s %s -> %s\n", rec.Type, host, rec.Value)
	}
	return nil
}

func apiStatusError(what string, status int, body []byte) error {
	var payload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &payload)
	if payload.Code != "" {
		if payload.Message != "" {
			return fmt.Errorf("%s returned %d: %s (%s)", what, status, payload.Code, payload.Message)
		}
		return fmt.Errorf("%s returned %d: %s", what, status, payload.Code)
	}
	return fmt.Errorf("%s returned %d: %s", what, status, strings.TrimSpace(string(body)))
}

func flagSet(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func flagValue(args []string, name string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
