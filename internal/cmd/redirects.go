package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Redirects handles `authio redirects <subcommand>`.
func Redirects(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: authio redirects list|create")
	}
	switch args[0] {
	case "list":
		return redirectsList(args[1:])
	case "create":
		return redirectsCreate(args[1:])
	default:
		return fmt.Errorf("unknown redirects subcommand %q", args[0])
	}
}

func redirectsList(args []string) error {
	p, _, err := loadProfile(resolveProfileName(args))
	if err != nil {
		return err
	}
	res, err := apiGet(p, "/v1/redirect-uris")
	if err != nil {
		return fmt.Errorf("list redirects: %w", err)
	}
	if res.status != 200 {
		return apiStatusError("GET /v1/redirect-uris", res.status, res.body)
	}
	if flagSet(args, "--json") {
		fmt.Println(string(res.body))
		return nil
	}
	var payload struct {
		Data []struct {
			ID   string `json:"id"`
			URI  string `json:"uri"`
			Kind string `json:"kind"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.body, &payload); err != nil {
		fmt.Println(string(res.body))
		return nil
	}
	if len(payload.Data) == 0 {
		fmt.Println("No redirect URIs.")
		return nil
	}
	for _, row := range payload.Data {
		fmt.Printf("%s  %s  %s\n", row.ID, row.Kind, row.URI)
	}
	return nil
}

func redirectsCreate(args []string) error {
	uri := flagValue(args, "--uri")
	if uri == "" {
		return errors.New("usage: authio redirects create --uri https://app.example.com/callback [--kind oauth_callback]")
	}
	kind := flagValue(args, "--kind")
	if kind == "" {
		kind = "oauth_callback"
	}
	p, _, err := loadProfile(resolveProfileName(args))
	if err != nil {
		return err
	}
	res, err := apiPost(p, "/v1/redirect-uris", map[string]any{"uri": uri, "kind": kind})
	if err != nil {
		return fmt.Errorf("create redirect: %w", err)
	}
	if res.status != 201 && res.status != 200 {
		return apiStatusError("POST /v1/redirect-uris", res.status, res.body)
	}
	if flagSet(args, "--json") {
		fmt.Println(string(res.body))
		return nil
	}
	fmt.Println(string(res.body))
	return nil
}
