package cmd

import "testing"

func TestLoginDefaultsToHostedProductionAPIs(t *testing.T) {
	t.Setenv(cliDevEnvironmentVar, "")
	opts, err := parseLoginOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.apiURL != defaultMgmtAPI || opts.authCoreURL != defaultAuthCore {
		t.Fatalf("unexpected defaults: %+v", opts)
	}
	if opts.apiURL == localMgmtAPI || opts.authCoreURL == localAuthCore {
		t.Fatal("login must not default to localhost")
	}
}

func TestLoginDevModeRequiresExplicitFlagOrEnvironment(t *testing.T) {
	t.Setenv(cliDevEnvironmentVar, "")
	opts, err := parseLoginOptions([]string{"--dev"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.apiURL != localMgmtAPI || opts.authCoreURL != localAuthCore {
		t.Fatalf("--dev did not select local services: %+v", opts)
	}

	t.Setenv(cliDevEnvironmentVar, "true")
	opts, err = parseLoginOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.apiURL != localMgmtAPI || opts.authCoreURL != localAuthCore {
		t.Fatalf("%s did not select local services: %+v", cliDevEnvironmentVar, opts)
	}
}

func TestLoginHonorsProfileAndEndpointOverrides(t *testing.T) {
	t.Setenv(cliDevEnvironmentVar, "")
	opts, err := parseLoginOptions([]string{
		"--profile", "staging",
		"--api-url", "https://api.example/",
		"--auth-core-url", "https://auth.example/",
		"--no-browser",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.profile != "staging" {
		t.Fatalf("profile = %q, want staging", opts.profile)
	}
	if opts.apiURL != "https://api.example" || opts.authCoreURL != "https://auth.example" {
		t.Fatalf("endpoint overrides not normalized: %+v", opts)
	}
	if !opts.noBrowser {
		t.Fatal("--no-browser was not honored")
	}
}

func TestLoginRejectsMissingProfileValue(t *testing.T) {
	t.Setenv(cliDevEnvironmentVar, "")
	if _, err := parseLoginOptions([]string{"--profile"}); err == nil {
		t.Fatal("expected missing --profile value to fail")
	}
}
