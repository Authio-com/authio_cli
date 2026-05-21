package cmd

import (
	"strings"
	"testing"
)

func TestParseClerkNativeFlags_Defaults(t *testing.T) {
	f, err := parseClerkNativeFlags([]string{
		"--secret-key", "sk_live_xxx",
		"--authio-project", "proj_abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.SecretKey != "sk_live_xxx" {
		t.Errorf("secret_key=%q", f.SecretKey)
	}
	if f.AuthioProject != "proj_abc" {
		t.Errorf("authio_project=%q", f.AuthioProject)
	}
	if !f.IncludeUsers || !f.IncludeOrgs || !f.IncludeMemberships {
		t.Errorf("expected include-users/orgs/memberships=true by default; got %+v", f)
	}
	if !f.IncludeOAuthBindings || !f.IncludeMFA {
		t.Errorf("expected include-oauth-bindings/mfa=true by default; got %+v", f)
	}
	if f.RateLimit <= 0 {
		t.Errorf("rate-limit should default to a positive value, got %v", f.RateLimit)
	}
	if f.BatchSize != 100 {
		t.Errorf("batch-size default=%d want 100", f.BatchSize)
	}
}

func TestParseClerkNativeFlags_OptOuts(t *testing.T) {
	f, err := parseClerkNativeFlags([]string{
		"--secret-key", "sk_live_xxx",
		"--authio-project", "proj_abc",
		"--no-mfa",
		"--include-oauth-bindings=false",
		"--rate-limit", "20",
		"--dry-run",
		"--resume-from", "/tmp/state.json",
		"--report", "/tmp/report.csv",
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.IncludeMFA {
		t.Errorf("expected --no-mfa to disable mfa")
	}
	if f.IncludeOAuthBindings {
		t.Errorf("expected --include-oauth-bindings=false to disable oauth bindings")
	}
	if f.RateLimit != 20 {
		t.Errorf("rate-limit=%v want 20", f.RateLimit)
	}
	if !f.DryRun {
		t.Errorf("expected dry-run=true")
	}
	if f.ResumeFrom != "/tmp/state.json" {
		t.Errorf("resume-from=%q", f.ResumeFrom)
	}
	if f.ReportPath != "/tmp/report.csv" {
		t.Errorf("report=%q", f.ReportPath)
	}
}

func TestParseClerkNativeFlags_MissingRequired(t *testing.T) {
	if _, err := parseClerkNativeFlags(nil); err == nil {
		t.Fatal("expected error when no flags supplied")
	}
	if _, err := parseClerkNativeFlags([]string{"--secret-key", "sk"}); err == nil {
		t.Fatal("expected error without --authio-project")
	} else if !strings.Contains(err.Error(), "authio-project") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHasClerkNativeFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"--secret-key", "x"}, true},
		{[]string{"--input", "x.json"}, false},
		{[]string{"--live-token", "x"}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := hasClerkNativeFlag(c.args); got != c.want {
			t.Errorf("hasClerkNativeFlag(%v)=%v want %v", c.args, got, c.want)
		}
	}
}
