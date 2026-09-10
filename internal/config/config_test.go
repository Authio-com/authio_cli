package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authio.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_FullFile(t *testing.T) {
	f, err := Load(write(t, `
version: 1
prune: true
redirect_uris:
  - uri: https://app.example.com/api/auth/callback
  - uri: https://app.example.com/magic
    kind: magic_link_redirect
webhooks:
  - url: https://app.example.com/api/authio/webhook
    events: ["session.revoked"]
    description: main receiver
risk_policy:
  threshold_step_up: 50
  threshold_block: 90
  signal_weights:
    new_device: 25
  enabled_signals: [new_device]
sso_connections:
  - organization_id: org_1
    external_id: acme-okta
    provider: saml
    display_name: Acme Okta
    jit_provisioning: false
    default_role: member
    saml:
      sso_url: https://idp.example.com/sso
      certificate: fake
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !f.Prune || len(f.RedirectURIs) != 2 || len(f.Webhooks) != 1 ||
		f.RiskPolicy == nil || len(f.SSOConnections) != 1 {
		t.Fatalf("unexpected parse: %+v", f)
	}
	if f.SSOConnections[0].JITProvisioning == nil || *f.SSOConnections[0].JITProvisioning {
		t.Errorf("jit_provisioning false must parse as explicit false, got %v", f.SSOConnections[0].JITProvisioning)
	}
	if f.SSOConnections[0].SAML["sso_url"] != "https://idp.example.com/sso" {
		t.Errorf("saml block lost: %v", f.SSOConnections[0].SAML)
	}
}

func TestLoad_Rejections(t *testing.T) {
	cases := map[string]struct {
		yaml    string
		wantErr string
	}{
		"unknown key": {
			yaml:    "version: 1\nredirekt_uris: []\n",
			wantErr: "not found",
		},
		"bad version": {
			yaml:    "version: 7\n",
			wantErr: "unsupported version",
		},
		"redirect uri missing": {
			yaml:    "redirect_uris:\n  - kind: oauth_callback\n",
			wantErr: "uri is required",
		},
		"bad kind": {
			yaml:    "redirect_uris:\n  - uri: https://x\n    kind: nope\n",
			wantErr: "unknown kind",
		},
		"duplicate webhook": {
			yaml:    "webhooks:\n  - url: https://x/h\n  - url: https://x/h\n",
			wantErr: "duplicate url",
		},
		"inverted thresholds": {
			yaml:    "risk_policy:\n  threshold_step_up: 90\n  threshold_block: 50\n",
			wantErr: "threshold_block must be >= threshold_step_up",
		},
		"sso without external_id": {
			yaml:    "sso_connections:\n  - organization_id: org_1\n    provider: saml\n    display_name: X\n",
			wantErr: "external_id is required",
		},
		"sso bad provider": {
			yaml:    "sso_connections:\n  - organization_id: org_1\n    external_id: a\n    provider: ldap\n    display_name: X\n",
			wantErr: "provider must be saml or oidc",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestEmpty(t *testing.T) {
	f, err := Load(write(t, "version: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Empty() {
		t.Error("file with no managed resources must report Empty")
	}
}
