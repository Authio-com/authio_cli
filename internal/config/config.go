// Package config parses the authio.yaml desired-state file consumed by
// `authio check` and `authio apply` (config-as-code, Phase 3 of the
// 2026-09 platform program).
//
// One file describes one project's declarative surface:
//
//	version: 1
//	prune: false                # delete live resources missing from this file
//	redirect_uris:
//	  - uri: https://app.example.com/api/auth/callback
//	    kind: oauth_callback    # oauth_callback | magic_link_redirect | custom_app_callback
//	webhooks:
//	  - url: https://app.example.com/api/authio/webhook
//	    events: ["session.revoked", "user.created"]   # default ["*"]
//	    description: main receiver
//	risk_policy:
//	  threshold_step_up: 50
//	  threshold_block: 90
//	  signal_weights: { new_device: 25 }
//	  enabled_signals: [new_device]
//	sso_connections:
//	  - organization_id: org_...
//	    external_id: acme-okta  # stable identity for diffing (required)
//	    provider: saml
//	    display_name: Acme Okta
//	    saml: { metadata_url: ..., sso_url: ..., certificate: ... }
//
// Identity keys for diffing: redirect_uris by uri, webhooks by url,
// sso_connections by organization_id + external_id, risk_policy is a
// singleton. Webhook secrets are write-only: they are returned exactly
// once at create/replace time and never stored in the file.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is the root of authio.yaml.
type File struct {
	Version        int             `yaml:"version"`
	Prune          bool            `yaml:"prune"`
	RedirectURIs   []RedirectURI   `yaml:"redirect_uris"`
	Webhooks       []Webhook       `yaml:"webhooks"`
	RiskPolicy     *RiskPolicy     `yaml:"risk_policy"`
	SSOConnections []SSOConnection `yaml:"sso_connections"`
}

// RedirectURI declares one allowed redirect URI. Identity: URI.
type RedirectURI struct {
	URI  string `yaml:"uri"`
	Kind string `yaml:"kind"` // default oauth_callback
}

// Webhook declares one webhook endpoint. Identity: URL. The management
// API has no update endpoint — event/description drift is resolved by
// replace (revoke + recreate), which rotates the secret.
type Webhook struct {
	URL            string   `yaml:"url"`
	Events         []string `yaml:"events"` // default ["*"]
	Description    string   `yaml:"description"`
	OrganizationID string   `yaml:"organization_id"`
}

// RiskPolicy declares the project's risk-engine policy (singleton,
// PUT /v1/risk/policy upsert).
type RiskPolicy struct {
	ThresholdStepUp int            `yaml:"threshold_step_up"`
	ThresholdBlock  int            `yaml:"threshold_block"`
	SignalWeights   map[string]int `yaml:"signal_weights"`
	EnabledSignals  []string       `yaml:"enabled_signals"`
}

// SSOConnection declares one org SSO connection. Identity:
// organization_id + external_id (the management API's idempotent-create
// key). The saml/oidc config blocks are write-only from the API's list
// surface, so they are sent on create but cannot be drift-detected —
// changing IdP config on an existing connection is a dashboard job.
type SSOConnection struct {
	OrganizationID  string            `yaml:"organization_id"`
	ExternalID      string            `yaml:"external_id"`
	Provider        string            `yaml:"provider"` // saml | oidc
	DisplayName     string            `yaml:"display_name"`
	IdPProvider     string            `yaml:"idp_provider"`
	SAML            map[string]any    `yaml:"saml"`
	OIDC            map[string]any    `yaml:"oidc"`
	AttributeMap    map[string]string `yaml:"attribute_map"`
	JITProvisioning *bool             `yaml:"jit_provisioning"`
	DefaultRole     string            `yaml:"default_role"`
	Status          string            `yaml:"status"`
}

var redirectKinds = map[string]bool{
	"oauth_callback":      true,
	"magic_link_redirect": true,
	"custom_app_callback": true,
}

// Load reads and validates an authio.yaml file. Validation is
// shape-level only — URL reachability, redirect-URI policy, and signal
// names are the management API's call, surfaced per-action at apply.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // typos in keys are config bugs, not extensions
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

func (f *File) validate() error {
	if f.Version != 0 && f.Version != 1 {
		return fmt.Errorf("unsupported version %d (this CLI understands version: 1)", f.Version)
	}
	seenURI := map[string]bool{}
	for i, r := range f.RedirectURIs {
		if strings.TrimSpace(r.URI) == "" {
			return fmt.Errorf("redirect_uris[%d]: uri is required", i)
		}
		if r.Kind != "" && !redirectKinds[r.Kind] {
			return fmt.Errorf("redirect_uris[%d]: unknown kind %q", i, r.Kind)
		}
		if seenURI[r.URI] {
			return fmt.Errorf("redirect_uris[%d]: duplicate uri %q", i, r.URI)
		}
		seenURI[r.URI] = true
	}
	seenURL := map[string]bool{}
	for i, w := range f.Webhooks {
		if strings.TrimSpace(w.URL) == "" {
			return fmt.Errorf("webhooks[%d]: url is required", i)
		}
		if seenURL[w.URL] {
			return fmt.Errorf("webhooks[%d]: duplicate url %q (webhook identity is the url)", i, w.URL)
		}
		seenURL[w.URL] = true
	}
	if p := f.RiskPolicy; p != nil {
		if p.ThresholdStepUp < 0 || p.ThresholdStepUp > 100 ||
			p.ThresholdBlock < 0 || p.ThresholdBlock > 100 {
			return fmt.Errorf("risk_policy: thresholds must be 0–100")
		}
		if p.ThresholdBlock < p.ThresholdStepUp {
			return fmt.Errorf("risk_policy: threshold_block must be >= threshold_step_up")
		}
		for name, w := range p.SignalWeights {
			if w < 0 || w > 100 {
				return fmt.Errorf("risk_policy: signal_weights.%s must be 0–100", name)
			}
		}
	}
	seenSSO := map[string]bool{}
	for i, s := range f.SSOConnections {
		if s.OrganizationID == "" {
			return fmt.Errorf("sso_connections[%d]: organization_id is required", i)
		}
		if s.ExternalID == "" {
			return fmt.Errorf("sso_connections[%d]: external_id is required (it is the stable identity apply diffs on)", i)
		}
		if s.Provider != "saml" && s.Provider != "oidc" {
			return fmt.Errorf("sso_connections[%d]: provider must be saml or oidc", i)
		}
		if strings.TrimSpace(s.DisplayName) == "" {
			return fmt.Errorf("sso_connections[%d]: display_name is required", i)
		}
		if s.DefaultRole != "" && s.DefaultRole != "owner" && s.DefaultRole != "admin" && s.DefaultRole != "member" {
			return fmt.Errorf("sso_connections[%d]: default_role must be owner, admin, or member", i)
		}
		if s.Status != "" && s.Status != "pending" && s.Status != "active" && s.Status != "suspended" {
			return fmt.Errorf("sso_connections[%d]: status must be pending, active, or suspended", i)
		}
		key := s.OrganizationID + "/" + s.ExternalID
		if seenSSO[key] {
			return fmt.Errorf("sso_connections[%d]: duplicate organization_id/external_id %q", i, key)
		}
		seenSSO[key] = true
	}
	return nil
}

// Empty reports whether the file declares nothing to manage — almost
// always a mistake (wrong file), so the commands refuse it explicitly.
func (f *File) Empty() bool {
	return len(f.RedirectURIs) == 0 && len(f.Webhooks) == 0 &&
		f.RiskPolicy == nil && len(f.SSOConnections) == 0
}
