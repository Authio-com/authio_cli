package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/tcast/authio_cli/internal/config"
	"github.com/tcast/authio_cli/internal/credentials"
)

// Check and Apply are the config-as-code pair (Phase 3, 2026-09
// platform program):
//
//	authio check  -f authio.yaml    print the plan; exit 2 when drift
//	authio apply  -f authio.yaml    execute the plan
//
// The YAML file declares desired state for a project's redirect URIs,
// webhook endpoints, risk policy, and org SSO connections; the plan is
// the diff between that file and the live management API. Deletions of
// live resources missing from the file happen only with prune (file key
// `prune: true` or the --prune flag) — additive by default so a partial
// file can't wipe a project.

// ---------------------------------------------------------------------
// Plan model
// ---------------------------------------------------------------------

type actionVerb string

const (
	verbCreate  actionVerb = "create"
	verbUpdate  actionVerb = "update"
	verbDelete  actionVerb = "delete"
	verbReplace actionVerb = "replace"
)

type planAction struct {
	verb     actionVerb
	resource string // redirect_uri | webhook | risk_policy | sso_connection
	name     string // human identity (uri, url, org/external_id, "policy")
	detail   string // one-line why / what changes
	execute  func(p *credentials.Profile) (string, error)
}

func (a planAction) symbol() string {
	switch a.verb {
	case verbCreate:
		return "+"
	case verbUpdate:
		return "~"
	case verbDelete:
		return "-"
	case verbReplace:
		return "±"
	}
	return "?"
}

// ---------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------

// Check loads authio.yaml, builds the plan, prints it, and exits 2 when
// there is drift — CI-friendly (0 = in sync, 1 = error, 2 = drift).
func Check(args []string) error {
	file, prune, profileName := applyFlags(args)
	p, _, err := loadProfile(profileName)
	if err != nil {
		return fmt.Errorf("no credentials — run `authio login` first: %w", err)
	}
	cfg, err := config.Load(file)
	if err != nil {
		return err
	}
	if cfg.Empty() {
		return fmt.Errorf("%s declares no managed resources — nothing to check", file)
	}
	actions, err := buildPlan(p, cfg, prune || cfg.Prune)
	if err != nil {
		return err
	}
	renderPlan(os.Stdout, p.ProjectID, actions)
	if len(actions) > 0 {
		os.Exit(2)
	}
	return nil
}

// Apply builds the same plan as Check and executes it action by action,
// stopping at the first failure (already-applied actions stay applied —
// re-running apply is safe because every action is idempotent by
// identity key).
func Apply(args []string) error {
	file, prune, profileName := applyFlags(args)
	p, _, err := loadProfile(profileName)
	if err != nil {
		return fmt.Errorf("no credentials — run `authio login` first: %w", err)
	}
	cfg, err := config.Load(file)
	if err != nil {
		return err
	}
	if cfg.Empty() {
		return fmt.Errorf("%s declares no managed resources — nothing to apply", file)
	}
	actions, err := buildPlan(p, cfg, prune || cfg.Prune)
	if err != nil {
		return err
	}
	renderPlan(os.Stdout, p.ProjectID, actions)
	if len(actions) == 0 {
		return nil
	}
	fmt.Println()
	for _, a := range actions {
		note, err := a.execute(p)
		if err != nil {
			return fmt.Errorf("%s %s %q: %w (earlier actions were applied; re-run apply after fixing)",
				a.verb, a.resource, a.name, err)
		}
		fmt.Printf("  %s %s %s ... done", a.symbol(), a.resource, a.name)
		if note != "" {
			fmt.Printf("  %s", note)
		}
		fmt.Println()
	}
	fmt.Printf("\nApplied %d change(s).\n", len(actions))
	return nil
}

func applyFlags(args []string) (file string, prune bool, profile string) {
	file = "authio.yaml"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f", "--file":
			if i+1 < len(args) {
				file = args[i+1]
				i++
			}
		case "--prune":
			prune = true
		}
	}
	return file, prune, resolveProfileName(args)
}

func renderPlan(w *os.File, projectID string, actions []planAction) {
	if len(actions) == 0 {
		fmt.Fprintf(w, "No changes. Live state for project %s matches the file.\n", projectID)
		return
	}
	fmt.Fprintf(w, "Plan for project %s:\n\n", projectID)
	var creates, updates, deletes, replaces int
	for _, a := range actions {
		fmt.Fprintf(w, "  %s %s %s", a.symbol(), a.resource, a.name)
		if a.detail != "" {
			fmt.Fprintf(w, "  (%s)", a.detail)
		}
		fmt.Fprintln(w)
		switch a.verb {
		case verbCreate:
			creates++
		case verbUpdate:
			updates++
		case verbDelete:
			deletes++
		case verbReplace:
			replaces++
		}
	}
	fmt.Fprintf(w, "\n%d to create, %d to update, %d to replace, %d to delete.\n",
		creates, updates, replaces, deletes)
}

// ---------------------------------------------------------------------
// Plan building
// ---------------------------------------------------------------------

func buildPlan(p *credentials.Profile, cfg *config.File, prune bool) ([]planAction, error) {
	var actions []planAction
	if len(cfg.RedirectURIs) > 0 || prune {
		a, err := planRedirectURIs(p, cfg, prune)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a...)
	}
	if len(cfg.Webhooks) > 0 || prune {
		a, err := planWebhooks(p, cfg, prune)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a...)
	}
	if cfg.RiskPolicy != nil {
		a, err := planRiskPolicy(p, cfg.RiskPolicy)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a...)
	}
	if len(cfg.SSOConnections) > 0 {
		a, err := planSSOConnections(p, cfg, prune)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a...)
	}
	return actions, nil
}

func apiError(res *apiResult, ctx string) error {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(res.body, &body)
	msg := body.Code
	if body.Message != "" {
		msg += ": " + body.Message
	}
	if msg == "" {
		msg = strings.TrimSpace(string(res.body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
	}
	return fmt.Errorf("%s -> HTTP %d %s", ctx, res.status, msg)
}

// ---- redirect URIs ---------------------------------------------------

type liveRedirectURI struct {
	ID   string `json:"id"`
	URI  string `json:"uri"`
	Kind string `json:"kind"`
}

func planRedirectURIs(p *credentials.Profile, cfg *config.File, prune bool) ([]planAction, error) {
	res, err := apiGet(p, "/v1/redirect-uris")
	if err != nil {
		return nil, err
	}
	if res.status != 200 {
		return nil, apiError(res, "list redirect URIs")
	}
	var live struct {
		Data []liveRedirectURI `json:"data"`
	}
	if err := json.Unmarshal(res.body, &live); err != nil {
		return nil, fmt.Errorf("list redirect URIs: %w", err)
	}
	liveByURI := map[string]liveRedirectURI{}
	for _, r := range live.Data {
		liveByURI[r.URI] = r
	}
	desired := map[string]bool{}
	var actions []planAction
	for _, want := range cfg.RedirectURIs {
		want := want
		desired[want.URI] = true
		kind := want.Kind
		if kind == "" {
			kind = "oauth_callback"
		}
		got, ok := liveByURI[want.URI]
		if ok && got.Kind == kind {
			continue
		}
		if ok {
			// Kind change: the API has no update — replace.
			gotID := got.ID
			actions = append(actions, planAction{
				verb: verbReplace, resource: "redirect_uri", name: want.URI,
				detail: fmt.Sprintf("kind %s -> %s", got.Kind, kind),
				execute: func(p *credentials.Profile) (string, error) {
					if res, err := apiDelete(p, "/v1/redirect-uris/"+gotID); err != nil {
						return "", err
					} else if res.status != 204 && res.status != 404 {
						return "", apiError(res, "delete redirect URI")
					}
					return "", createRedirectURI(p, want.URI, kind)
				},
			})
			continue
		}
		actions = append(actions, planAction{
			verb: verbCreate, resource: "redirect_uri", name: want.URI, detail: kind,
			execute: func(p *credentials.Profile) (string, error) {
				return "", createRedirectURI(p, want.URI, kind)
			},
		})
	}
	if prune {
		for _, got := range live.Data {
			if desired[got.URI] {
				continue
			}
			got := got
			actions = append(actions, planAction{
				verb: verbDelete, resource: "redirect_uri", name: got.URI, detail: "prune",
				execute: func(p *credentials.Profile) (string, error) {
					res, err := apiDelete(p, "/v1/redirect-uris/"+got.ID)
					if err != nil {
						return "", err
					}
					if res.status != 204 && res.status != 404 {
						return "", apiError(res, "delete redirect URI")
					}
					return "", nil
				},
			})
		}
	}
	return actions, nil
}

func createRedirectURI(p *credentials.Profile, uri, kind string) error {
	res, err := apiPost(p, "/v1/redirect-uris", map[string]string{"uri": uri, "kind": kind})
	if err != nil {
		return err
	}
	if res.status != 201 && res.status != 409 { // 409 = already exists, fine
		return apiError(res, "create redirect URI")
	}
	return nil
}

// ---- webhooks --------------------------------------------------------

type liveWebhook struct {
	ID             string   `json:"id"`
	URL            string   `json:"url"`
	Description    *string  `json:"description"`
	Events         []string `json:"events"`
	Status         string   `json:"status"`
	OrganizationID *string  `json:"organization_id"`
}

func planWebhooks(p *credentials.Profile, cfg *config.File, prune bool) ([]planAction, error) {
	res, err := apiGet(p, "/v1/webhooks")
	if err != nil {
		return nil, err
	}
	if res.status != 200 {
		return nil, apiError(res, "list webhooks")
	}
	var live []liveWebhook
	if err := json.Unmarshal(res.body, &live); err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	liveByURL := map[string]liveWebhook{}
	for _, w := range live {
		if w.Status == "revoked" {
			continue
		}
		liveByURL[w.URL] = w
	}
	desired := map[string]bool{}
	var actions []planAction
	for _, want := range cfg.Webhooks {
		want := want
		desired[want.URL] = true
		events := want.Events
		if len(events) == 0 {
			events = []string{"*"}
		}
		got, ok := liveByURL[want.URL]
		if ok && sameStringSet(got.Events, events) && derefStr(got.Description) == want.Description {
			continue
		}
		if ok {
			gotID := got.ID
			actions = append(actions, planAction{
				verb: verbReplace, resource: "webhook", name: want.URL,
				detail: "events/description changed; replace rotates the secret",
				execute: func(p *credentials.Profile) (string, error) {
					if res, err := apiDelete(p, "/v1/webhooks/"+gotID); err != nil {
						return "", err
					} else if res.status != 204 && res.status != 404 {
						return "", apiError(res, "revoke webhook")
					}
					return createWebhook(p, want, events)
				},
			})
			continue
		}
		actions = append(actions, planAction{
			verb: verbCreate, resource: "webhook", name: want.URL,
			detail: "events: " + strings.Join(events, ","),
			execute: func(p *credentials.Profile) (string, error) {
				return createWebhook(p, want, events)
			},
		})
	}
	if prune {
		for _, got := range liveByURL {
			if desired[got.URL] {
				continue
			}
			got := got
			actions = append(actions, planAction{
				verb: verbDelete, resource: "webhook", name: got.URL, detail: "prune (revoke)",
				execute: func(p *credentials.Profile) (string, error) {
					res, err := apiDelete(p, "/v1/webhooks/"+got.ID)
					if err != nil {
						return "", err
					}
					if res.status != 204 && res.status != 404 {
						return "", apiError(res, "revoke webhook")
					}
					return "", nil
				},
			})
		}
	}
	sortActions(actions)
	return actions, nil
}

// createWebhook POSTs the endpoint and surfaces the write-only secret
// exactly once, in the apply output — it is never persisted anywhere.
func createWebhook(p *credentials.Profile, want config.Webhook, events []string) (string, error) {
	body := map[string]any{"url": want.URL, "events": events}
	if want.Description != "" {
		body["description"] = want.Description
	}
	if want.OrganizationID != "" {
		body["organization_id"] = want.OrganizationID
	}
	res, err := apiPost(p, "/v1/webhooks", body)
	if err != nil {
		return "", err
	}
	if res.status != 201 {
		return "", apiError(res, "create webhook")
	}
	var created struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(res.body, &created)
	if created.Secret == "" {
		return "", nil
	}
	return fmt.Sprintf("secret: %s  (write-only — store it now, it is not retrievable later)", created.Secret), nil
}

// ---- risk policy -----------------------------------------------------

type liveRiskPolicy struct {
	ThresholdStepUp int            `json:"threshold_step_up"`
	ThresholdBlock  int            `json:"threshold_block"`
	SignalWeights   map[string]int `json:"signal_weights"`
	EnabledSignals  []string       `json:"enabled_signals"`
	Defaulted       bool           `json:"defaulted"`
}

func planRiskPolicy(p *credentials.Profile, want *config.RiskPolicy) ([]planAction, error) {
	res, err := apiGet(p, "/v1/risk/policy")
	if err != nil {
		return nil, err
	}
	if res.status != 200 {
		return nil, apiError(res, "get risk policy")
	}
	var live liveRiskPolicy
	if err := json.Unmarshal(res.body, &live); err != nil {
		return nil, fmt.Errorf("get risk policy: %w", err)
	}
	var diffs []string
	if live.ThresholdStepUp != want.ThresholdStepUp {
		diffs = append(diffs, fmt.Sprintf("threshold_step_up %d -> %d", live.ThresholdStepUp, want.ThresholdStepUp))
	}
	if live.ThresholdBlock != want.ThresholdBlock {
		diffs = append(diffs, fmt.Sprintf("threshold_block %d -> %d", live.ThresholdBlock, want.ThresholdBlock))
	}
	if !sameIntMap(live.SignalWeights, want.SignalWeights) {
		diffs = append(diffs, "signal_weights")
	}
	if !sameStringSet(live.EnabledSignals, want.EnabledSignals) {
		diffs = append(diffs, "enabled_signals")
	}
	if len(diffs) == 0 {
		return nil, nil
	}
	return []planAction{{
		verb: verbUpdate, resource: "risk_policy", name: "policy",
		detail: strings.Join(diffs, "; "),
		execute: func(p *credentials.Profile) (string, error) {
			res, err := apiPut(p, "/v1/risk/policy", map[string]any{
				"threshold_step_up": want.ThresholdStepUp,
				"threshold_block":   want.ThresholdBlock,
				"signal_weights":    orEmptyIntMap(want.SignalWeights),
				"enabled_signals":   orEmptyStrings(want.EnabledSignals),
			})
			if err != nil {
				return "", err
			}
			if res.status != 200 {
				return "", apiError(res, "put risk policy")
			}
			return "takes effect within 60s", nil
		},
	}}, nil
}

// ---- SSO connections -------------------------------------------------

type liveSSOConnection struct {
	ID              string            `json:"id"`
	OrganizationID  string            `json:"organization_id"`
	Protocol        string            `json:"protocol"`
	Status          string            `json:"status"`
	DisplayName     string            `json:"display_name"`
	ExternalID      *string           `json:"external_id"`
	AttributeMap    map[string]string `json:"attribute_map"`
	JITProvisioning bool              `json:"jit_provisioning"`
	DefaultRole     string            `json:"default_role"`
}

func planSSOConnections(p *credentials.Profile, cfg *config.File, prune bool) ([]planAction, error) {
	// Group desired connections per org — the API is org-scoped.
	byOrg := map[string][]config.SSOConnection{}
	for _, s := range cfg.SSOConnections {
		byOrg[s.OrganizationID] = append(byOrg[s.OrganizationID], s)
	}
	orgs := make([]string, 0, len(byOrg))
	for org := range byOrg {
		orgs = append(orgs, org)
	}
	sort.Strings(orgs)

	var actions []planAction
	for _, org := range orgs {
		org := org
		res, err := apiGet(p, "/v1/organizations/"+org+"/sso-connections")
		if err != nil {
			return nil, err
		}
		if res.status != 200 {
			return nil, apiError(res, "list SSO connections for "+org)
		}
		var live []liveSSOConnection
		if err := json.Unmarshal(res.body, &live); err != nil {
			return nil, fmt.Errorf("list SSO connections for %s: %w", org, err)
		}
		liveByExt := map[string]liveSSOConnection{}
		for _, l := range live {
			if l.ExternalID != nil && *l.ExternalID != "" {
				liveByExt[*l.ExternalID] = l
			}
		}
		desired := map[string]bool{}
		for _, want := range byOrg[org] {
			want := want
			desired[want.ExternalID] = true
			name := org + "/" + want.ExternalID
			got, ok := liveByExt[want.ExternalID]
			if !ok {
				actions = append(actions, planAction{
					verb: verbCreate, resource: "sso_connection", name: name,
					detail: want.Provider,
					execute: func(p *credentials.Profile) (string, error) {
						return "", createSSOConnection(p, org, want)
					},
				})
				continue
			}
			// Observable-field diff. The saml/oidc config blocks are
			// write-only on the list surface, so their drift is
			// undetectable here (documented limitation).
			var diffs []string
			patch := map[string]any{}
			if got.DisplayName != want.DisplayName {
				diffs = append(diffs, fmt.Sprintf("display_name %q -> %q", got.DisplayName, want.DisplayName))
				patch["display_name"] = want.DisplayName
			}
			if want.Status != "" && got.Status != want.Status {
				diffs = append(diffs, fmt.Sprintf("status %s -> %s", got.Status, want.Status))
				patch["status"] = want.Status
			}
			if want.AttributeMap != nil && !sameStringMap(got.AttributeMap, want.AttributeMap) {
				diffs = append(diffs, "attribute_map")
				patch["attribute_map"] = want.AttributeMap
			}
			if want.JITProvisioning != nil && got.JITProvisioning != *want.JITProvisioning {
				diffs = append(diffs, fmt.Sprintf("jit_provisioning %t -> %t", got.JITProvisioning, *want.JITProvisioning))
				patch["jit_provisioning"] = *want.JITProvisioning
			}
			if want.DefaultRole != "" && got.DefaultRole != want.DefaultRole {
				diffs = append(diffs, fmt.Sprintf("default_role %s -> %s", got.DefaultRole, want.DefaultRole))
				patch["default_role"] = want.DefaultRole
			}
			if len(diffs) == 0 {
				continue
			}
			gotID := got.ID
			actions = append(actions, planAction{
				verb: verbUpdate, resource: "sso_connection", name: name,
				detail: strings.Join(diffs, "; "),
				execute: func(p *credentials.Profile) (string, error) {
					res, err := apiPatch(p, "/v1/organizations/"+org+"/sso-connections/"+gotID, patch)
					if err != nil {
						return "", err
					}
					if res.status != 200 {
						return "", apiError(res, "update SSO connection")
					}
					return "", nil
				},
			})
		}
		if prune {
			for ext, got := range liveByExt {
				if desired[ext] {
					continue
				}
				got := got
				actions = append(actions, planAction{
					verb: verbDelete, resource: "sso_connection", name: org + "/" + ext, detail: "prune",
					execute: func(p *credentials.Profile) (string, error) {
						res, err := apiDelete(p, "/v1/organizations/"+org+"/sso-connections/"+got.ID)
						if err != nil {
							return "", err
						}
						if res.status != 200 && res.status != 204 && res.status != 404 {
							return "", apiError(res, "delete SSO connection")
						}
						return "", nil
					},
				})
			}
		}
	}
	sortActions(actions)
	return actions, nil
}

func createSSOConnection(p *credentials.Profile, org string, want config.SSOConnection) error {
	body := map[string]any{
		"provider":     want.Provider,
		"display_name": want.DisplayName,
		"external_id":  want.ExternalID,
	}
	if want.IdPProvider != "" {
		body["idp_provider"] = want.IdPProvider
	}
	if want.SAML != nil {
		body["saml"] = want.SAML
	}
	if want.OIDC != nil {
		body["oidc"] = want.OIDC
	}
	if want.AttributeMap != nil {
		body["attribute_map"] = want.AttributeMap
	}
	if want.JITProvisioning != nil {
		body["jit_provisioning"] = *want.JITProvisioning
	}
	if want.DefaultRole != "" {
		body["default_role"] = want.DefaultRole
	}
	if want.Status != "" {
		body["status"] = want.Status
	}
	res, err := apiPost(p, "/v1/organizations/"+org+"/sso-connections", body)
	if err != nil {
		return err
	}
	// 201 = created; 200 = idempotent hit on external_id (already exists).
	if res.status != 201 && res.status != 200 {
		return apiError(res, "create SSO connection")
	}
	return nil
}

// ---------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------

func sortActions(actions []planAction) {
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].resource != actions[j].resource {
			return actions[i].resource < actions[j].resource
		}
		return actions[i].name < actions[j].name
	})
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

func sameIntMap(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func orEmptyIntMap(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

func orEmptyStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
