package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// PlanRunner executes a parsed ImportPlan against the Authio management-
// API. It is idempotent on every record: users on (project_id, email),
// orgs on (project_id, slug), memberships on (project_id, user_id, org_id),
// scim directories on (project_id, organization_id).
//
// The runner emits a structured per-record progress event when EmitJSON
// is true (used by the dashboard wizard). When false, it prints human-
// readable lines suitable for terminal use.
type PlanRunner struct {
	APIURL   string
	APIKey   string
	HTTP     *http.Client
	Out      io.Writer // progress sink; defaults to os.Stdout
	EmitJSON bool      // emit NDJSON events instead of human lines
	DryRun   bool
	// ExtraHeaders are merged into every outbound request. Used by the
	// migrate worker to send X-Authio-Worker + X-Authio-Project-Id so
	// the management-api accepts the call without a real API key.
	ExtraHeaders map[string]string
	// TargetOrganizationID pins memberships to an existing Authio org.
	TargetOrganizationID string
	// RecordErrors collects per-record failures for the dashboard.
	RecordErrors []RecordError
}

// RecordError is one failed/skipped import row surfaced to the wizard.
type RecordError struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
	Msg  string `json:"msg"`
}

// Run applies the plan and returns the final stats. The plan's Stats
// fields are updated in place.
func (p *PlanRunner) Run(ctx context.Context, plan *ImportPlan) (PlanStats, error) {
	if plan == nil {
		return PlanStats{}, errors.New("nil plan")
	}
	if !p.DryRun {
		if p.APIURL == "" {
			return PlanStats{}, errors.New("PlanRunner.APIURL is required")
		}
		if p.APIKey == "" {
			return PlanStats{}, errors.New("PlanRunner.APIKey is required")
		}
	}
	if p.HTTP == nil {
		p.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if p.Out == nil {
		p.Out = os.Stdout
	}

	stats := plan.Stats
	p.emit(map[string]any{"event": "begin", "provider": plan.Provider, "users": len(plan.Users), "orgs": len(plan.Orgs), "memberships": len(plan.Memberships)})

	// =====================================================
	// 1) Orgs first — we need orgID for memberships + SCIM.
	// =====================================================
	orgIDByExt := map[string]string{}
	if p.TargetOrganizationID != "" {
		if p.DryRun {
			orgIDByExt[TargetOrgExternalID] = p.TargetOrganizationID
		} else if err := p.assertTargetOrg(ctx, p.TargetOrganizationID); err != nil {
			return stats, err
		} else {
			orgIDByExt[TargetOrgExternalID] = p.TargetOrganizationID
			p.progress("org", TargetOrgExternalID, "using existing "+p.TargetOrganizationID)
		}
	}
	for _, o := range plan.Orgs {
		if p.DryRun {
			stats.OrgsCreated++
			orgIDByExt[o.ExternalID] = "(dry-run:" + o.Slug + ")"
			p.progress("org", o.ExternalID, "dry-run")
			continue
		}
		id, created, err := p.upsertOrg(ctx, o)
		if err != nil {
			stats.Errored++
			p.progress("org", o.ExternalID, "error: "+err.Error())
			continue
		}
		orgIDByExt[o.ExternalID] = id
		if created {
			stats.OrgsCreated++
			p.progress("org", o.ExternalID, "created "+id)
		} else {
			stats.OrgsExisted++
			p.progress("org", o.ExternalID, "existed "+id)
		}
	}

	// =====================================================
	// 2) Users — upsert by email.
	// =====================================================
	userIDByExt := map[string]string{}
	for _, u := range plan.Users {
		if p.DryRun {
			stats.UsersCreated++
			placeholder := "(dry-run:" + u.Email + ")"
			userIDByExt[u.ExternalID] = placeholder
			for _, src := range u.SourceExternalIDs {
				userIDByExt[src] = placeholder
			}
			p.progress("user", u.Email, "dry-run")
			continue
		}
		id, existed, err := p.upsertUser(ctx, u)
		if err != nil {
			stats.Errored++
			p.progress("user", u.Email, "error: "+err.Error())
			continue
		}
		userIDByExt[u.ExternalID] = id
		// Map every source external_id to the same Authio user (merge support).
		for _, src := range u.SourceExternalIDs {
			userIDByExt[src] = id
		}
		if existed {
			stats.UsersExisted++
			p.progress("user", u.Email, "existed "+id)
		} else {
			stats.UsersCreated++
			p.progress("user", u.Email, "created "+id)
		}
	}

	// =====================================================
	// 3) Memberships.
	// =====================================================
	for _, m := range plan.Memberships {
		userID := userIDByExt[m.UserExternalID]
		orgID := orgIDByExt[m.OrgExternalID]
		if userID == "" || orgID == "" {
			stats.Errored++
			p.progress("membership", m.UserExternalID+"@"+m.OrgExternalID, "skip — missing user or org")
			continue
		}
		if p.DryRun {
			stats.MembershipsCreated++
			p.progress("membership", m.UserExternalID+"@"+m.OrgExternalID, "dry-run")
			continue
		}
		if err := p.addMembership(ctx, orgID, userID, m.Role, m.Status); err != nil {
			stats.Errored++
			p.progress("membership", m.UserExternalID+"@"+m.OrgExternalID, "error: "+err.Error())
			continue
		}
		stats.MembershipsCreated++
		p.progress("membership", m.UserExternalID+"@"+m.OrgExternalID, "ok")
	}

	// =====================================================
	// 4) SCIM directories (one per org).
	// =====================================================
	for _, d := range plan.ScimDirectories {
		orgID := orgIDByExt[d.OrgExternalID]
		if orgID == "" {
			stats.Errored++
			p.progress("scim", d.OrgExternalID, "skip — missing org")
			continue
		}
		if p.DryRun {
			stats.ScimDirectoriesCreated++
			p.progress("scim", d.OrgExternalID, "dry-run")
			continue
		}
		if err := p.createScimDirectory(ctx, orgID, d.Name, d.OrgExternalID+":scim"); err != nil {
			stats.Errored++
			p.progress("scim", d.OrgExternalID, "error: "+err.Error())
			continue
		}
		stats.ScimDirectoriesCreated++
		p.progress("scim", d.OrgExternalID, "ok")
	}

	// =====================================================
	// 5) Identities — write each link via the new
	//    POST /v1/users/{userId}/identities endpoint.
	// =====================================================
	for _, ident := range plan.Identities {
		userID := userIDByExt[ident.UserExternalID]
		if userID == "" {
			stats.Errored++
			p.progress("identity", ident.UserExternalID+"/"+ident.Kind, "skip — missing user")
			continue
		}
		if p.DryRun {
			stats.IdentitiesCreated++
			p.progress("identity", ident.UserExternalID+"/"+ident.Kind, "dry-run")
			continue
		}
		if err := p.createIdentity(ctx, userID, ident); err != nil {
			stats.Errored++
			p.progress("identity", ident.UserExternalID+"/"+ident.Kind, "error: "+err.Error())
			continue
		}
		stats.IdentitiesCreated++
		p.progress("identity", ident.UserExternalID+"/"+ident.Kind, "ok")
	}

	// =====================================================
	// 6) SSO connections — POST /v1/organizations/{orgId}/sso-connections
	//    per record. The route normalizes saml|oidc to the underlying
	//    protocol column. We don't ship raw SAML certs / OIDC secrets
	//    from the importer (the source provider holds them); the
	//    operator wires those in the dashboard SSO config step. We do
	//    create the row in `pending` status so it shows up in the
	//    dashboard for completion.
	// =====================================================
	for _, s := range plan.SsoConnections {
		orgID := orgIDByExt[s.OrgExternalID]
		if orgID == "" {
			stats.Errored++
			p.progress("sso", s.OrgExternalID+"/"+s.Name, "skip — missing org")
			continue
		}
		if p.DryRun {
			stats.SsoConnectionsCreated++
			p.progress("sso", s.OrgExternalID+"/"+s.Name, "dry-run")
			continue
		}
		if err := p.createSsoConnection(ctx, orgID, s); err != nil {
			stats.Errored++
			p.progress("sso", s.OrgExternalID+"/"+s.Name, "error: "+err.Error())
			continue
		}
		stats.SsoConnectionsCreated++
		p.progress("sso", s.OrgExternalID+"/"+s.Name, "ok")
	}

	plan.Stats = stats
	p.emit(map[string]any{"event": "done", "stats": stats, "warnings": plan.Warnings})
	return stats, nil
}

// ----- helpers -----

func (p *PlanRunner) emit(payload map[string]any) {
	if p.EmitJSON {
		b, _ := json.Marshal(payload)
		fmt.Fprintln(p.Out, string(b))
		return
	}
	if ev, _ := payload["event"].(string); ev == "begin" {
		fmt.Fprintf(p.Out, "  begin %v — %v users, %v orgs, %v memberships\n",
			payload["provider"], payload["users"], payload["orgs"], payload["memberships"])
	} else if ev == "done" {
		stats := payload["stats"].(PlanStats)
		fmt.Fprintf(p.Out, "  done. users(created=%d existed=%d) orgs(created=%d existed=%d) memberships=%d identities=%d sso=%d scim=%d warnings=%d errored=%d\n",
			stats.UsersCreated, stats.UsersExisted, stats.OrgsCreated, stats.OrgsExisted,
			stats.MembershipsCreated, stats.IdentitiesCreated, stats.SsoConnectionsCreated,
			stats.ScimDirectoriesCreated, stats.Warnings, stats.Errored)
	}
}

func (p *PlanRunner) progress(kind, key, msg string) {
	if strings.HasPrefix(msg, "error:") || strings.HasPrefix(msg, "skip —") {
		p.RecordErrors = append(p.RecordErrors, RecordError{Kind: kind, Key: key, Msg: msg})
	}
	if p.EmitJSON {
		b, _ := json.Marshal(map[string]any{"event": "progress", "kind": kind, "key": key, "msg": msg})
		fmt.Fprintln(p.Out, string(b))
		return
	}
	fmt.Fprintf(p.Out, "    %-10s %-40s %s\n", kind, truncate(key, 40), msg)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func (p *PlanRunner) doJSON(ctx context.Context, method, path string, body any) (*http.Response, []byte, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.APIURL+path, reader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("User-Agent", "authio-cli-import/0.1")
	for k, v := range p.ExtraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, raw, nil
}

func (p *PlanRunner) assertTargetOrg(ctx context.Context, orgID string) error {
	path := fmt.Sprintf("/v1/organizations/%s", orgID)
	resp, raw, err := p.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("target organization %s not found: %d %s", orgID, resp.StatusCode, strings.TrimSpace(string(raw)))
}

func (p *PlanRunner) upsertOrg(ctx context.Context, o OrgRecord) (string, bool, error) {
	resp, raw, err := p.doJSON(ctx, http.MethodPost, "/v1/organizations", map[string]any{
		"name":   o.Name,
		"slug":   o.Slug,
		"domain": o.Domain,
	})
	if err != nil {
		return "", false, err
	}
	switch resp.StatusCode {
	case http.StatusCreated:
		var r struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &r)
		return r.ID, true, nil
	case http.StatusConflict:
		// Look up by slug.
		listResp, listRaw, err := p.doJSON(ctx, http.MethodGet, "/v1/organizations", nil)
		if err != nil {
			return "", false, err
		}
		if listResp.StatusCode != 200 {
			return "", false, fmt.Errorf("list orgs: %d %s", listResp.StatusCode, string(listRaw))
		}
		var rows []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		}
		if err := json.Unmarshal(listRaw, &rows); err != nil {
			return "", false, err
		}
		for _, r := range rows {
			if r.Slug == o.Slug {
				return r.ID, false, nil
			}
		}
		return "", false, fmt.Errorf("org slug %q reported conflict but not in list", o.Slug)
	default:
		return "", false, fmt.Errorf("create org: %d %s", resp.StatusCode, string(raw))
	}
}

func (p *PlanRunner) upsertUser(ctx context.Context, u UserRecord) (string, bool, error) {
	resp, raw, err := p.doJSON(ctx, http.MethodPost, "/v1/users", map[string]any{
		"email":          u.Email,
		"name":           u.Name,
		"email_verified": u.EmailVerified,
	})
	if err != nil {
		return "", false, err
	}
	switch resp.StatusCode {
	case http.StatusCreated:
		var r struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &r)
		return r.ID, false, nil
	case http.StatusOK:
		var r struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &r)
		return r.ID, true, nil
	default:
		return "", false, fmt.Errorf("create user: %d %s", resp.StatusCode, string(raw))
	}
}

func (p *PlanRunner) addMembership(ctx context.Context, orgID, userID, role, status string) error {
	if role == "" {
		role = "member"
	}
	if status == "" {
		status = "active"
	}
	path := fmt.Sprintf("/v1/organizations/%s/memberships", orgID)
	resp, raw, err := p.doJSON(ctx, http.MethodPost, path, map[string]any{
		"user_id": userID,
		"role":    role,
		"status":  status,
	})
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	// ON CONFLICT DO NOTHING means an idempotent re-add still returns 201 with
	// the existing row — anything else is a real failure.
	return fmt.Errorf("add membership: %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}

func (p *PlanRunner) createScimDirectory(ctx context.Context, orgID, name, externalID string) error {
	path := fmt.Sprintf("/v1/organizations/%s/scim-directories", orgID)
	body := map[string]any{"name": name}
	if externalID != "" {
		body["external_id"] = externalID
	}
	resp, raw, err := p.doJSON(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		// 409 == already exists for this org (UNIQUE constraint). Idempotent OK.
		return nil
	}
	return fmt.Errorf("create scim directory: %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}

// createIdentity POSTs one identity link. The management-API upserts on
// (project_id, kind, subject), so a re-run is idempotent — both the
// initial creation and the no-op replay return 2xx.
func (p *PlanRunner) createIdentity(ctx context.Context, userID string, ident IdentityRecord) error {
	path := fmt.Sprintf("/v1/users/%s/identities", userID)
	body := map[string]any{
		"provider":    ident.Kind,
		"subject":     ident.Subject,
		"external_id": ident.UserExternalID + ":" + ident.Subject,
	}
	if len(ident.Metadata) > 0 {
		body["raw"] = ident.Metadata
	}
	resp, raw, err := p.doJSON(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("create identity: %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}

// createSsoConnection POSTs one SSO record. We always seed it in `pending`
// status — the operator is expected to finish configuration in the
// dashboard (paste cert, save). external_id makes replays idempotent.
func (p *PlanRunner) createSsoConnection(ctx context.Context, orgID string, s SsoConnectionRecord) error {
	path := fmt.Sprintf("/v1/organizations/%s/sso-connections", orgID)
	protocol := strings.ToLower(s.Kind)
	if protocol != "saml" && protocol != "oidc" {
		// Provider parsers should normalize to saml|oidc; if a custom one
		// slipped through, default to saml (the more common case).
		protocol = "saml"
	}
	body := map[string]any{
		"provider":     protocol,
		"display_name": s.Name,
		"external_id":  s.OrgExternalID + ":" + s.Name,
		"status":       "pending",
	}
	if len(s.Metadata) > 0 {
		body["idp_provider"] = guessIdpProvider(s.Metadata)
	}
	resp, raw, err := p.doJSON(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		// 409 happens when the per-protocol uniqueness collides on a re-run
		// without a matching external_id — treat as idempotent OK.
		return nil
	}
	return fmt.Errorf("create sso connection: %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}

// guessIdpProvider picks a brand hint out of provider-specific metadata
// keys. The management-API stores it on `provider` (free-form text) and
// the dashboard uses it for the IdP-brand logo.
func guessIdpProvider(meta map[string]any) string {
	for _, k := range []string{"idp_provider", "workos_connection_type", "okta", "auth0_connection"} {
		if v, ok := meta[k].(string); ok && v != "" {
			low := strings.ToLower(v)
			switch {
			case strings.Contains(low, "okta"):
				return "okta"
			case strings.Contains(low, "azure") || strings.Contains(low, "entra"):
				return "entra"
			case strings.Contains(low, "google"):
				return "google_workspace"
			case strings.Contains(low, "ping"):
				return "ping"
			case strings.Contains(low, "onelogin"):
				return "onelogin"
			case strings.Contains(low, "jumpcloud"):
				return "jumpcloud"
			case strings.Contains(low, "adfs"):
				return "adfs"
			}
			return low
		}
	}
	return "generic_saml"
}
