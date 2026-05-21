package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// stytchLivePuller targets Stytch B2B (the only Stytch product with
// orgs+members; Consumer is a flat list and re-uses the same per-user
// search but no org-level fanout).
//
// Endpoints:
//   POST /v1/b2b/organizations/search                  body {limit, cursor}
//   POST /v1/b2b/organizations/{id}/members/search     body {limit, cursor}
//   GET  /v1/b2b/sso?organization_id={id}
//
// Auth: HTTP Basic with project_id:project_secret.
type stytchLivePuller struct{}

func (stytchLivePuller) Name() string { return "stytch" }

func (stytchLivePuller) PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error) {
	if creds.ProjectID == "" || creds.ProjectSecret == "" {
		return nil, fmt.Errorf("stytch: --stytch-project-id and --stytch-secret are required")
	}
	base := "https://api.stytch.com"
	if opts.BaseURLOverride != "" {
		base = strings.TrimRight(opts.BaseURLOverride, "/")
	}
	h := newLiveHTTP(opts, "stytch")
	progress := opts.ProgressFn
	if progress == nil {
		progress = func(string, int) {}
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(creds.ProjectID+":"+creds.ProjectSecret)) // AUTHIO_REDACT

	plan := &ImportPlan{Provider: "stytch"}
	users := newUserIndex(true)

	// ---- Organizations ----
	type stytchOrg struct {
		OrganizationID   string `json:"organization_id"`
		OrganizationName string `json:"organization_name"`
		OrganizationSlug string `json:"organization_slug"`
	}
	var orgs []stytchOrg
	cursor := ""
	pages := 0
	for {
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			break
		}
		body := map[string]any{"limit": 100}
		if cursor != "" {
			body["cursor"] = cursor
		}
		respBody, err := stytchPost(ctx, h, base+"/v1/b2b/organizations/search", auth, body)
		if err != nil {
			return nil, fmt.Errorf("stytch orgs: %w", err)
		}
		var wrap struct {
			Organizations  []stytchOrg `json:"organizations"`
			NextCursor     string      `json:"next_cursor"`
		}
		if err := json.Unmarshal(respBody, &wrap); err != nil {
			return nil, fmt.Errorf("stytch orgs decode: %w", err)
		}
		orgs = append(orgs, wrap.Organizations...)
		progress("orgs", len(orgs))
		if wrap.NextCursor == "" {
			break
		}
		cursor = wrap.NextCursor
		pages++
	}
	orgExtByID := map[string]string{}
	for _, o := range orgs {
		ext := extID("stytch", "org:"+o.OrganizationID)
		orgExtByID[o.OrganizationID] = ext
		plan.Orgs = append(plan.Orgs, OrgRecord{
			ExternalID: ext,
			Name:       o.OrganizationName,
			Slug:       slugify(firstNonEmpty(o.OrganizationSlug, o.OrganizationName)),
		})
	}

	// ---- Members per org ----
	type stytchMember struct {
		MemberID      string `json:"member_id"`
		EmailAddress  string `json:"email_address"`
		Name          string `json:"name"`
		Role          string `json:"role"`
		EmailVerified bool   `json:"email_address_verified"`
		Status        string `json:"status"`
	}
	memberCount := 0
	for _, o := range orgs {
		cursor := ""
		for {
			body := map[string]any{"limit": 100, "organization_id": o.OrganizationID}
			if cursor != "" {
				body["cursor"] = cursor
			}
			respBody, err := stytchPost(ctx, h, base+"/v1/b2b/organizations/"+o.OrganizationID+"/members/search", auth, body)
			if err != nil {
				plan.addWarning("stytch: org %s members: %v", o.OrganizationID, err)
				break
			}
			var wrap struct {
				Members    []stytchMember `json:"members"`
				NextCursor string         `json:"next_cursor"`
			}
			if err := json.Unmarshal(respBody, &wrap); err != nil {
				plan.addWarning("stytch: org %s members decode: %v", o.OrganizationID, err)
				break
			}
			for _, m := range wrap.Members {
				plan.Stats.SourceUsers++
				email := normEmail(m.EmailAddress)
				if email == "" {
					continue
				}
				users.upsert(UserRecord{
					ExternalID:            extID("stytch", m.MemberID),
					Email:                 email,
					EmailVerified:         m.EmailVerified,
					Name:                  m.Name,
					MigrationPendingEmail: true,
					SourceExternalIDs:     []string{extID("stytch", m.MemberID)},
				})
				plan.Memberships = append(plan.Memberships, MembershipRecord{
					UserExternalID: extID("stytch", m.MemberID),
					OrgExternalID:  orgExtByID[o.OrganizationID],
					Role:           mapRole(m.Role),
					Status:         firstNonEmpty(m.Status, "active"),
				})
				memberCount++
			}
			progress("users", memberCount)
			if wrap.NextCursor == "" {
				break
			}
			cursor = wrap.NextCursor
		}

		// ---- SSO per org ----
		ssoBody, err := stytchGet(ctx, h, base+"/v1/b2b/sso?organization_id="+o.OrganizationID, auth)
		if err == nil {
			var ssoWrap struct {
				SAMLConnections []struct {
					ID          string `json:"connection_id"`
					DisplayName string `json:"display_name"`
				} `json:"saml_connections"`
				OIDCConnections []struct {
					ID          string `json:"connection_id"`
					DisplayName string `json:"display_name"`
				} `json:"oidc_connections"`
			}
			if json.Unmarshal(ssoBody, &ssoWrap) == nil {
				for _, s := range ssoWrap.SAMLConnections {
					plan.SsoConnections = append(plan.SsoConnections, SsoConnectionRecord{
						OrgExternalID: orgExtByID[o.OrganizationID],
						Name:          s.DisplayName,
						Kind:          "saml",
						Metadata:      map[string]any{"stytch_connection_id": s.ID},
					})
				}
				for _, s := range ssoWrap.OIDCConnections {
					plan.SsoConnections = append(plan.SsoConnections, SsoConnectionRecord{
						OrgExternalID: orgExtByID[o.OrganizationID],
						Name:          s.DisplayName,
						Kind:          "oidc",
						Metadata:      map[string]any{"stytch_connection_id": s.ID},
					})
				}
			}
		}
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	progress("done", 0)
	return plan, nil
}

func stytchPost(ctx context.Context, h *liveHTTP, url, auth string, body any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth) // AUTHIO_REDACT
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, &statusErr{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	return b, nil
}

func stytchGet(ctx context.Context, h *liveHTTP, url, auth string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth) // AUTHIO_REDACT
	resp, err := h.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, &statusErr{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	return b, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
