package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// descopeLivePuller talks to Descope's Management API.
//
// Endpoints:
//   GET  /v1/mgmt/tenant/all
//   POST /v1/mgmt/user/search           body {limit, page}
//   GET  /v1/mgmt/sso/settings/all
//
// Auth: Bearer {project_id}:{mgmt_key} (the Descope convention).
type descopeLivePuller struct{}

func (descopeLivePuller) Name() string { return "descope" }

func (descopeLivePuller) PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error) {
	if creds.ProjectID == "" || creds.MgmtKey == "" {
		return nil, fmt.Errorf("descope: --descope-project-id and --live-token (mgmt key) are required")
	}
	base := "https://api.descope.com"
	if opts.BaseURLOverride != "" {
		base = strings.TrimRight(opts.BaseURLOverride, "/")
	}
	h := newLiveHTTP(opts, "descope")
	auth := "Bearer " + creds.ProjectID + ":" + creds.MgmtKey // AUTHIO_REDACT
	progress := opts.ProgressFn
	if progress == nil {
		progress = func(string, int) {}
	}

	plan := &ImportPlan{Provider: "descope"}
	users := newUserIndex(true)

	// ---- Tenants ----
	body, err := descopeGet(ctx, h, base+"/v1/mgmt/tenant/all", auth)
	if err != nil {
		return nil, fmt.Errorf("descope tenants: %w", err)
	}
	var tenWrap struct {
		Tenants []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"tenants"`
	}
	if err := json.Unmarshal(body, &tenWrap); err != nil {
		return nil, fmt.Errorf("descope tenants decode: %w", err)
	}
	orgExtByTenant := map[string]string{}
	for _, t := range tenWrap.Tenants {
		ext := extID("descope", "tenant:"+t.ID)
		orgExtByTenant[t.ID] = ext
		plan.Orgs = append(plan.Orgs, OrgRecord{
			ExternalID: ext,
			Name:       t.Name,
			Slug:       slugify(t.Name),
		})
	}
	progress("orgs", len(plan.Orgs))

	// ---- Users ----
	page := 0
	totalUsers := 0
	for {
		if opts.MaxPages > 0 && page >= opts.MaxPages {
			break
		}
		body, err := descopePost(ctx, h, base+"/v1/mgmt/user/search", auth, map[string]any{"limit": 100, "page": page})
		if err != nil {
			return nil, fmt.Errorf("descope users page %d: %w", page, err)
		}
		var uwrap struct {
			Users []struct {
				UserID    string   `json:"userId"`
				Email     string   `json:"email"`
				Name      string   `json:"name"`
				Status    string   `json:"status"`
				Verified  bool     `json:"verifiedEmail"`
				TenantIDs []string `json:"tenantIds"`
				Tenants   []struct {
					TenantID string   `json:"tenantId"`
					Roles    []string `json:"roleNames"`
				} `json:"userTenants"`
			} `json:"users"`
		}
		if err := json.Unmarshal(body, &uwrap); err != nil {
			return nil, fmt.Errorf("descope users decode: %w", err)
		}
		for _, u := range uwrap.Users {
			plan.Stats.SourceUsers++
			if u.Status == "disabled" {
				continue
			}
			email := normEmail(u.Email)
			if email == "" {
				continue
			}
			users.upsert(UserRecord{
				ExternalID:            extID("descope", u.UserID),
				Email:                 email,
				EmailVerified:         u.Verified,
				Name:                  u.Name,
				MigrationPendingEmail: true,
				SourceExternalIDs:     []string{extID("descope", u.UserID)},
			})
			seenTenant := map[string]bool{}
			for _, ut := range u.Tenants {
				orgExt := orgExtByTenant[ut.TenantID]
				if orgExt == "" {
					continue
				}
				role := ""
				if len(ut.Roles) > 0 {
					role = ut.Roles[0]
				}
				plan.Memberships = append(plan.Memberships, MembershipRecord{
					UserExternalID: extID("descope", u.UserID),
					OrgExternalID:  orgExt,
					Role:           mapRole(role),
					Status:         "active",
				})
				seenTenant[ut.TenantID] = true
			}
			for _, tid := range u.TenantIDs {
				if seenTenant[tid] {
					continue
				}
				orgExt := orgExtByTenant[tid]
				if orgExt == "" {
					continue
				}
				plan.Memberships = append(plan.Memberships, MembershipRecord{
					UserExternalID: extID("descope", u.UserID),
					OrgExternalID:  orgExt,
					Role:           "member",
					Status:         "active",
				})
			}
			totalUsers++
		}
		progress("users", totalUsers)
		if len(uwrap.Users) < 100 {
			break
		}
		page++
	}
	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged

	// ---- SSO ----
	if body, err := descopeGet(ctx, h, base+"/v1/mgmt/sso/settings/all", auth); err == nil {
		var ssoWrap struct {
			SSOSettings []struct {
				TenantID string `json:"tenantId"`
				IDPMetadata struct {
					EntityID    string `json:"entityId"`
					DisplayName string `json:"displayName"`
				} `json:"idpMetadata"`
			} `json:"ssoSettings"`
		}
		if json.Unmarshal(body, &ssoWrap) == nil {
			for _, s := range ssoWrap.SSOSettings {
				orgExt := orgExtByTenant[s.TenantID]
				if orgExt == "" {
					continue
				}
				name := s.IDPMetadata.DisplayName
				if name == "" {
					name = s.IDPMetadata.EntityID
				}
				if name == "" {
					name = "SAML"
				}
				plan.SsoConnections = append(plan.SsoConnections, SsoConnectionRecord{
					OrgExternalID: orgExt,
					Name:          name,
					Kind:          "saml",
					Metadata:      map[string]any{"descope_tenant_id": s.TenantID},
				})
			}
		}
	}
	progress("done", 0)
	return plan, nil
}

func descopeGet(ctx context.Context, h *liveHTTP, url, auth string) ([]byte, error) {
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

func descopePost(ctx context.Context, h *liveHTTP, url, auth string, body any) ([]byte, error) {
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
