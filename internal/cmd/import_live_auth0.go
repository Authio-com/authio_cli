package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// auth0LivePuller talks to the Auth0 Management API to pull users, orgs,
// memberships, roles, and identities, and assembles them into the same
// ImportPlan the file-based importer produces.
//
// Endpoints:
//   GET /api/v2/users?per_page=100&page=N&include_totals=true
//   GET /api/v2/organizations?per_page=100&page=N
//   GET /api/v2/organizations/{id}/members?per_page=100&page=N
//   GET /api/v2/organizations/{id}/members/{userId}/roles
//
// Reuses auth0PlanParser.identityKind for the OAuth provider mapping so
// file and live imports produce identical Identities arrays.
//
// AUTHIO_REDACT — the Bearer token from creds.Token is the high-risk
// secret. We pass it only to the auth0 host and never echo it.
type auth0LivePuller struct{}

func (auth0LivePuller) Name() string { return "auth0" }

func (auth0LivePuller) PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error) {
	domain := strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(creds.Domain, "https://"), "http://"), "/")
	if domain == "" {
		return nil, fmt.Errorf("auth0: --auth0-domain or credentials.domain is required")
	}
	if creds.Token == "" {
		return nil, fmt.Errorf("auth0: missing management API token")
	}
	base := "https://" + domain
	if opts.BaseURLOverride != "" {
		base = strings.TrimRight(opts.BaseURLOverride, "/")
	}
	h := newLiveHTTP(opts, "auth0")
	progress := opts.ProgressFn
	if progress == nil {
		progress = func(string, int) {}
	}

	plan := &ImportPlan{Provider: "auth0"}
	users := newUserIndex(true)
	orgs := map[string]*OrgRecord{}

	// ---- Users (paginated) ----
	page := 0
	totalUsers := 0
	for {
		if opts.MaxPages > 0 && page >= opts.MaxPages {
			plan.addWarning("auth0: hit --max-pages=%d on users", opts.MaxPages)
			break
		}
		url := fmt.Sprintf("%s/api/v2/users?per_page=100&page=%d&include_totals=true", base, page)
		body, err := auth0Get(ctx, h, url, creds.Token)
		if err != nil {
			return nil, fmt.Errorf("auth0 users page %d: %w", page, err)
		}
		var resp struct {
			Users  []auth0Record `json:"users"`
			Start  int           `json:"start"`
			Limit  int           `json:"limit"`
			Length int           `json:"length"`
			Total  int           `json:"total"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			// Some tenants disable include_totals. Fall back to a bare array.
			var bare []auth0Record
			if err2 := json.Unmarshal(body, &bare); err2 != nil {
				return nil, fmt.Errorf("auth0 users decode page %d: %w", page, err)
			}
			resp.Users = bare
			resp.Length = len(bare)
		}
		for _, rec := range resp.Users {
			plan.Stats.SourceUsers++
			if rec.Blocked || rec.Email == "" {
				plan.addWarning("auth0: skipped blocked or no-email user %s", rec.UserID)
				continue
			}
			email := normEmail(rec.Email)
			if email == "" {
				continue
			}
			name := strings.TrimSpace(rec.Name)
			if name == "" {
				name = strings.TrimSpace(rec.Nickname)
			}
			meta := map[string]any{}
			if len(rec.AppMetadata) > 0 {
				meta["app"] = rec.AppMetadata
			}
			if len(rec.UserMetadata) > 0 {
				meta["user"] = rec.UserMetadata
			}
			users.upsert(UserRecord{
				ExternalID:            extID("auth0", rec.UserID),
				Email:                 email,
				EmailVerified:         rec.EmailVerified,
				Name:                  name,
				AvatarURL:             rec.Picture,
				Metadata:              meta,
				MigrationPendingEmail: true,
				SourceExternalIDs:     []string{extID("auth0", rec.UserID)},
			})
			for _, ident := range rec.Identities {
				kind, sub := auth0IdentityKind(ident)
				if kind == "" || sub == "" {
					continue
				}
				plan.Identities = append(plan.Identities, IdentityRecord{
					UserExternalID: extID("auth0", rec.UserID),
					Kind:           kind,
					Subject:        sub,
					Metadata:       map[string]any{"connection": ident.Connection},
				})
			}
			totalUsers++
		}
		progress("users", totalUsers)
		if len(resp.Users) < 100 {
			break
		}
		page++
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged

	// ---- Organizations + memberships ----
	page = 0
	totalOrgs := 0
	for {
		if opts.MaxPages > 0 && page >= opts.MaxPages {
			plan.addWarning("auth0: hit --max-pages=%d on organizations", opts.MaxPages)
			break
		}
		url := fmt.Sprintf("%s/api/v2/organizations?per_page=100&page=%d", base, page)
		body, err := auth0Get(ctx, h, url, creds.Token)
		if err != nil {
			// Auth0 orgs is an optional feature; 404/403 means the tenant
			// didn't enable it. Silent skip + warning.
			if isStatusErr(err, http.StatusNotFound) || isStatusErr(err, http.StatusForbidden) {
				plan.addWarning("auth0: organizations API unavailable (tenant feature off); skipping org graph")
				break
			}
			return nil, fmt.Errorf("auth0 organizations page %d: %w", page, err)
		}
		var raw []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			// include_totals form.
			var wrap struct {
				Organizations []struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					DisplayName string `json:"display_name"`
				} `json:"organizations"`
			}
			if err2 := json.Unmarshal(body, &wrap); err2 != nil {
				return nil, fmt.Errorf("auth0 organizations decode: %w", err)
			}
			for _, o := range wrap.Organizations {
				raw = append(raw, struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					DisplayName string `json:"display_name"`
				}{o.ID, o.Name, o.DisplayName})
			}
		}
		for _, o := range raw {
			ext := extID("auth0", "org:"+o.ID)
			orgName := o.DisplayName
			if orgName == "" {
				orgName = o.Name
			}
			if _, ok := orgs[ext]; !ok {
				orgs[ext] = &OrgRecord{
					ExternalID: ext,
					Name:       orgName,
					Slug:       slugify(o.Name),
				}
				totalOrgs++
			}
			if err := auth0PullOrgMembers(ctx, h, base, creds.Token, o.ID, ext, plan); err != nil {
				plan.addWarning("auth0: org %s members: %v", o.ID, err)
			}
		}
		progress("orgs", totalOrgs)
		if len(raw) < 100 {
			break
		}
		page++
	}
	for _, o := range orgs {
		plan.Orgs = append(plan.Orgs, *o)
	}
	progress("done", 0)
	return plan, nil
}

// auth0PullOrgMembers paginates org members and their roles. Roles
// retrieval is per-user — for large orgs this is the slowest step. We
// accept that cost; the alternative (Auth0 batch role API) doesn't
// scope per-org.
func auth0PullOrgMembers(
	ctx context.Context,
	h *liveHTTP,
	base, token, orgID, orgExt string,
	plan *ImportPlan,
) error {
	page := 0
	for {
		url := fmt.Sprintf("%s/api/v2/organizations/%s/members?per_page=100&page=%d", base, orgID, page)
		body, err := auth0Get(ctx, h, url, token)
		if err != nil {
			return err
		}
		var members []struct {
			UserID string `json:"user_id"`
			Email  string `json:"email"`
			Name   string `json:"name"`
			Roles  []struct {
				Name string `json:"name"`
			} `json:"roles"`
		}
		if err := json.Unmarshal(body, &members); err != nil {
			// Wrapped form.
			var wrap struct {
				Members []struct {
					UserID string `json:"user_id"`
					Email  string `json:"email"`
				} `json:"members"`
			}
			if err2 := json.Unmarshal(body, &wrap); err2 != nil {
				return err
			}
			for _, m := range wrap.Members {
				members = append(members, struct {
					UserID string `json:"user_id"`
					Email  string `json:"email"`
					Name   string `json:"name"`
					Roles  []struct {
						Name string `json:"name"`
					} `json:"roles"`
				}{UserID: m.UserID, Email: m.Email})
			}
		}
		for _, m := range members {
			role := ""
			if len(m.Roles) > 0 {
				role = m.Roles[0].Name
			} else {
				// Fall back to GET /organizations/{id}/members/{uid}/roles
				rolesURL := fmt.Sprintf("%s/api/v2/organizations/%s/members/%s/roles", base, orgID, m.UserID)
				rb, err := auth0Get(ctx, h, rolesURL, token)
				if err == nil {
					var rr []struct {
						Name string `json:"name"`
					}
					if json.Unmarshal(rb, &rr) == nil && len(rr) > 0 {
						role = rr[0].Name
					}
				}
			}
			plan.Memberships = append(plan.Memberships, MembershipRecord{
				UserExternalID: extID("auth0", m.UserID),
				OrgExternalID:  orgExt,
				Role:           mapAuth0Role(role),
				Status:         "active",
			})
		}
		if len(members) < 100 {
			break
		}
		page++
	}
	return nil
}

func auth0Get(ctx context.Context, h *liveHTTP, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token) // AUTHIO_REDACT
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

type statusErr struct {
	code int
	body string
}

func (e *statusErr) Error() string {
	body := e.body
	if len(body) > 200 {
		body = body[:200] + "…"
	}
	return fmt.Sprintf("status %d: %s", e.code, body)
}

func isStatusErr(err error, code int) bool {
	se, ok := err.(*statusErr)
	return ok && se.code == code
}
