package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// clerkLivePuller pulls users, organizations, and memberships from
// Clerk's Backend API. Reuses clerkPlanParser's role-mapping convention.
//
// Endpoints:
//   GET /v1/users?limit=500&offset=N
//   GET /v1/organizations?limit=100&offset=N
//   GET /v1/organizations/{id}/memberships?limit=100&offset=N
type clerkLivePuller struct{}

func (clerkLivePuller) Name() string { return "clerk" }

func (clerkLivePuller) PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error) {
	key := creds.SecretKey
	if key == "" {
		key = creds.Token
	}
	if key == "" {
		return nil, fmt.Errorf("clerk: missing secret_key (sk_live_…)")
	}
	base := "https://api.clerk.com"
	if opts.BaseURLOverride != "" {
		base = strings.TrimRight(opts.BaseURLOverride, "/")
	}
	h := newLiveHTTP(opts, "clerk")
	progress := opts.ProgressFn
	if progress == nil {
		progress = func(string, int) {}
	}

	plan := &ImportPlan{Provider: "clerk"}
	users := newUserIndex(true)
	userIDToEmail := map[string]string{}

	// ---- Users ----
	offset := 0
	pages := 0
	totalUsers := 0
	for {
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			plan.addWarning("clerk: hit --max-pages=%d on users", opts.MaxPages)
			break
		}
		url := fmt.Sprintf("%s/v1/users?limit=500&offset=%d", base, offset)
		body, err := bearerGet(ctx, h, url, key)
		if err != nil {
			return nil, fmt.Errorf("clerk users offset %d: %w", offset, err)
		}
		var rows []struct {
			ID             string `json:"id"`
			EmailAddresses []struct {
				EmailAddress string `json:"email_address"`
				Verification struct {
					Status string `json:"status"`
				} `json:"verification"`
			} `json:"email_addresses"`
			FirstName      string `json:"first_name"`
			LastName       string `json:"last_name"`
			ImageURL       string `json:"image_url"`
			ExternalAccts  []struct {
				Provider string `json:"provider"`
				Identity string `json:"provider_user_id"`
			} `json:"external_accounts"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			return nil, fmt.Errorf("clerk users decode: %w", err)
		}
		for _, r := range rows {
			plan.Stats.SourceUsers++
			if len(r.EmailAddresses) == 0 {
				continue
			}
			email := normEmail(r.EmailAddresses[0].EmailAddress)
			if email == "" {
				continue
			}
			verified := r.EmailAddresses[0].Verification.Status == "verified"
			name := strings.TrimSpace(strings.TrimSpace(r.FirstName) + " " + strings.TrimSpace(r.LastName))
			users.upsert(UserRecord{
				ExternalID:            extID("clerk", r.ID),
				Email:                 email,
				EmailVerified:         verified,
				Name:                  name,
				AvatarURL:             r.ImageURL,
				MigrationPendingEmail: true,
				SourceExternalIDs:     []string{extID("clerk", r.ID)},
			})
			userIDToEmail[r.ID] = email
			for _, ext := range r.ExternalAccts {
				kind := mapClerkProvider(ext.Provider)
				if kind == "" || ext.Identity == "" {
					continue
				}
				plan.Identities = append(plan.Identities, IdentityRecord{
					UserExternalID: extID("clerk", r.ID),
					Kind:           kind,
					Subject:        ext.Identity,
				})
			}
			totalUsers++
		}
		progress("users", totalUsers)
		if len(rows) < 500 {
			break
		}
		offset += 500
		pages++
	}
	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged

	// ---- Organizations ----
	offset = 0
	pages = 0
	totalOrgs := 0
	for {
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			break
		}
		url := fmt.Sprintf("%s/v1/organizations?limit=100&offset=%d", base, offset)
		body, err := bearerGet(ctx, h, url, key)
		if err != nil {
			return nil, fmt.Errorf("clerk organizations offset %d: %w", offset, err)
		}
		// Clerk wraps as {data:[…]} or returns a bare array depending on plan.
		var raw []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Slug     string `json:"slug"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			var wrap struct {
				Data []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Slug string `json:"slug"`
				} `json:"data"`
			}
			if err2 := json.Unmarshal(body, &wrap); err2 != nil {
				return nil, fmt.Errorf("clerk organizations decode: %w", err)
			}
			for _, o := range wrap.Data {
				raw = append(raw, struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Slug string `json:"slug"`
				}{o.ID, o.Name, o.Slug})
			}
		}
		for _, o := range raw {
			ext := extID("clerk", "org:"+o.ID)
			plan.Orgs = append(plan.Orgs, OrgRecord{
				ExternalID: ext,
				Name:       o.Name,
				Slug:       slugify(o.Slug),
			})
			totalOrgs++
			if err := clerkPullOrgMemberships(ctx, h, base, key, o.ID, ext, userIDToEmail, plan); err != nil {
				plan.addWarning("clerk: org %s memberships: %v", o.ID, err)
			}
		}
		progress("orgs", totalOrgs)
		if len(raw) < 100 {
			break
		}
		offset += 100
		pages++
	}
	progress("done", 0)
	return plan, nil
}

func clerkPullOrgMemberships(
	ctx context.Context,
	h *liveHTTP,
	base, key, orgID, orgExt string,
	userEmails map[string]string,
	plan *ImportPlan,
) error {
	offset := 0
	for {
		url := fmt.Sprintf("%s/v1/organizations/%s/memberships?limit=100&offset=%d", base, orgID, offset)
		body, err := bearerGet(ctx, h, url, key)
		if err != nil {
			return err
		}
		var rows []struct {
			Role      string `json:"role"`
			PublicUserData struct {
				UserID string `json:"user_id"`
			} `json:"public_user_data"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			var wrap struct {
				Data []struct {
					Role           string `json:"role"`
					PublicUserData struct {
						UserID string `json:"user_id"`
					} `json:"public_user_data"`
				} `json:"data"`
			}
			if err2 := json.Unmarshal(body, &wrap); err2 != nil {
				return err
			}
			for _, m := range wrap.Data {
				rows = append(rows, struct {
					Role           string `json:"role"`
					PublicUserData struct {
						UserID string `json:"user_id"`
					} `json:"public_user_data"`
				}{m.Role, m.PublicUserData})
			}
		}
		for _, m := range rows {
			plan.Memberships = append(plan.Memberships, MembershipRecord{
				UserExternalID: extID("clerk", m.PublicUserData.UserID),
				OrgExternalID:  orgExt,
				Role:           mapClerkRole(m.Role),
				Status:         "active",
			})
		}
		if len(rows) < 100 {
			break
		}
		offset += 100
	}
	return nil
}

func mapClerkProvider(p string) string {
	switch {
	case strings.HasPrefix(p, "oauth_google"):
		return "oauth_google"
	case strings.HasPrefix(p, "oauth_microsoft"):
		return "oauth_microsoft"
	case strings.HasPrefix(p, "oauth_github"):
		return "oauth_github"
	case strings.HasPrefix(p, "oauth_apple"):
		return "oauth_apple"
	case strings.HasPrefix(p, "oauth_"):
		return p
	}
	return ""
}

func mapClerkRole(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	switch r {
	case "admin", "org:admin":
		return "owner"
	case "basic_member", "org:basic_member", "member":
		return "member"
	default:
		return mapRole(r)
	}
}

func bearerGet(ctx context.Context, h *liveHTTP, url, token string) ([]byte, error) {
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
