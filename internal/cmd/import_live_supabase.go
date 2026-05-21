package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// supabaseLivePuller uses the Supabase platform API (api.supabase.com).
// This API is the operator-facing one; the per-instance auth.users
// table is reachable only via the project's own service-role key
// (which is per-project, not portable). The platform API takes a
// Personal Access Token (PAT) + project ref and returns user rows.
//
// Endpoint:
//   GET https://api.supabase.com/v1/projects/{ref}/users?limit=...&offset=...
//
// Auth: Bearer PAT.
type supabaseLivePuller struct{}

func (supabaseLivePuller) Name() string { return "supabase" }

func (supabaseLivePuller) PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error) {
	pat := creds.PAT
	if pat == "" {
		pat = creds.Token
	}
	if pat == "" {
		return nil, fmt.Errorf("supabase: missing PAT (Personal Access Token)")
	}
	ref := creds.ProjectRef
	if ref == "" {
		return nil, fmt.Errorf("supabase: --supabase-ref or credentials.project_ref is required")
	}
	base := "https://api.supabase.com"
	if opts.BaseURLOverride != "" {
		base = strings.TrimRight(opts.BaseURLOverride, "/")
	}
	h := newLiveHTTP(opts, "supabase")
	progress := opts.ProgressFn
	if progress == nil {
		progress = func(string, int) {}
	}

	plan := &ImportPlan{Provider: "supabase"}
	users := newUserIndex(true)

	offset := 0
	pages := 0
	totalUsers := 0
	for {
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			break
		}
		url := fmt.Sprintf("%s/v1/projects/%s/users?limit=100&offset=%d", base, ref, offset)
		body, err := bearerGet(ctx, h, url, pat)
		if err != nil {
			return nil, fmt.Errorf("supabase users offset %d: %w", offset, err)
		}
		// Supabase returns either a bare array or {users:[…]}.
		var rows []map[string]any
		if err := json.Unmarshal(body, &rows); err != nil {
			var wrap struct {
				Users []map[string]any `json:"users"`
			}
			if err2 := json.Unmarshal(body, &wrap); err2 != nil {
				return nil, fmt.Errorf("supabase users decode: %w", err)
			}
			rows = wrap.Users
		}
		for _, r := range rows {
			plan.Stats.SourceUsers++
			id, _ := r["id"].(string)
			email, _ := r["email"].(string)
			email = normEmail(email)
			if id == "" || email == "" {
				continue
			}
			verified := r["email_confirmed_at"] != nil
			users.upsert(UserRecord{
				ExternalID:            extID("supabase", id),
				Email:                 email,
				EmailVerified:         verified,
				MigrationPendingEmail: true,
				SourceExternalIDs:     []string{extID("supabase", id)},
			})
			if idents, ok := r["identities"].([]any); ok {
				for _, ig := range idents {
					im, ok := ig.(map[string]any)
					if !ok {
						continue
					}
					prov, _ := im["provider"].(string)
					sub := ""
					if id2, ok := im["id"].(string); ok {
						sub = id2
					}
					kind := ""
					switch strings.ToLower(prov) {
					case "google":
						kind = "oauth_google"
					case "github":
						kind = "oauth_github"
					case "apple":
						kind = "oauth_apple"
					case "azure", "microsoft":
						kind = "oauth_microsoft"
					case "facebook":
						kind = "oauth_facebook"
					}
					if kind == "" || sub == "" {
						continue
					}
					plan.Identities = append(plan.Identities, IdentityRecord{
						UserExternalID: extID("supabase", id),
						Kind:           kind,
						Subject:        sub,
					})
				}
			}
			totalUsers++
		}
		progress("users", totalUsers)
		if len(rows) < 100 {
			break
		}
		offset += 100
		pages++
	}
	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged

	// Supabase has no native multi-org concept. Fall through to one
	// "Default" org so users have somewhere to land.
	defaultExt := extID("supabase", "org:default")
	plan.Orgs = append(plan.Orgs, OrgRecord{
		ExternalID: defaultExt,
		Name:       "Default",
		Slug:       "default",
	})
	for _, u := range plan.Users {
		plan.Memberships = append(plan.Memberships, MembershipRecord{
			UserExternalID: u.ExternalID,
			OrgExternalID:  defaultExt,
			Role:           "member",
			Status:         "active",
		})
	}
	progress("done", 0)
	return plan, nil
}
