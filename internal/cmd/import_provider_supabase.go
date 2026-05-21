package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// supabasePlanParser handles a JSON dump of auth.users (with optional
// auth.identities under .identities[]). The Supabase CLI's `db dump
// --schema auth` plus a small `pg_dump --table public.profiles` cover
// the auth side. Supabase orgs are *app-level*, not auth-level — the
// importer accepts an optional --orgs-table JSON file that maps
// app-defined org graph onto Authio.
//
// What's mapped:
//   - id                              -> external_id (supabase:<id>)
//   - email + email_confirmed_at      -> Authio user + verified
//   - raw_user_meta_data.full_name    -> Authio user.name
//   - raw_user_meta_data.avatar_url   -> Authio user.avatar_url
//   - raw_app_meta_data               -> Authio user.metadata.app
//   - raw_user_meta_data              -> Authio user.metadata.user
//   - identities[].provider/id        -> Authio identities (google/github/...)
//   - phone, phone_confirmed_at       -> metadata.phone
//
// What's dropped:
//   - encrypted_password (bcrypt) — flagged migration_pending_email
//   - sessions
type supabasePlanParser struct{}

func (supabasePlanParser) Name() string { return "supabase" }
func (supabasePlanParser) Help() string {
	return `supabase: a JSON dump of the auth.users table (with optional
auth.identities[] nested), produced by:
  supabase db dump --data-only --schema auth | jq '...'
or
  pg_dump --data-only --table=auth.users --format=p -F j ...

Each row looks like:
  {"id":"...","email":"...","email_confirmed_at":"2024-...",
   "raw_user_meta_data":{"full_name":"..."}, "raw_app_meta_data":{...},
   "identities":[{"provider":"google","id":"...","identity_data":{...}}]}

Without --orgs-table, all users land under one "default" org.`
}

type supabaseIdentity struct {
	ID           string         `json:"id"`
	Provider     string         `json:"provider"`
	IdentityData map[string]any `json:"identity_data"`
}

type supabaseRecord struct {
	ID                string             `json:"id"`
	Email             string             `json:"email"`
	EmailConfirmedAt  *string            `json:"email_confirmed_at"`
	Phone             string             `json:"phone"`
	PhoneConfirmedAt  *string            `json:"phone_confirmed_at"`
	BannedUntil       *string            `json:"banned_until"`
	RawUserMetaData   map[string]any     `json:"raw_user_meta_data"`
	RawAppMetaData    map[string]any     `json:"raw_app_meta_data"`
	Identities        []supabaseIdentity `json:"identities"`
}

type supabaseOrgsTable struct {
	Orgs []struct {
		ExternalID string `json:"external_id"`
		Name       string `json:"name"`
		Slug       string `json:"slug"`
		Domain     string `json:"domain"`
		Members    []struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"members"`
	} `json:"orgs"`
}

func (supabasePlanParser) ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error) {
	plan := &ImportPlan{Provider: "supabase"}
	users := newUserIndex(opts.MergeDuplicateEmails)

	// Default org (used unless --orgs-table is provided).
	defaultName := opts.DefaultOrgName
	if defaultName == "" {
		defaultName = "Default"
	}
	defaultExt := extID("supabase", "org:default")

	// Read the optional --orgs-table.
	var orgsTbl supabaseOrgsTable
	useOrgsTable := false
	if opts.OrgsTablePath != "" {
		f, err := os.Open(opts.OrgsTablePath)
		if err != nil {
			return nil, fmt.Errorf("open --orgs-table %s: %w", opts.OrgsTablePath, err)
		}
		defer f.Close()
		if err := json.NewDecoder(f).Decode(&orgsTbl); err != nil {
			return nil, fmt.Errorf("parse --orgs-table: %w", err)
		}
		useOrgsTable = true
		for i := range orgsTbl.Orgs {
			o := &orgsTbl.Orgs[i]
			slug := o.Slug
			if slug == "" {
				slug = slugify(o.Name)
			}
			plan.Orgs = append(plan.Orgs, OrgRecord{
				ExternalID: extID("supabase", "org:"+o.ExternalID),
				Name:       o.Name,
				Slug:       slug,
				Domain:     o.Domain,
			})
		}
	}
	if !useOrgsTable {
		plan.Orgs = append(plan.Orgs, OrgRecord{
			ExternalID: defaultExt,
			Name:       defaultName,
			Slug:       slugify(defaultName),
		})
	}

	// Track which Authio user IDs we created (by email) so we can wire
	// memberships in the orgs-table phase.
	emailToExt := map[string]string{}

	err := streamArrayOrNDJSON(ctx, r, "users", func(_ SourceUser) error { return nil },
		func(raw json.RawMessage) (SourceUser, bool) {
			var rec supabaseRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				return SourceUser{}, false
			}
			plan.Stats.SourceUsers++
			email := normEmail(rec.Email)
			if email == "" {
				plan.addWarning("supabase: skipped user %s — no email", rec.ID)
				return SourceUser{}, false
			}
			if rec.BannedUntil != nil && *rec.BannedUntil != "" {
				if t, err := time.Parse(time.RFC3339, *rec.BannedUntil); err == nil && t.After(time.Now().UTC()) {
					plan.addWarning("supabase: skipped banned user %s", rec.ID)
					return SourceUser{}, false
				}
			}

			verified := rec.EmailConfirmedAt != nil && *rec.EmailConfirmedAt != ""

			meta := map[string]any{}
			if len(rec.RawAppMetaData) > 0 {
				meta["app"] = rec.RawAppMetaData
			}
			if len(rec.RawUserMetaData) > 0 {
				meta["user"] = rec.RawUserMetaData
			}
			if rec.Phone != "" {
				meta["phone"] = rec.Phone
				if rec.PhoneConfirmedAt != nil && *rec.PhoneConfirmedAt != "" {
					meta["phone_verified"] = true
				}
			}

			name := ""
			avatar := ""
			if md := rec.RawUserMetaData; md != nil {
				name = fallbackName(strAny(md["full_name"]), strAny(md["name"]))
				avatar = strAny(md["avatar_url"])
			}

			ext := extID("supabase", rec.ID)
			users.upsert(UserRecord{
				ExternalID:            ext,
				Email:                 email,
				EmailVerified:         verified,
				Name:                  name,
				AvatarURL:             avatar,
				Metadata:              meta,
				MigrationPendingEmail: true,
				SourceExternalIDs:     []string{ext},
			})
			emailToExt[email] = ext

			for _, ident := range rec.Identities {
				kind := ""
				sub := ident.ID
				if sub == "" {
					sub = strAny(ident.IdentityData["sub"])
				}
				switch ident.Provider {
				case "email":
					continue
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
				default:
					if ident.Provider != "" {
						kind = "oauth_" + ident.Provider
					}
				}
				if kind == "" || sub == "" {
					continue
				}
				plan.Identities = append(plan.Identities, IdentityRecord{
					UserExternalID: ext,
					Kind:           kind,
					Subject:        sub,
				})
			}

			if !useOrgsTable {
				plan.Memberships = append(plan.Memberships, MembershipRecord{
					UserExternalID: ext,
					OrgExternalID:  defaultExt,
					Role:           "member",
					Status:         "active",
				})
			}
			return SourceUser{}, false
		},
	)
	if err != nil {
		return nil, err
	}

	if useOrgsTable {
		for _, o := range orgsTbl.Orgs {
			orgExt := extID("supabase", "org:"+o.ExternalID)
			for _, m := range o.Members {
				me := normEmail(m.Email)
				if me == "" {
					continue
				}
				userExt, ok := emailToExt[me]
				if !ok {
					plan.addWarning("supabase orgs-table: member %s for org %s not in user export", me, o.Name)
					continue
				}
				plan.Memberships = append(plan.Memberships, MembershipRecord{
					UserExternalID: userExt,
					OrgExternalID:  orgExt,
					Role:           mapRole(m.Role),
					Status:         "active",
				})
			}
		}
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	return plan, nil
}

func strAny(v any) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}
