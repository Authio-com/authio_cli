package cmd

import (
	"context"
	"encoding/json"
	"io"
	"strings"
)

// clerkPlanParser handles Clerk Backend-API user exports.
//
// What's mapped:
//   - id                                -> external_id (clerk:<id>)
//   - email_addresses[].email_address    -> Authio user.email (primary first)
//   - phone_numbers[].phone_number       -> Authio user.metadata.phones[]
//   - first_name + last_name / username  -> Authio user.name
//   - image_url                          -> Authio user.avatar_url
//   - external_accounts[].provider       -> Authio identities
//   - organization_memberships[]         -> Authio orgs + memberships (1:1)
//   - public_metadata / private_metadata -> Authio user.metadata.public/private
//
// What's dropped:
//   - password_hash (bcrypt)             -> dropped; user flagged for
//                                           migration-pending email.
//   - totp_secret / backup_codes         -> mfa_enrolled flag preserved.
//   - sessions                           -> users re-auth on next visit.
type clerkPlanParser struct{}

func (clerkPlanParser) Name() string { return "clerk" }
func (clerkPlanParser) Help() string {
	return `clerk: a JSON array (or NDJSON) of Clerk Backend-API user objects from
  curl https://api.clerk.com/v1/users?limit=500 -H "Authorization: Bearer sk_live_..."

Each row has email_addresses[], organization_memberships[], and
external_accounts[]. Clerk's multi-org graph is preserved 1:1 (Clerk and
Authio share the same shape there). Passwords are NEVER imported.`
}

type clerkEmail struct {
	ID           string `json:"id"`
	EmailAddress string `json:"email_address"`
	Verification struct {
		Status string `json:"status"`
	} `json:"verification"`
}

type clerkPhone struct {
	PhoneNumber string `json:"phone_number"`
	Verified    bool   `json:"verified"`
}

type clerkExternal struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
}

type clerkOrgMember struct {
	ID           string `json:"id"`
	Role         string `json:"role"`
	Organization struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"organization"`
}

type clerkRecord struct {
	ID                   string           `json:"id"`
	EmailAddresses       []clerkEmail     `json:"email_addresses"`
	PrimaryEmailID       string           `json:"primary_email_address_id"`
	PhoneNumbers         []clerkPhone     `json:"phone_numbers"`
	ExternalAccounts     []clerkExternal  `json:"external_accounts"`
	OrganizationMembers  []clerkOrgMember `json:"organization_memberships"`
	FirstName            string           `json:"first_name"`
	LastName             string           `json:"last_name"`
	Username             string           `json:"username"`
	ImageURL             string           `json:"image_url"`
	ProfileImageURL      string           `json:"profile_image_url"`
	TwoFactorEnabled     bool             `json:"two_factor_enabled"`
	TotpEnabled          bool             `json:"totp_enabled"`
	BackupCodeEnabled    bool             `json:"backup_code_enabled"`
	Banned               bool             `json:"banned"`
	Locked               bool             `json:"locked"`
	PublicMetadata       map[string]any   `json:"public_metadata"`
	PrivateMetadata      map[string]any   `json:"private_metadata"`
	UnsafeMetadata       map[string]any   `json:"unsafe_metadata"`
}

func (clerkPlanParser) ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error) {
	plan := &ImportPlan{Provider: "clerk"}
	users := newUserIndex(opts.MergeDuplicateEmails)
	orgs := map[string]*OrgRecord{}

	err := streamArrayOrNDJSON(ctx, r, "data", func(_ SourceUser) error { return nil },
		func(raw json.RawMessage) (SourceUser, bool) {
			var rec clerkRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				return SourceUser{}, false
			}
			plan.Stats.SourceUsers++
			if rec.Banned || rec.Locked {
				plan.addWarning("clerk: skipped banned/locked user %s", rec.ID)
				return SourceUser{}, false
			}
			email, verified := primaryClerkEmail(rec)
			if email == "" {
				plan.addWarning("clerk: skipped user %s — no email_addresses", rec.ID)
				return SourceUser{}, false
			}
			email = normEmail(email)
			if email == "" {
				return SourceUser{}, false
			}

			meta := map[string]any{}
			if len(rec.PublicMetadata) > 0 {
				meta["public"] = rec.PublicMetadata
			}
			if len(rec.PrivateMetadata) > 0 {
				meta["private"] = rec.PrivateMetadata
			}
			if len(rec.UnsafeMetadata) > 0 {
				meta["unsafe"] = rec.UnsafeMetadata
			}
			if len(rec.PhoneNumbers) > 0 {
				phones := make([]string, 0, len(rec.PhoneNumbers))
				for _, p := range rec.PhoneNumbers {
					if p.PhoneNumber != "" {
						phones = append(phones, p.PhoneNumber)
					}
				}
				if len(phones) > 0 {
					meta["phones"] = phones
				}
			}

			img := rec.ImageURL
			if img == "" {
				img = rec.ProfileImageURL
			}

			name := strings.TrimSpace(strings.TrimSpace(rec.FirstName) + " " + strings.TrimSpace(rec.LastName))
			if name == "" {
				name = rec.Username
			}

			users.upsert(UserRecord{
				ExternalID:            extID("clerk", rec.ID),
				Email:                 email,
				EmailVerified:         verified,
				Name:                  name,
				AvatarURL:             img,
				Metadata:              meta,
				MigrationPendingEmail: true,
				MfaEnrolled:           rec.TwoFactorEnabled || rec.TotpEnabled || rec.BackupCodeEnabled,
				SourceExternalIDs:     []string{extID("clerk", rec.ID)},
			})

			for _, x := range rec.ExternalAccounts {
				kind, sub := clerkIdentityKind(x)
				if kind == "" || sub == "" {
					continue
				}
				plan.Identities = append(plan.Identities, IdentityRecord{
					UserExternalID: extID("clerk", rec.ID),
					Kind:           kind,
					Subject:        sub,
				})
			}

			for _, m := range rec.OrganizationMembers {
				if m.Organization.ID == "" {
					continue
				}
				ext := extID("clerk", "org:"+m.Organization.ID)
				if _, exists := orgs[ext]; !exists {
					slug := m.Organization.Slug
					if slug == "" {
						slug = slugify(m.Organization.Name)
					} else {
						slug = slugify(slug)
					}
					orgs[ext] = &OrgRecord{
						ExternalID: ext,
						Name:       m.Organization.Name,
						Slug:       slug,
					}
				}
				plan.Memberships = append(plan.Memberships, MembershipRecord{
					UserExternalID: extID("clerk", rec.ID),
					OrgExternalID:  ext,
					Role:           mapRole(m.Role),
					Status:         "active",
				})
			}
			return SourceUser{}, false
		},
	)
	if err != nil {
		return nil, err
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	for _, o := range orgs {
		plan.Orgs = append(plan.Orgs, *o)
	}
	return plan, nil
}

func primaryClerkEmail(rec clerkRecord) (string, bool) {
	if len(rec.EmailAddresses) == 0 {
		return "", false
	}
	if rec.PrimaryEmailID != "" {
		for _, e := range rec.EmailAddresses {
			if e.ID == rec.PrimaryEmailID {
				return e.EmailAddress, e.Verification.Status == "verified"
			}
		}
	}
	for _, e := range rec.EmailAddresses {
		if e.Verification.Status == "verified" {
			return e.EmailAddress, true
		}
	}
	return rec.EmailAddresses[0].EmailAddress, false
}

func clerkIdentityKind(x clerkExternal) (string, string) {
	switch strings.ToLower(x.Provider) {
	case "oauth_google", "google":
		return "oauth_google", x.ProviderUserID
	case "oauth_microsoft", "microsoft":
		return "oauth_microsoft", x.ProviderUserID
	case "oauth_github", "github":
		return "oauth_github", x.ProviderUserID
	case "oauth_apple", "apple":
		return "oauth_apple", x.ProviderUserID
	case "oauth_facebook", "facebook":
		return "oauth_facebook", x.ProviderUserID
	default:
		if x.Provider != "" {
			return "oauth_" + strings.TrimPrefix(strings.ToLower(x.Provider), "oauth_"), x.ProviderUserID
		}
		return "", ""
	}
}
