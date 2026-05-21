package cmd

import (
	"context"
	"encoding/json"
	"io"
	"strings"
)

// firebasePlanParser handles `firebase auth:export users.json --format=JSON`.
//
// What's mapped:
//   - localId               -> external_id (firebase:<localId>)
//   - email + emailVerified -> Authio user
//   - displayName / photoUrl-> Authio user.name, user.avatar_url
//   - customAttributes      -> Authio user.metadata.claims (JSON-decoded)
//   - providerUserInfo[]    -> Authio identities (Google/MS/Apple/Facebook/Twitter/GitHub)
//   - mfaInfo[]             -> mfa_enrolled flag
//
// Firebase Auth has no native multi-tenant org concept (Firebase tenants
// are auth tenants, not orgs). All users land under opts.DefaultOrgName
// (or a `default` org) unless an --orgs-table is provided.
//
// What's dropped:
//   - passwordHash + salt (bcrypt or scrypt) — flagged migration_pending.
//   - sessions — users re-auth via passkey/magic-link.
type firebasePlanParser struct{}

func (firebasePlanParser) Name() string { return "firebase" }
func (firebasePlanParser) Help() string {
	return `firebase: output of "firebase auth:export users.json --format=JSON":
  {"users":[{"localId":"...","email":"...","emailVerified":true,
              "displayName":"...","photoUrl":"...",
              "providerUserInfo":[{"providerId":"google.com","rawId":"..."}],
              "customAttributes":"{\"role\":\"admin\"}"}]}

passwordHash/salt are NEVER imported (we don't keep passwords). Users get
a magic-link enrollment on first sign-in.`
}

type firebaseProviderInfo struct {
	ProviderID  string `json:"providerId"`
	RawID       string `json:"rawId"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	PhotoURL    string `json:"photoUrl"`
	FederatedID string `json:"federatedId"`
}

type firebaseRecord struct {
	LocalID          string                 `json:"localId"`
	Email            string                 `json:"email"`
	EmailVerified    bool                   `json:"emailVerified"`
	DisplayName      string                 `json:"displayName"`
	PhotoURL         string                 `json:"photoUrl"`
	Disabled         bool                   `json:"disabled"`
	ProviderUserInfo []firebaseProviderInfo `json:"providerUserInfo"`
	CustomAttributes string                 `json:"customAttributes"`
	TenantID         string                 `json:"tenantId"`
	MfaInfo          []json.RawMessage      `json:"mfaInfo"`
}

func (firebasePlanParser) ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error) {
	plan := &ImportPlan{Provider: "firebase"}
	users := newUserIndex(opts.MergeDuplicateEmails)

	defaultOrgName := opts.DefaultOrgName
	if defaultOrgName == "" {
		defaultOrgName = "Default"
	}
	defaultOrgSlug := slugify(defaultOrgName)
	defaultOrgExt := extID("firebase", "org:default")

	// Always emit the default org so memberships have a target.
	plan.Orgs = append(plan.Orgs, OrgRecord{
		ExternalID: defaultOrgExt,
		Name:       defaultOrgName,
		Slug:       defaultOrgSlug,
	})

	// Tenant-scoped orgs are emitted on demand.
	tenants := map[string]string{} // tenantId -> orgExternalID

	err := streamArrayOrNDJSON(ctx, r, "users", func(_ SourceUser) error { return nil },
		func(raw json.RawMessage) (SourceUser, bool) {
			var rec firebaseRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				return SourceUser{}, false
			}
			plan.Stats.SourceUsers++
			if rec.Disabled {
				plan.addWarning("firebase: skipped disabled user %s", rec.LocalID)
				return SourceUser{}, false
			}
			email := normEmail(rec.Email)
			if email == "" {
				plan.addWarning("firebase: skipped user %s — no email", rec.LocalID)
				return SourceUser{}, false
			}

			meta := map[string]any{}
			if rec.CustomAttributes != "" {
				var claims map[string]any
				if err := json.Unmarshal([]byte(rec.CustomAttributes), &claims); err == nil && len(claims) > 0 {
					meta["claims"] = claims
				}
			}

			users.upsert(UserRecord{
				ExternalID:            extID("firebase", rec.LocalID),
				Email:                 email,
				EmailVerified:         rec.EmailVerified,
				Name:                  rec.DisplayName,
				AvatarURL:             rec.PhotoURL,
				Metadata:              meta,
				MigrationPendingEmail: true,
				MfaEnrolled:           len(rec.MfaInfo) > 0,
				SourceExternalIDs:     []string{extID("firebase", rec.LocalID)},
			})

			for _, p := range rec.ProviderUserInfo {
				kind, sub := firebaseIdentityKind(p)
				if kind == "" || sub == "" {
					continue
				}
				plan.Identities = append(plan.Identities, IdentityRecord{
					UserExternalID: extID("firebase", rec.LocalID),
					Kind:           kind,
					Subject:        sub,
				})
			}

			// Place the user in the right "org":
			//   - if Firebase tenantId is set, that becomes the org.
			//   - else the global default org.
			orgExt := defaultOrgExt
			if rec.TenantID != "" {
				ext, ok := tenants[rec.TenantID]
				if !ok {
					ext = extID("firebase", "tenant:"+rec.TenantID)
					tenants[rec.TenantID] = ext
					plan.Orgs = append(plan.Orgs, OrgRecord{
						ExternalID: ext,
						Name:       rec.TenantID,
						Slug:       slugify(rec.TenantID),
					})
				}
				orgExt = ext
			}
			plan.Memberships = append(plan.Memberships, MembershipRecord{
				UserExternalID: extID("firebase", rec.LocalID),
				OrgExternalID:  orgExt,
				Role:           "member",
				Status:         "active",
			})
			return SourceUser{}, false
		},
	)
	if err != nil {
		return nil, err
	}
	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	return plan, nil
}

func firebaseIdentityKind(p firebaseProviderInfo) (string, string) {
	switch strings.ToLower(p.ProviderID) {
	case "google.com":
		return "oauth_google", p.RawID
	case "microsoft.com":
		return "oauth_microsoft", p.RawID
	case "github.com":
		return "oauth_github", p.RawID
	case "apple.com":
		return "oauth_apple", p.RawID
	case "facebook.com":
		return "oauth_facebook", p.RawID
	case "twitter.com":
		return "oauth_twitter", p.RawID
	case "password":
		return "", "" // dropped — passwords aren't imported
	case "phone":
		return "", "" // mapped via metadata.phone, not as a separate identity
	default:
		if p.ProviderID != "" {
			return "oauth_" + slugify(p.ProviderID), p.RawID
		}
		return "", ""
	}
}
