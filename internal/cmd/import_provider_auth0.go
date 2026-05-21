package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// auth0PlanParser handles the Management-API user export and the
// dashboard CSV-to-JSON tool, plus a richer "rich" shape some operators
// produce that bundles Auth0 organizations + roles into a single doc.
//
// What's mapped:
//   - user_id            -> external_id (auth0:<id>)
//   - email + verified   -> Authio user
//   - name / nickname    -> Authio user.name (name wins)
//   - app_metadata       -> Authio user.metadata.app
//   - user_metadata      -> Authio user.metadata.user
//   - identities[].provider/user_id (google-oauth2, windowslive, etc.)
//                        -> Authio identities (oauth_google, oauth_microsoft, ...)
//   - organizations[]    -> Authio orgs + memberships
//                          role "admin" -> Authio "owner"
//
// What's dropped:
//   - password_hash      -> dropped; flagged MigrationPendingEmail
//   - multi-factor       -> mfa_enrolled flag preserved; secret dropped
type auth0PlanParser struct{}

func (auth0PlanParser) Name() string { return "auth0" }

func (auth0PlanParser) Help() string {
	return `auth0: a JSON array (or NDJSON) of Auth0 user objects. The Management-
API user export and the dashboard CSV-to-JSON tool both emit this shape.

  {"user_id":"auth0|abc","email":"a@x.com","email_verified":true,
   "name":"Ada","identities":[{"provider":"google-oauth2","user_id":"..."}],
   "organizations":[{"id":"org_1","name":"Acme","display_name":"Acme",
                      "roles":[{"name":"admin"}]}],
   "app_metadata":{...},"user_metadata":{...}}

Auth0 passwords are bcrypt; we never import them. Users get a
migration_pending_email flag so the first login triggers passkey/magic-link
enrollment.`
}

type auth0Identity struct {
	Provider   string `json:"provider"`
	UserID     string `json:"user_id"`
	Connection string `json:"connection"`
}

type auth0Org struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Roles       []struct {
		Name string `json:"name"`
	} `json:"roles"`
	Role string `json:"role"`
}

type auth0Record struct {
	UserID         string          `json:"user_id"`
	Email          string          `json:"email"`
	EmailVerified  bool            `json:"email_verified"`
	Name           string          `json:"name"`
	Nickname       string          `json:"nickname"`
	Picture        string          `json:"picture"`
	Blocked        bool            `json:"blocked"`
	Identities     []auth0Identity `json:"identities"`
	Organizations  []auth0Org      `json:"organizations"`
	AppMetadata    map[string]any  `json:"app_metadata"`
	UserMetadata   map[string]any  `json:"user_metadata"`
	MultifactorRaw json.RawMessage `json:"multifactor"`
}

func (auth0PlanParser) ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error) {
	plan := &ImportPlan{Provider: "auth0"}
	mergeEmails := opts.MergeDuplicateEmails || true // auth0 is single-org-per-tenant but we still dedupe on email
	users := newUserIndex(mergeEmails)
	orgs := map[string]*OrgRecord{} // ext_id -> org

	err := iterAuth0Records(ctx, r, func(rec auth0Record) error {
		plan.Stats.SourceUsers++
		if rec.Blocked || rec.Email == "" {
			plan.addWarning("auth0: skipped blocked or no-email user %s", rec.UserID)
			return nil
		}
		email := normEmail(rec.Email)
		if email == "" {
			plan.addWarning("auth0: skipped user %s — invalid email %q", rec.UserID, rec.Email)
			return nil
		}
		name := strings.TrimSpace(rec.Name)
		if name == "" {
			name = strings.TrimSpace(rec.Nickname)
		}
		mfaOn := len(bytes.TrimSpace(rec.MultifactorRaw)) > 0 && string(bytes.TrimSpace(rec.MultifactorRaw)) != "null" && string(bytes.TrimSpace(rec.MultifactorRaw)) != "[]"

		meta := map[string]any{}
		if len(rec.AppMetadata) > 0 {
			meta["app"] = rec.AppMetadata
		}
		if len(rec.UserMetadata) > 0 {
			meta["user"] = rec.UserMetadata
		}

		u := UserRecord{
			ExternalID:            extID("auth0", rec.UserID),
			Email:                 email,
			EmailVerified:         rec.EmailVerified,
			Name:                  name,
			AvatarURL:             rec.Picture,
			Metadata:              meta,
			MigrationPendingEmail: true,
			MfaEnrolled:           mfaOn,
			SourceExternalIDs:     []string{extID("auth0", rec.UserID)},
		}
		users.upsert(u)

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

		for _, o := range rec.Organizations {
			orgName := o.DisplayName
			if orgName == "" {
				orgName = o.Name
			}
			if orgName == "" {
				continue
			}
			ext := extID("auth0", "org:"+o.ID)
			if _, exists := orgs[ext]; !exists {
				orgs[ext] = &OrgRecord{
					ExternalID: ext,
					Name:       orgName,
					Slug:       slugify(o.Name),
				}
			}
			role := o.Role
			if role == "" && len(o.Roles) > 0 {
				role = o.Roles[0].Name
			}
			plan.Memberships = append(plan.Memberships, MembershipRecord{
				UserExternalID: extID("auth0", rec.UserID),
				OrgExternalID:  ext,
				Role:           mapAuth0Role(role),
				Status:         "active",
			})
		}
		return nil
	})
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

func auth0IdentityKind(i auth0Identity) (string, string) {
	switch strings.ToLower(i.Provider) {
	case "google-oauth2", "google":
		return "oauth_google", i.UserID
	case "windowslive", "microsoft", "azure-ad", "azuread", "windows-live":
		return "oauth_microsoft", i.UserID
	case "github":
		return "oauth_github", i.UserID
	case "apple":
		return "oauth_apple", i.UserID
	case "facebook":
		return "oauth_facebook", i.UserID
	case "auth0":
		// the Auth0-DB identity itself; no Authio analogue (password is dropped).
		return "", ""
	case "samlp":
		return "saml_" + strings.ReplaceAll(i.Connection, " ", "_"), i.UserID
	case "oidc":
		return "oidc_" + strings.ReplaceAll(i.Connection, " ", "_"), i.UserID
	default:
		if i.Provider != "" {
			return "oauth_" + strings.ToLower(i.Provider), i.UserID
		}
		return "", ""
	}
}

// iterAuth0Records streams records from JSON-array, NDJSON, or {users:[...]}.
func iterAuth0Records(ctx context.Context, r io.Reader, cb func(auth0Record) error) error {
	return streamArrayOrNDJSON(ctx, r, "users",
		func(_ SourceUser) error { return nil },
		func(raw json.RawMessage) (SourceUser, bool) {
			var rec auth0Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				return SourceUser{}, false
			}
			if err := cb(rec); err != nil {
				return SourceUser{}, false
			}
			return SourceUser{}, false
		},
	)
}

// userIndex dedupes UserRecords by email and merges metadata + source IDs.
type userIndex struct {
	byEmail map[string]*UserRecord
	order   []string
	merge   bool
	merged  int
}

func newUserIndex(merge bool) *userIndex {
	return &userIndex{byEmail: map[string]*UserRecord{}, merge: merge}
}

func (x *userIndex) upsert(u UserRecord) *UserRecord {
	key := strings.ToLower(strings.TrimSpace(u.Email))
	if key == "" {
		return nil
	}
	if existing, ok := x.byEmail[key]; ok {
		if !x.merge {
			return existing
		}
		x.merged++
		// Merge source IDs.
		seen := map[string]struct{}{}
		for _, s := range existing.SourceExternalIDs {
			seen[s] = struct{}{}
		}
		for _, s := range u.SourceExternalIDs {
			if _, ok := seen[s]; !ok {
				existing.SourceExternalIDs = append(existing.SourceExternalIDs, s)
				seen[s] = struct{}{}
			}
		}
		if u.EmailVerified {
			existing.EmailVerified = true
		}
		if u.MigrationPendingEmail {
			existing.MigrationPendingEmail = true
		}
		if u.MfaEnrolled {
			existing.MfaEnrolled = true
		}
		if existing.Name == "" && u.Name != "" {
			existing.Name = u.Name
		}
		if existing.AvatarURL == "" && u.AvatarURL != "" {
			existing.AvatarURL = u.AvatarURL
		}
		if len(u.Metadata) > 0 {
			if existing.Metadata == nil {
				existing.Metadata = map[string]any{}
			}
			for k, v := range u.Metadata {
				if _, taken := existing.Metadata[k]; !taken {
					existing.Metadata[k] = v
				}
			}
		}
		return existing
	}
	cp := u
	x.byEmail[key] = &cp
	x.order = append(x.order, key)
	return &cp
}

func (x *userIndex) list() []UserRecord {
	out := make([]UserRecord, 0, len(x.order))
	for _, k := range x.order {
		out = append(out, *x.byEmail[k])
	}
	return out
}

// mapAuth0Role honors Auth0's RBAC convention where org-level "admin" is
// the most-privileged role inside an organization. Authio's vocabulary
// reserves "owner" for that tier, so admin → owner. Anything below admin
// is best-effort: member roles stay member.
func mapAuth0Role(sourceRole string) string {
	switch strings.ToLower(strings.TrimSpace(sourceRole)) {
	case "owner", "org_owner", "super_admin", "superadmin":
		return "owner"
	case "admin", "administrator", "org_admin":
		return "owner"
	case "manager", "moderator":
		return "admin"
	case "member", "user", "":
		return "member"
	default:
		return "member"
	}
}

// fallbackName is a tiny helper used by several parsers.
func fallbackName(parts ...string) string {
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			return p
		}
	}
	return ""
}

// Compile-time check.
var _ = fmt.Sprintf
