package clerk

import (
	"encoding/json"
	"strings"
	"time"
)

// ---------------------------------------------------------------------
// Clerk Backend-API source shapes.
//
// Field set follows https://clerk.com/docs/reference/backend-api as of
// the time this importer was first written. Optional fields are
// omitempty/pointer-ish via json.RawMessage where the spec is
// best-effort. Everything we read on the wire round-trips through
// these types — no parallel maps.
// ---------------------------------------------------------------------

// ClerkUser is one row from `GET /v1/users`.
type ClerkUser struct {
	ID                      string             `json:"id"`
	EmailAddresses          []ClerkEmail       `json:"email_addresses"`
	PrimaryEmailAddressID   string             `json:"primary_email_address_id"`
	PhoneNumbers            []ClerkPhone       `json:"phone_numbers"`
	PrimaryPhoneNumberID    string             `json:"primary_phone_number_id"`
	FirstName               string             `json:"first_name"`
	LastName                string             `json:"last_name"`
	Username                string             `json:"username"`
	ImageURL                string             `json:"image_url"`
	HasImage                bool               `json:"has_image"`
	ExternalAccounts        []ClerkExternal    `json:"external_accounts"`
	Passkeys                []ClerkPasskey     `json:"passkeys"`
	TOTPEnabled             bool               `json:"totp_enabled"`
	BackupCodeEnabled       bool               `json:"backup_code_enabled"`
	TwoFactorEnabled        bool               `json:"two_factor_enabled"`
	Banned                  bool               `json:"banned"`
	Locked                  bool               `json:"locked"`
	CreatedAt               int64              `json:"created_at"`        // epoch milliseconds
	UpdatedAt               int64              `json:"updated_at"`
	LastSignInAt            int64              `json:"last_sign_in_at"`
	LastActiveAt            int64              `json:"last_active_at"`
	PublicMetadata          json.RawMessage    `json:"public_metadata"`
	PrivateMetadata         json.RawMessage    `json:"private_metadata"`
	UnsafeMetadata          json.RawMessage    `json:"unsafe_metadata"`
}

// ClerkEmail is one element of ClerkUser.EmailAddresses.
type ClerkEmail struct {
	ID           string `json:"id"`
	EmailAddress string `json:"email_address"`
	Verification struct {
		Status string `json:"status"`
	} `json:"verification"`
	LinkedTo []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"linked_to"`
}

// ClerkPhone is one element of ClerkUser.PhoneNumbers.
type ClerkPhone struct {
	ID          string `json:"id"`
	PhoneNumber string `json:"phone_number"`
	Verified    bool   `json:"verified"`
	Verification struct {
		Status string `json:"status"`
	} `json:"verification"`
}

// ClerkExternal is one row of ClerkUser.ExternalAccounts.
type ClerkExternal struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
	EmailAddress   string `json:"email_address"`
	Username       string `json:"username"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	AvatarURL      string `json:"avatar_url"`
	ImageURL       string `json:"image_url"`
}

// ClerkPasskey is one row of ClerkUser.Passkeys.
type ClerkPasskey struct {
	ID              string `json:"id"`
	CredentialID    string `json:"credential_id"`
	Name            string `json:"name"`
	PublicKey       string `json:"public_key"`
	AAGUID          string `json:"aaguid"`
	Counter         uint64 `json:"counter"`
	Transports      []string `json:"transports"`
	BackupEligible  bool   `json:"backup_eligible"`
	BackupState     bool   `json:"backup_state"`
	UserVerified    bool   `json:"user_verified"`
	CreatedAt       int64  `json:"created_at"`
	LastUsedAt      int64  `json:"last_used_at"`
}

// ClerkOrganization is one row from `GET /v1/organizations`.
type ClerkOrganization struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Slug           string          `json:"slug"`
	LogoURL        string          `json:"logo_url"`
	ImageURL       string          `json:"image_url"`
	HasImage       bool            `json:"has_image"`
	CreatedAt      int64           `json:"created_at"`
	UpdatedAt      int64           `json:"updated_at"`
	MembersCount   int             `json:"members_count"`
	PublicMetadata json.RawMessage `json:"public_metadata"`
	PrivateMetadata json.RawMessage `json:"private_metadata"`
}

// ClerkMembership is one row of `GET /v1/organizations/:id/memberships`.
type ClerkMembership struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Role           string `json:"role"`
	RoleName       string `json:"role_name"`
	PublicUserData struct {
		UserID    string `json:"user_id"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		ImageURL  string `json:"image_url"`
		Identifier string `json:"identifier"`
	} `json:"public_user_data"`
	CreatedAt int64           `json:"created_at"`
	UpdatedAt int64           `json:"updated_at"`
	PublicMetadata json.RawMessage `json:"public_metadata"`
}

// ---------------------------------------------------------------------
// Authio destination payload shapes — what the bulk endpoints accept.
//
// Each payload carries a `clerk_*_id` source-ID field that the
// management-api uses as the idempotency key (re-runs become no-ops).
// ---------------------------------------------------------------------

// AuthioUserPayload is one row of POST /v1/migrate/bulk-users.
type AuthioUserPayload struct {
	ClerkUserID       string                  `json:"clerk_user_id"`
	Email             string                  `json:"email"`
	EmailVerified     bool                    `json:"email_verified"`
	EmailVerifiedAt   *time.Time              `json:"email_verified_at,omitempty"`
	PhoneE164         string                  `json:"phone_e164,omitempty"`
	PhoneVerifiedAt   *time.Time              `json:"phone_verified_at,omitempty"`
	Name              string                  `json:"name,omitempty"`
	AvatarURL         string                  `json:"avatar_url,omitempty"`
	CreatedAt         *time.Time              `json:"created_at,omitempty"`
	LastSignInAt      *time.Time              `json:"last_sign_in_at,omitempty"`
	Metadata          map[string]any          `json:"metadata,omitempty"`
	Identities        []AuthioIdentityPayload `json:"identities,omitempty"`
	WebAuthnCredentials []AuthioWebAuthnPayload `json:"webauthn_credentials,omitempty"`
	MFAFactors        []AuthioMFAPayload      `json:"mfa_factors,omitempty"`
}

// AuthioIdentityPayload is one OAuth / external account linked to a user.
type AuthioIdentityPayload struct {
	Kind     string         `json:"kind"`
	Subject  string         `json:"subject"`
	Email    string         `json:"email,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// AuthioWebAuthnPayload is one passkey credential.
type AuthioWebAuthnPayload struct {
	CredentialID string         `json:"credential_id"`
	PublicKey    string         `json:"public_key"`
	AAGUID       string         `json:"aaguid,omitempty"`
	Transports   []string       `json:"transports,omitempty"`
	SignCount    uint64         `json:"sign_count"`
	Nickname     string         `json:"nickname,omitempty"`
	Flags        map[string]any `json:"flags,omitempty"`
	CreatedAt    *time.Time     `json:"created_at,omitempty"`
	LastUsedAt   *time.Time     `json:"last_used_at,omitempty"`
}

// AuthioMFAPayload is one MFA factor — TOTP or SMS.
type AuthioMFAPayload struct {
	Kind     string         `json:"kind"` // totp | sms | backup_code
	Metadata map[string]any `json:"metadata,omitempty"`
}

// AuthioOrgPayload is one row of POST /v1/migrate/bulk-organizations.
type AuthioOrgPayload struct {
	ClerkOrgID string         `json:"clerk_org_id"`
	Name       string         `json:"name"`
	Slug       string         `json:"slug"`
	LogoURL    string         `json:"logo_url,omitempty"`
	CreatedAt  *time.Time     `json:"created_at,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// AuthioMembershipPayload is one row of POST /v1/migrate/bulk-memberships.
type AuthioMembershipPayload struct {
	ClerkMembershipID string         `json:"clerk_membership_id"`
	ClerkOrgID        string         `json:"clerk_org_id"`
	ClerkUserID       string         `json:"clerk_user_id"`
	Role              string         `json:"role"`
	Status            string         `json:"status"`
	CreatedAt         *time.Time     `json:"created_at,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

// ---------------------------------------------------------------------
// Transform functions
// ---------------------------------------------------------------------

// TransformOptions controls optional pieces of the user transform.
type TransformOptions struct {
	IncludeOAuthBindings bool
	IncludeMFA           bool
}

// TransformUser converts one Clerk user into the Authio bulk payload.
// Returns ok=false when the user must be skipped (no email, banned, or
// locked). The reason is returned for inclusion in the CSV report.
func TransformUser(u ClerkUser, opts TransformOptions) (AuthioUserPayload, string, bool) {
	if u.Banned {
		return AuthioUserPayload{ClerkUserID: u.ID}, "skipped: user is banned in Clerk", false
	}
	if u.Locked {
		return AuthioUserPayload{ClerkUserID: u.ID}, "skipped: user is locked in Clerk", false
	}

	email, emailVerified := primaryEmail(u)
	if email == "" {
		return AuthioUserPayload{ClerkUserID: u.ID}, "skipped: no email addresses on user", false
	}

	phone, phoneVerified := primaryPhone(u)

	payload := AuthioUserPayload{
		ClerkUserID:   u.ID,
		Email:         strings.ToLower(strings.TrimSpace(email)),
		EmailVerified: emailVerified,
		Name:          composeName(u),
		AvatarURL:     u.ImageURL,
	}
	if emailVerified {
		t := epochMsToTime(u.UpdatedAt)
		if !t.IsZero() {
			payload.EmailVerifiedAt = &t
		}
	}
	if phone != "" {
		payload.PhoneE164 = phone
		if phoneVerified {
			t := epochMsToTime(u.UpdatedAt)
			if !t.IsZero() {
				payload.PhoneVerifiedAt = &t
			}
		}
	}
	if t := epochMsToTime(u.CreatedAt); !t.IsZero() {
		payload.CreatedAt = &t
	}
	if t := epochMsToTime(u.LastSignInAt); !t.IsZero() {
		payload.LastSignInAt = &t
	}

	meta := map[string]any{
		"clerk_user_id": u.ID,
	}
	if len(u.PublicMetadata) > 0 && !isJSONNull(u.PublicMetadata) {
		meta["clerk_public_metadata"] = json.RawMessage(u.PublicMetadata)
	}
	if len(u.PrivateMetadata) > 0 && !isJSONNull(u.PrivateMetadata) {
		meta["clerk_private_metadata"] = json.RawMessage(u.PrivateMetadata)
	}
	if len(u.UnsafeMetadata) > 0 && !isJSONNull(u.UnsafeMetadata) {
		meta["clerk_unsafe_metadata"] = json.RawMessage(u.UnsafeMetadata)
	}
	if u.Username != "" {
		meta["clerk_username"] = u.Username
	}
	if u.LastActiveAt > 0 {
		meta["clerk_last_active_at"] = epochMsToTime(u.LastActiveAt).UTC().Format(time.RFC3339)
	}
	payload.Metadata = meta

	if opts.IncludeOAuthBindings {
		for _, e := range u.ExternalAccounts {
			kind := MapClerkProvider(e.Provider)
			if kind == "" || e.ProviderUserID == "" {
				continue
			}
			payload.Identities = append(payload.Identities, AuthioIdentityPayload{
				Kind:    kind,
				Subject: e.ProviderUserID,
				Email:   strings.ToLower(strings.TrimSpace(e.EmailAddress)),
				Metadata: map[string]any{
					"clerk_external_account_id": e.ID,
					"clerk_provider":            e.Provider,
				},
			})
		}
	}

	for _, pk := range u.Passkeys {
		if pk.CredentialID == "" || pk.PublicKey == "" {
			continue
		}
		flags := map[string]any{
			"backup_eligible": pk.BackupEligible,
			"backup_state":    pk.BackupState,
			"user_verified":   pk.UserVerified,
		}
		webauthn := AuthioWebAuthnPayload{
			CredentialID: pk.CredentialID,
			PublicKey:    pk.PublicKey,
			AAGUID:       pk.AAGUID,
			Transports:   pk.Transports,
			SignCount:    pk.Counter,
			Nickname:     pk.Name,
			Flags:        flags,
		}
		if t := epochMsToTime(pk.CreatedAt); !t.IsZero() {
			webauthn.CreatedAt = &t
		}
		if t := epochMsToTime(pk.LastUsedAt); !t.IsZero() {
			webauthn.LastUsedAt = &t
		}
		payload.WebAuthnCredentials = append(payload.WebAuthnCredentials, webauthn)
	}

	if opts.IncludeMFA {
		if u.TOTPEnabled {
			payload.MFAFactors = append(payload.MFAFactors, AuthioMFAPayload{
				Kind:     "totp",
				Metadata: map[string]any{"clerk_totp_enabled": true},
			})
		}
		if u.BackupCodeEnabled {
			payload.MFAFactors = append(payload.MFAFactors, AuthioMFAPayload{
				Kind:     "backup_code",
				Metadata: map[string]any{"clerk_backup_code_enabled": true},
			})
		}
		// Phone-based SMS MFA is implicit when a verified phone exists
		// and two_factor_enabled is true.
		if u.TwoFactorEnabled && phone != "" && phoneVerified {
			payload.MFAFactors = append(payload.MFAFactors, AuthioMFAPayload{
				Kind:     "sms",
				Metadata: map[string]any{"clerk_phone_e164": phone},
			})
		}
	}

	return payload, "", true
}

// TransformOrganization converts one Clerk org into the Authio bulk
// payload.
func TransformOrganization(o ClerkOrganization) AuthioOrgPayload {
	slug := o.Slug
	if slug == "" {
		slug = slugify(o.Name)
	} else {
		slug = slugify(slug)
	}
	logo := o.LogoURL
	if logo == "" {
		logo = o.ImageURL
	}
	meta := map[string]any{
		"clerk_org_id": o.ID,
	}
	if len(o.PublicMetadata) > 0 && !isJSONNull(o.PublicMetadata) {
		meta["clerk_public_metadata"] = json.RawMessage(o.PublicMetadata)
	}
	if len(o.PrivateMetadata) > 0 && !isJSONNull(o.PrivateMetadata) {
		meta["clerk_private_metadata"] = json.RawMessage(o.PrivateMetadata)
	}
	if logo != "" {
		meta["clerk_logo_url"] = logo
	}
	payload := AuthioOrgPayload{
		ClerkOrgID: o.ID,
		Name:       o.Name,
		Slug:       slug,
		LogoURL:    logo,
		Metadata:   meta,
	}
	if t := epochMsToTime(o.CreatedAt); !t.IsZero() {
		payload.CreatedAt = &t
	}
	return payload
}

// TransformMembership converts one Clerk membership into the Authio
// bulk payload.
func TransformMembership(m ClerkMembership) AuthioMembershipPayload {
	payload := AuthioMembershipPayload{
		ClerkMembershipID: m.ID,
		ClerkOrgID:        m.OrganizationID,
		ClerkUserID:       m.PublicUserData.UserID,
		Role:              MapClerkRole(m.Role),
		Status:            "active",
		Metadata: map[string]any{
			"clerk_membership_id": m.ID,
			"clerk_role":          m.Role,
		},
	}
	if t := epochMsToTime(m.CreatedAt); !t.IsZero() {
		payload.CreatedAt = &t
	}
	if m.RoleName != "" {
		payload.Metadata["clerk_role_name"] = m.RoleName
	}
	return payload
}

// ---------------------------------------------------------------------
// Mappers shared with the plan-mode importer for cross-surface parity.
// ---------------------------------------------------------------------

// MapClerkProvider normalizes a Clerk `external_accounts[].provider`
// string ("oauth_google", "google", "saml", …) into Authio's identity
// `kind` namespace. Returns "" for unknown providers; the caller drops.
func MapClerkProvider(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch {
	case p == "google" || strings.HasPrefix(p, "oauth_google"):
		return "oauth_google"
	case p == "microsoft" || strings.HasPrefix(p, "oauth_microsoft"):
		return "oauth_microsoft"
	case p == "github" || strings.HasPrefix(p, "oauth_github"):
		return "oauth_github"
	case p == "apple" || strings.HasPrefix(p, "oauth_apple"):
		return "oauth_apple"
	case p == "facebook" || strings.HasPrefix(p, "oauth_facebook"):
		return "oauth_facebook"
	case p == "linkedin" || strings.HasPrefix(p, "oauth_linkedin"):
		return "oauth_linkedin"
	case p == "discord" || strings.HasPrefix(p, "oauth_discord"):
		return "oauth_discord"
	case p == "twitter" || strings.HasPrefix(p, "oauth_twitter") || strings.HasPrefix(p, "oauth_x"):
		return "oauth_twitter"
	case p == "saml":
		return "saml_clerk"
	case strings.HasPrefix(p, "oauth_"):
		return p
	case p == "":
		return ""
	default:
		return "oauth_" + p
	}
}

// MapClerkRole maps Clerk role strings (admin / basic_member / org:admin
// / org:basic_member / custom) to Authio's owner/admin/member triad.
// Custom Clerk roles default to "member" — the original string is kept
// in metadata so customers can re-promote in the dashboard if needed.
func MapClerkRole(role string) string {
	r := strings.ToLower(strings.TrimSpace(role))
	r = strings.TrimPrefix(r, "org:")
	switch r {
	case "admin", "owner", "org_admin":
		return "owner"
	case "manager", "moderator":
		return "admin"
	case "basic_member", "member", "user", "":
		return "member"
	default:
		return "member"
	}
}

// primaryEmail returns the primary email + verified-flag for a user.
// Falls back to the first verified address, then the first address in
// the list.
func primaryEmail(u ClerkUser) (string, bool) {
	if len(u.EmailAddresses) == 0 {
		return "", false
	}
	if u.PrimaryEmailAddressID != "" {
		for _, e := range u.EmailAddresses {
			if e.ID == u.PrimaryEmailAddressID {
				return e.EmailAddress, e.Verification.Status == "verified"
			}
		}
	}
	for _, e := range u.EmailAddresses {
		if e.Verification.Status == "verified" {
			return e.EmailAddress, true
		}
	}
	return u.EmailAddresses[0].EmailAddress, u.EmailAddresses[0].Verification.Status == "verified"
}

// primaryPhone returns the verified primary phone (E.164) if any.
func primaryPhone(u ClerkUser) (string, bool) {
	if len(u.PhoneNumbers) == 0 {
		return "", false
	}
	if u.PrimaryPhoneNumberID != "" {
		for _, p := range u.PhoneNumbers {
			if p.ID == u.PrimaryPhoneNumberID {
				return p.PhoneNumber, p.Verified || p.Verification.Status == "verified"
			}
		}
	}
	for _, p := range u.PhoneNumbers {
		if p.Verified || p.Verification.Status == "verified" {
			return p.PhoneNumber, true
		}
	}
	return u.PhoneNumbers[0].PhoneNumber, false
}

func composeName(u ClerkUser) string {
	n := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
	if n == "" {
		n = strings.TrimSpace(u.Username)
	}
	return n
}

func epochMsToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func isJSONNull(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "{}"
}

// slugify mirrors internal/cmd/import_plan.go's slugify so wizard- and
// CLI-driven imports collide on the same Authio org slug.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dashRun := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dashRun = false
		default:
			if !dashRun {
				b.WriteRune('-')
				dashRun = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "org"
	}
	if len(out) > 60 {
		out = strings.TrimRight(out[:60], "-")
	}
	if len(out) < 2 {
		out = out + "0"
	}
	return out
}
