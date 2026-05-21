package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// stytchPlanParser handles B2B (Members) exports and Consumer (Users)
// exports. B2B looks like:
//
//   {"organizations":[{"organization_id":"org_...","organization_name":"Acme",
//                       "organization_slug":"acme",
//                       "members":[{"member_id":"member_...","email_address":"...",
//                                    "trusted_metadata":{...},"untrusted_metadata":{...},
//                                    "is_breakglass":false,"status":"active",
//                                    "sso_registrations":[...],"name":"...",
//                                    "mfa_enrolled":false}]}],
//     "sso_connections":[{"connection_id":"...","organization_id":"...",
//                          "display_name":"...","idp":"saml"}]}
//
// Consumer (single-tenant) export is just a flat array of users:
//
//   [{"user_id":"user-test-...","emails":[{"email":"..."}],"name":{"first_name":"..."}}]
//
// We auto-detect by looking for `organizations[]` first.
//
// Stytch B2B is already multi-org with shared-member-by-email, so the
// mapping is almost 1:1 with Authio.
type stytchPlanParser struct{}

func (stytchPlanParser) Name() string { return "stytch" }
func (stytchPlanParser) Help() string {
	return `stytch: B2B export from Stytch Members API:
  {"organizations":[{...,"members":[...]}],"sso_connections":[...]}
or Consumer export:
  [{"user_id":"...","emails":[{"email":"..."}],"name":{"first_name":"..."}}]

Stytch B2B's multi-org-shared-member-by-email model maps 1:1 to Authio.
Consumer Stytch users all land in one default org.`
}

type stytchBundle struct {
	Organizations  []stytchOrganization `json:"organizations"`
	SsoConnections []stytchSso          `json:"sso_connections"`
	// When the file is a flat Consumer-Users array, we'll decode it into
	// .Users below via a fallback path.
}

type stytchOrganization struct {
	OrganizationID   string         `json:"organization_id"`
	OrganizationName string         `json:"organization_name"`
	OrganizationSlug string         `json:"organization_slug"`
	Members          []stytchMember `json:"members"`
}

type stytchMember struct {
	MemberID         string         `json:"member_id"`
	EmailAddress     string         `json:"email_address"`
	Name             string         `json:"name"`
	Status           string         `json:"status"`
	IsAdmin          bool           `json:"is_admin"`
	IsBreakglass     bool           `json:"is_breakglass"`
	MfaEnrolled      bool           `json:"mfa_enrolled"`
	Roles            []struct {
		RoleID string `json:"role_id"`
	} `json:"roles"`
	SsoRegistrations []struct {
		ConnectionID  string `json:"connection_id"`
		SsoExternalID string `json:"external_id"`
	} `json:"sso_registrations"`
	TrustedMetadata   map[string]any `json:"trusted_metadata"`
	UntrustedMetadata map[string]any `json:"untrusted_metadata"`
}

type stytchSso struct {
	ConnectionID   string `json:"connection_id"`
	OrganizationID string `json:"organization_id"`
	DisplayName    string `json:"display_name"`
	IDP            string `json:"idp"`
}

type stytchConsumerUser struct {
	UserID string `json:"user_id"`
	Status string `json:"status"`
	Emails []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	} `json:"emails"`
	Name struct {
		FirstName  string `json:"first_name"`
		LastName   string `json:"last_name"`
		MiddleName string `json:"middle_name"`
	} `json:"name"`
	TrustedMetadata   map[string]any `json:"trusted_metadata"`
	UntrustedMetadata map[string]any `json:"untrusted_metadata"`
	Providers         []struct {
		ProviderType string `json:"provider_type"`
		ProviderSubject string `json:"provider_subject"`
	} `json:"providers"`
}

func (stytchPlanParser) ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	plan := &ImportPlan{Provider: "stytch"}

	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	if strings.HasPrefix(trimmed, "[") {
		// Consumer export — flat user array.
		return stytchParseConsumer(plan, raw, opts)
	}
	// B2B export — JSON object envelope.
	var bundle stytchBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("stytch bundle: %w", err)
	}

	users := newUserIndex(opts.MergeDuplicateEmails)
	orgByID := map[string]string{}

	for _, o := range bundle.Organizations {
		ext := extID("stytch", "org:"+o.OrganizationID)
		slug := o.OrganizationSlug
		if slug == "" {
			slug = slugify(o.OrganizationName)
		}
		plan.Orgs = append(plan.Orgs, OrgRecord{
			ExternalID: ext,
			Name:       o.OrganizationName,
			Slug:       slugify(slug),
		})
		orgByID[o.OrganizationID] = ext

		for _, m := range o.Members {
			plan.Stats.SourceUsers++
			email := normEmail(m.EmailAddress)
			if email == "" {
				plan.addWarning("stytch: skipped member %s — no email", m.MemberID)
				continue
			}
			meta := map[string]any{}
			if len(m.TrustedMetadata) > 0 {
				meta["trusted"] = m.TrustedMetadata
			}
			if len(m.UntrustedMetadata) > 0 {
				meta["untrusted"] = m.UntrustedMetadata
			}
			users.upsert(UserRecord{
				ExternalID:            extID("stytch", m.MemberID),
				Email:                 email,
				EmailVerified:         true, // Stytch verifies at signup
				Name:                  m.Name,
				Metadata:              meta,
				MigrationPendingEmail: true,
				MfaEnrolled:           m.MfaEnrolled,
				SourceExternalIDs:     []string{extID("stytch", m.MemberID)},
			})
			// Find the merged Authio user for this email.
			userExt := ""
			for _, u := range users.list() {
				if u.Email == email {
					userExt = u.ExternalID
					break
				}
			}
			role := "member"
			if m.IsAdmin {
				role = "admin"
			}
			if len(m.Roles) > 0 {
				role = mapRole(m.Roles[0].RoleID)
			}
			status := m.Status
			if status == "" {
				status = "active"
			}
			plan.Memberships = append(plan.Memberships, MembershipRecord{
				UserExternalID: userExt,
				OrgExternalID:  ext,
				Role:           role,
				Status:         status,
			})
		}
	}

	for _, s := range bundle.SsoConnections {
		orgExt, ok := orgByID[s.OrganizationID]
		if !ok {
			plan.addWarning("stytch: sso connection %s references unknown org %s", s.ConnectionID, s.OrganizationID)
			continue
		}
		kind := "saml"
		if strings.EqualFold(s.IDP, "oidc") {
			kind = "oidc"
		}
		plan.SsoConnections = append(plan.SsoConnections, SsoConnectionRecord{
			OrgExternalID: orgExt,
			Name:          s.DisplayName,
			Kind:          kind,
			Metadata:      map[string]any{"stytch_connection_id": s.ConnectionID},
		})
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	return plan, nil
}

func stytchParseConsumer(plan *ImportPlan, raw []byte, opts PlanOptions) (*ImportPlan, error) {
	var rows []stytchConsumerUser
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("stytch consumer: %w", err)
	}

	users := newUserIndex(opts.MergeDuplicateEmails)
	defaultExt := extID("stytch", "org:default")
	defaultName := opts.DefaultOrgName
	if defaultName == "" {
		defaultName = "Default"
	}
	plan.Orgs = append(plan.Orgs, OrgRecord{
		ExternalID: defaultExt,
		Name:       defaultName,
		Slug:       slugify(defaultName),
	})

	for _, u := range rows {
		plan.Stats.SourceUsers++
		var email string
		var verified bool
		for _, e := range u.Emails {
			if e.Email != "" {
				email = e.Email
				verified = e.Verified
				if e.Verified {
					break
				}
			}
		}
		email = normEmail(email)
		if email == "" {
			plan.addWarning("stytch: skipped consumer user %s — no email", u.UserID)
			continue
		}
		if u.Status != "" && u.Status != "active" {
			plan.addWarning("stytch: skipped %s user %s", u.Status, u.UserID)
			continue
		}
		name := strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
		meta := map[string]any{}
		if len(u.TrustedMetadata) > 0 {
			meta["trusted"] = u.TrustedMetadata
		}
		if len(u.UntrustedMetadata) > 0 {
			meta["untrusted"] = u.UntrustedMetadata
		}
		users.upsert(UserRecord{
			ExternalID:            extID("stytch", u.UserID),
			Email:                 email,
			EmailVerified:         verified,
			Name:                  name,
			Metadata:              meta,
			MigrationPendingEmail: true,
			SourceExternalIDs:     []string{extID("stytch", u.UserID)},
		})
		plan.Memberships = append(plan.Memberships, MembershipRecord{
			UserExternalID: extID("stytch", u.UserID),
			OrgExternalID:  defaultExt,
			Role:           "member",
			Status:         "active",
		})
		for _, p := range u.Providers {
			kind := "oauth_" + strings.ToLower(p.ProviderType)
			plan.Identities = append(plan.Identities, IdentityRecord{
				UserExternalID: extID("stytch", u.UserID),
				Kind:           kind,
				Subject:        p.ProviderSubject,
			})
		}
	}
	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	return plan, nil
}
