package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// descopePlanParser handles the Descope Management-API user search +
// tenants bundle:
//
//   {
//     "users":[{"loginId":"...","email":"...","verifiedEmail":true,
//                "name":"...","userTenants":[{"tenantId":"...","tenantName":"...",
//                                              "roleNames":["admin"]}],
//                "customAttributes":{...},"status":"enabled"}],
//     "tenants":[{"id":"...","name":"...","selfProvisioningDomains":["acme.com"]}],
//     "sso":[{"tenantId":"...","name":"...","type":"saml"}]
//   }
//
// Descope tenants ≈ Authio orgs; multi-tenant users map 1:1 to multi-org
// memberships in Authio.
type descopePlanParser struct{}

func (descopePlanParser) Name() string { return "descope" }
func (descopePlanParser) Help() string {
	return `descope: a JSON bundle from Descope's Management API:
  POST /v1/mgmt/user/search          -> users[]
  GET  /v1/mgmt/tenant/all           -> tenants[]
  GET  /v1/mgmt/sso/settings/all     -> sso[]

Wrap them as: {"users":[...],"tenants":[...],"sso":[...]}.
Descope tenants become Authio orgs 1:1.`
}

type descopeBundle struct {
	Users   []descopeUser   `json:"users"`
	Tenants []descopeTenant `json:"tenants"`
	SSO     []descopeSso    `json:"sso"`
}

type descopeUser struct {
	LoginID          string            `json:"loginId"`
	UserID           string            `json:"userId"`
	Email            string            `json:"email"`
	VerifiedEmail    bool              `json:"verifiedEmail"`
	Phone            string            `json:"phone"`
	VerifiedPhone    bool              `json:"verifiedPhone"`
	Name             string            `json:"name"`
	GivenName        string            `json:"givenName"`
	FamilyName       string            `json:"familyName"`
	Picture          string            `json:"picture"`
	Status           string            `json:"status"`
	CustomAttributes map[string]any    `json:"customAttributes"`
	UserTenants      []descopeUserTenant `json:"userTenants"`
	OauthSubjects    map[string]string `json:"oauth"`
	TotpEnabled      bool              `json:"totp"`
}

type descopeUserTenant struct {
	TenantID   string   `json:"tenantId"`
	TenantName string   `json:"tenantName"`
	RoleNames  []string `json:"roleNames"`
}

type descopeTenant struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	SelfProvisioningDomains  []string `json:"selfProvisioningDomains"`
}

type descopeSso struct {
	TenantID string `json:"tenantId"`
	Name     string `json:"name"`
	Type     string `json:"type"`
}

func (descopePlanParser) ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error) {
	var bundle descopeBundle
	if err := json.NewDecoder(r).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("descope bundle: %w", err)
	}
	plan := &ImportPlan{Provider: "descope"}
	users := newUserIndex(opts.MergeDuplicateEmails)
	orgByID := map[string]string{}

	for _, t := range bundle.Tenants {
		ext := extID("descope", "tenant:"+t.ID)
		domain := ""
		if len(t.SelfProvisioningDomains) > 0 {
			domain = t.SelfProvisioningDomains[0]
		}
		plan.Orgs = append(plan.Orgs, OrgRecord{
			ExternalID: ext,
			Name:       t.Name,
			Slug:       slugify(t.Name),
			Domain:     domain,
		})
		orgByID[t.ID] = ext
	}

	for _, u := range bundle.Users {
		plan.Stats.SourceUsers++
		email := normEmail(u.Email)
		if email == "" {
			plan.addWarning("descope: skipped user %s — no email", u.LoginID)
			continue
		}
		if u.Status != "" && u.Status != "enabled" && u.Status != "active" {
			plan.addWarning("descope: skipped %s user %s", u.Status, u.LoginID)
			continue
		}
		name := u.Name
		if name == "" {
			name = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
		}
		meta := map[string]any{}
		if len(u.CustomAttributes) > 0 {
			meta["custom"] = u.CustomAttributes
		}
		if u.Phone != "" {
			meta["phone"] = u.Phone
			if u.VerifiedPhone {
				meta["phone_verified"] = true
			}
		}
		userExt := extID("descope", u.LoginID)
		users.upsert(UserRecord{
			ExternalID:            userExt,
			Email:                 email,
			EmailVerified:         u.VerifiedEmail,
			Name:                  name,
			AvatarURL:             u.Picture,
			Metadata:              meta,
			MigrationPendingEmail: true,
			MfaEnrolled:           u.TotpEnabled,
			SourceExternalIDs:     []string{userExt},
		})

		for prov, sub := range u.OauthSubjects {
			kind := "oauth_" + strings.ToLower(prov)
			plan.Identities = append(plan.Identities, IdentityRecord{
				UserExternalID: userExt,
				Kind:           kind,
				Subject:        sub,
			})
		}

		for _, ut := range u.UserTenants {
			orgExt, ok := orgByID[ut.TenantID]
			if !ok {
				// Create an ad-hoc org from the tenant name.
				orgExt = extID("descope", "tenant:"+ut.TenantID)
				orgByID[ut.TenantID] = orgExt
				plan.Orgs = append(plan.Orgs, OrgRecord{
					ExternalID: orgExt,
					Name:       fallbackName(ut.TenantName, ut.TenantID),
					Slug:       slugify(fallbackName(ut.TenantName, ut.TenantID)),
				})
			}
			role := "member"
			if len(ut.RoleNames) > 0 {
				role = mapRole(ut.RoleNames[0])
			}
			plan.Memberships = append(plan.Memberships, MembershipRecord{
				UserExternalID: userExt,
				OrgExternalID:  orgExt,
				Role:           role,
				Status:         "active",
			})
		}
	}

	for _, s := range bundle.SSO {
		orgExt, ok := orgByID[s.TenantID]
		if !ok {
			plan.addWarning("descope: sso %s references unknown tenant %s", s.Name, s.TenantID)
			continue
		}
		kind := "saml"
		if strings.EqualFold(s.Type, "oidc") {
			kind = "oidc"
		}
		plan.SsoConnections = append(plan.SsoConnections, SsoConnectionRecord{
			OrgExternalID: orgExt,
			Name:          s.Name,
			Kind:          kind,
		})
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	return plan, nil
}
