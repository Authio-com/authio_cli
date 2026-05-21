package cmd

import (
	"context"
	"encoding/json"
	"io"
	"strings"
)

// cognitoPlanParser handles output from `aws cognito-idp list-users`,
// optionally enriched with `aws cognito-idp admin-list-groups-for-user`.
//
// What's mapped:
//   - Username           -> external_id (cognito:<username>)
//   - Attributes[email]  -> Authio user.email
//   - email_verified     -> Authio user.email_verified
//   - sub                -> Authio user.metadata.sub (also as identity subject)
//   - name/given_name    -> Authio user.name
//   - custom:*           -> Authio user.metadata.custom.*
//   - Groups[]           -> Authio orgs + memberships (groups ≈ orgs)
//   - MFAOptions != nil  -> mfa_enrolled flag
//   - Identities[]       -> Authio identities (Google/MS/etc.) — if present
//
// What's dropped:
//   - password (Cognito stores hashed; users re-auth via passkey/magic-link)
//   - TOTP secrets (we only preserve the enrolled flag)
type cognitoPlanParser struct{}

func (cognitoPlanParser) Name() string { return "cognito" }
func (cognitoPlanParser) Help() string {
	return `cognito: output of "aws cognito-idp list-users", shaped as
  {"Users":[{"Username":"...","Attributes":[{"Name":"email","Value":"..."}],
             "Enabled":true,"UserStatus":"CONFIRMED",
             "Groups":[{"GroupName":"acme-admins"}]}]}

Disabled/UNCONFIRMED users are skipped. Custom attributes (custom:tier,
etc.) are preserved in Authio user metadata. Groups become Authio orgs.`
}

type cognitoAttr struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

type cognitoGroup struct {
	GroupName   string `json:"GroupName"`
	Description string `json:"Description"`
	Role        string `json:"Role"`
}

type cognitoRecord struct {
	Username   string          `json:"Username"`
	Enabled    *bool           `json:"Enabled"`
	UserStatus string          `json:"UserStatus"`
	Attributes []cognitoAttr   `json:"Attributes"`
	MFAOptions []cognitoAttr   `json:"MFAOptions"`
	Groups     []cognitoGroup  `json:"Groups"`
	// Optional federated identities pulled via admin-list-groups; encoded
	// here for parser convenience.
	FederatedIdentities []struct {
		Provider   string `json:"provider"`
		Subject    string `json:"subject"`
	} `json:"FederatedIdentities"`
}

func (cognitoPlanParser) ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error) {
	plan := &ImportPlan{Provider: "cognito"}
	users := newUserIndex(opts.MergeDuplicateEmails)
	orgs := map[string]*OrgRecord{}

	err := streamArrayOrNDJSON(ctx, r, "Users", func(_ SourceUser) error { return nil },
		func(raw json.RawMessage) (SourceUser, bool) {
			var rec cognitoRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				return SourceUser{}, false
			}
			plan.Stats.SourceUsers++
			enabled := rec.Enabled == nil || *rec.Enabled
			if !enabled {
				plan.addWarning("cognito: skipped disabled user %s", rec.Username)
				return SourceUser{}, false
			}
			if rec.UserStatus != "" && rec.UserStatus != "CONFIRMED" && rec.UserStatus != "EXTERNAL_PROVIDER" {
				plan.addWarning("cognito: skipped %s user %s", rec.UserStatus, rec.Username)
				return SourceUser{}, false
			}

			var email, name, sub string
			var verified bool
			meta := map[string]any{}
			custom := map[string]any{}
			for _, a := range rec.Attributes {
				switch {
				case a.Name == "email":
					email = a.Value
				case a.Name == "email_verified":
					verified = strings.EqualFold(a.Value, "true")
				case a.Name == "name", a.Name == "given_name":
					if name == "" {
						name = a.Value
					}
				case a.Name == "phone_number":
					meta["phone"] = a.Value
				case a.Name == "sub":
					sub = a.Value
					meta["sub"] = a.Value
				case a.Name == "preferred_username":
					meta["preferred_username"] = a.Value
				case strings.HasPrefix(a.Name, "custom:"):
					custom[strings.TrimPrefix(a.Name, "custom:")] = a.Value
				}
			}
			if len(custom) > 0 {
				meta["custom"] = custom
			}
			email = normEmail(email)
			if email == "" {
				plan.addWarning("cognito: skipped user %s — no email attribute", rec.Username)
				return SourceUser{}, false
			}

			users.upsert(UserRecord{
				ExternalID:            extID("cognito", rec.Username),
				Email:                 email,
				EmailVerified:         verified,
				Name:                  name,
				Metadata:              meta,
				MigrationPendingEmail: true,
				MfaEnrolled:           len(rec.MFAOptions) > 0,
				SourceExternalIDs:     []string{extID("cognito", rec.Username)},
			})

			if sub != "" {
				plan.Identities = append(plan.Identities, IdentityRecord{
					UserExternalID: extID("cognito", rec.Username),
					Kind:           "cognito_sub",
					Subject:        sub,
				})
			}
			for _, fi := range rec.FederatedIdentities {
				if fi.Subject == "" {
					continue
				}
				kind := "oauth_" + strings.ToLower(fi.Provider)
				switch strings.ToLower(fi.Provider) {
				case "google":
					kind = "oauth_google"
				case "facebook":
					kind = "oauth_facebook"
				case "loginwithamazon":
					kind = "oauth_amazon"
				case "signinwithapple":
					kind = "oauth_apple"
				}
				plan.Identities = append(plan.Identities, IdentityRecord{
					UserExternalID: extID("cognito", rec.Username),
					Kind:           kind,
					Subject:        fi.Subject,
				})
			}

			for _, g := range rec.Groups {
				if g.GroupName == "" {
					continue
				}
				ext := extID("cognito", "group:"+g.GroupName)
				if _, exists := orgs[ext]; !exists {
					name := g.Description
					if name == "" {
						name = g.GroupName
					}
					orgs[ext] = &OrgRecord{
						ExternalID: ext,
						Name:       name,
						Slug:       slugify(g.GroupName),
					}
				}
				plan.Memberships = append(plan.Memberships, MembershipRecord{
					UserExternalID: extID("cognito", rec.Username),
					OrgExternalID:  ext,
					Role:           mapRole(g.Role),
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
