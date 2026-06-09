package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// workosPlanParser is the marquee importer.
//
// WorkOS exports a *bundle* (we accept a single JSON envelope) consisting
// of users, organizations, organization_memberships, sso_connections, and
// directories. The expected shape:
//
//   {
//     "users":[ ...AuthKit user rows... ],
//     "organizations":[ ... ],
//     "organization_memberships":[ ... ],
//     "sso_connections":[ ... ],
//     "directories":[ ... ]   // SCIM directories
//   }
//
// The "1-user-1-org" WorkOS limitation: WorkOS issues a new user_id per
// (email, organization) pair. The importer detects this and merges all
// such users into a single Authio user with N memberships. This is the
// differentiating sales moment — it's surfaced in the stats and warnings.
type workosPlanParser struct{}

func (workosPlanParser) Name() string { return "workos" }
func (workosPlanParser) Help() string {
	return `workos: a JSON bundle assembled from the WorkOS Admin API:
  GET /users, GET /organizations,
  GET /organization_memberships?organization_id=<org_id> (once per org),
  GET /connections, GET /directories.

Wrap them as:
  {"users":[...],"organizations":[...],"organization_memberships":[...],
   "sso_connections":[...],"directories":[...]}

The same email across multiple WorkOS orgs collapses into one Authio user
with N memberships — call out the merge count in the importer summary.`
}

type workosBundle struct {
	Users                   []workosUser           `json:"users"`
	Organizations           []workosOrganization   `json:"organizations"`
	OrganizationMemberships []workosMembership     `json:"organization_memberships"`
	SsoConnections          []workosSsoConnection  `json:"sso_connections"`
	Directories             []workosDirectory      `json:"directories"`
}

type workosUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	ProfilePicture string `json:"profile_picture_url"`
}

type workosOrganization struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Domain string `json:"domain"`
	Domains []struct {
		Domain string `json:"domain"`
	} `json:"domains"`
}

type workosMembership struct {
	ID             string `json:"id"`
	UserID         string `json:"user_id"`
	OrganizationID string `json:"organization_id"`
	Role           struct {
		Slug string `json:"slug"`
	} `json:"role"`
	Status string `json:"status"`
}

type workosSsoConnection struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ConnectionType string `json:"connection_type"`
	OrganizationID string `json:"organization_id"`
}

type workosDirectory struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	OrganizationID string `json:"organization_id"`
}

func (workosPlanParser) ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error) {
	plan := &ImportPlan{Provider: "workos"}
	var bundle workosBundle
	if err := json.NewDecoder(r).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("workos bundle: %w", err)
	}

	// ---- orgs ----
	orgByID := map[string]string{} // workos org id -> Authio external_id
	for _, o := range bundle.Organizations {
		domain := o.Domain
		if domain == "" && len(o.Domains) > 0 {
			domain = o.Domains[0].Domain
		}
		ext := extID("workos", "org:"+o.ID)
		slug := o.Slug
		if slug == "" {
			slug = slugify(o.Name)
		} else {
			slug = slugify(slug)
		}
		plan.Orgs = append(plan.Orgs, OrgRecord{
			ExternalID: ext,
			Name:       o.Name,
			Slug:       slug,
			Domain:     domain,
		})
		orgByID[o.ID] = ext
	}

	// ---- users (with email-merge) ----
	merge := opts.MergeDuplicateEmails || true
	users := newUserIndex(merge)
	userIDToEmail := map[string]string{} // workos user_id -> email
	for _, u := range bundle.Users {
		plan.Stats.SourceUsers++
		email := normEmail(u.Email)
		if email == "" {
			plan.addWarning("workos: skipped user %s — no email", u.ID)
			continue
		}
		name := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
		users.upsert(UserRecord{
			ExternalID:            extID("workos", u.ID),
			Email:                 email,
			EmailVerified:         u.EmailVerified,
			Name:                  name,
			AvatarURL:             u.ProfilePicture,
			MigrationPendingEmail: true,
			SourceExternalIDs:     []string{extID("workos", u.ID)},
		})
		userIDToEmail[u.ID] = email
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	if users.merged > 0 {
		plan.addWarning("workos: merged %d duplicate-email users into %d Authio users with multi-org memberships", users.merged, len(plan.Users))
	}

	// ---- memberships ----
	for _, m := range bundle.OrganizationMemberships {
		email, ok := userIDToEmail[m.UserID]
		if !ok {
			plan.addWarning("workos: membership %s references unknown user %s", m.ID, m.UserID)
			continue
		}
		orgExt, ok := orgByID[m.OrganizationID]
		if !ok {
			plan.addWarning("workos: membership %s references unknown org %s", m.ID, m.OrganizationID)
			continue
		}
		// userExternalID points at the *primary* Authio user (the one we
		// kept after merging). Look it up by email.
		userExt := ""
		for _, u := range plan.Users {
			if u.Email == email {
				userExt = u.ExternalID
				break
			}
		}
		if userExt == "" {
			continue
		}
		status := m.Status
		if status == "" {
			status = "active"
		}
		plan.Memberships = append(plan.Memberships, MembershipRecord{
			UserExternalID: userExt,
			OrgExternalID:  orgExt,
			Role:           mapRole(m.Role.Slug),
			Status:         status,
		})
	}

	// ---- SSO connections ----
	for _, s := range bundle.SsoConnections {
		orgExt, ok := orgByID[s.OrganizationID]
		if !ok {
			plan.addWarning("workos: sso connection %s references unknown org %s", s.ID, s.OrganizationID)
			continue
		}
		kind := "saml"
		if strings.Contains(strings.ToLower(s.ConnectionType), "oidc") {
			kind = "oidc"
		}
		plan.SsoConnections = append(plan.SsoConnections, SsoConnectionRecord{
			OrgExternalID: orgExt,
			Name:          s.Name,
			Kind:          kind,
			Metadata: map[string]any{
				"workos_connection_id":   s.ID,
				"workos_connection_type": s.ConnectionType,
			},
		})
	}

	// ---- SCIM directories ----
	for _, d := range bundle.Directories {
		orgExt, ok := orgByID[d.OrganizationID]
		if !ok {
			plan.addWarning("workos: directory %s references unknown org %s", d.ID, d.OrganizationID)
			continue
		}
		plan.ScimDirectories = append(plan.ScimDirectories, ScimDirectoryRecord{
			OrgExternalID: orgExt,
			Name:          d.Name,
		})
	}

	return plan, nil
}
