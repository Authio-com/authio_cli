package cmd

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// ImportPlan is the canonical, provider-neutral shape that every plan
// parser emits. The plan-runner consumes it to drive idempotent writes
// against the Authio management-api.
//
// Idempotency contract: every record carries an ExternalID of the form
// "<provider>:<source_id>". Re-running the importer with the same source
// export is safe — users are upserted on (project_id, email), orgs on
// (project_id, slug), memberships on (project_id, user_id, org_id),
// scim directories on (project_id, organization_id).
type ImportPlan struct {
	Provider        string                  `json:"provider"`
	Users           []UserRecord            `json:"users"`
	Orgs            []OrgRecord             `json:"orgs"`
	Memberships     []MembershipRecord      `json:"memberships"`
	Identities      []IdentityRecord        `json:"identities"`
	SsoConnections  []SsoConnectionRecord   `json:"sso_connections"`
	ScimDirectories []ScimDirectoryRecord   `json:"scim_directories"`
	Warnings        []string                `json:"warnings"`
	Stats           PlanStats               `json:"stats"`
}

// UserRecord — a single user, deduped by email within the plan.
type UserRecord struct {
	ExternalID            string         `json:"external_id"`
	Email                 string         `json:"email"`
	EmailVerified         bool           `json:"email_verified"`
	Name                  string         `json:"name,omitempty"`
	AvatarURL             string         `json:"avatar_url,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
	MigrationPendingEmail bool           `json:"migration_pending_email"`
	MfaEnrolled           bool           `json:"mfa_enrolled,omitempty"`
	// SourceExternalIDs is the list of every source-system ID that
	// merged into this Authio user. For most providers it is a 1-element
	// list. WorkOS produces N-element lists when the same email appears
	// in multiple WorkOS orgs (the "marquee" merge moment).
	SourceExternalIDs []string `json:"source_external_ids,omitempty"`
}

type OrgRecord struct {
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	Domain     string `json:"domain,omitempty"`
}

type MembershipRecord struct {
	UserExternalID string `json:"user_external_id"`
	OrgExternalID  string `json:"org_external_id"`
	Role           string `json:"role"`
	Status         string `json:"status"`
}

type IdentityRecord struct {
	UserExternalID string         `json:"user_external_id"`
	Kind           string         `json:"kind"`
	Subject        string         `json:"subject"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type SsoConnectionRecord struct {
	OrgExternalID string         `json:"org_external_id"`
	Name          string         `json:"name"`
	Kind          string         `json:"kind"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type ScimDirectoryRecord struct {
	OrgExternalID string `json:"org_external_id"`
	Name          string `json:"name"`
}

type PlanStats struct {
	SourceUsers            int `json:"source_users"`
	MergedUsers            int `json:"merged_users"`
	UsersCreated           int `json:"users_created"`
	UsersExisted           int `json:"users_existed"`
	OrgsCreated            int `json:"orgs_created"`
	OrgsExisted            int `json:"orgs_existed"`
	MembershipsCreated     int `json:"memberships_created"`
	IdentitiesCreated      int `json:"identities_created"`
	SsoConnectionsCreated  int `json:"sso_connections_created"`
	ScimDirectoriesCreated int `json:"scim_directories_created"`
	Errored                int `json:"errored"`
	Warnings               int `json:"warnings"`
}

// PlanOptions modifies how a parser builds the plan.
type PlanOptions struct {
	// OrgsTablePath, when non-empty, is a path to a JSON file describing
	// an org graph for providers (Supabase, Firebase) that don't have a
	// first-class org concept. Format:
	//
	//   {
	//     "orgs":[{"external_id":"...", "name":"...", "slug":"...",
	//              "domain":"...", "members":[{"email":"...","role":"admin"}]}]
	//   }
	OrgsTablePath string
	// MergeDuplicateEmails enables WorkOS-style merge: source users with
	// the same email across multiple source orgs collapse into one Authio
	// user with N memberships. Default true.
	MergeDuplicateEmails bool
	// DefaultOrgName is used when a provider has zero orgs in its export
	// (Supabase without --orgs-table, Firebase, Consumer Stytch). All
	// users land under this org as members.
	DefaultOrgName string
}

// PlanParser is what each "production" importer implements. It reads the
// export file once and returns a fully-built ImportPlan.
//
// Parsers do not hit the network and never see a project_id / API key —
// they only translate the source export. The PlanRunner does the writes.
type PlanParser interface {
	Name() string
	Help() string
	ParsePlan(ctx context.Context, r io.Reader, opts PlanOptions) (*ImportPlan, error)
}

// ==========================================================================
// shared helpers used by every provider parser
// ==========================================================================

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// slugify returns a URL-safe slug suitable for the management-api's
// organization slug validator (^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$).
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "org"
	}
	if len(s) > 60 {
		s = s[:60]
		s = strings.TrimRight(s, "-")
	}
	if len(s) < 2 {
		s = s + "0"
	}
	return s
}

// extID builds "<provider>:<source_id>" — the idempotency key we round-trip
// to the management-api on every record.
func extID(provider, sourceID string) string {
	if sourceID == "" {
		return ""
	}
	return provider + ":" + sourceID
}

// normEmail lowercases + trims. Returns "" for clearly invalid inputs so
// the caller can skip them.
func normEmail(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.Contains(s, "@") {
		return ""
	}
	return s
}

// mapAuth0Role translates source-provider role names into Authio's
// canonical role vocabulary (owner|admin|member). Anything unknown maps
// to "member" — the spec leans conservative on privilege.
func mapRole(sourceRole string) string {
	switch strings.ToLower(strings.TrimSpace(sourceRole)) {
	case "owner", "org_owner", "tenant_admin", "super_admin", "superadmin":
		return "owner"
	case "admin", "administrator", "org_admin", "stytch_admin":
		return "admin"
	case "member", "user", "stytch_member", "":
		return "member"
	default:
		return "member"
	}
}

// addWarning appends a unique warning to the plan.
func (p *ImportPlan) addWarning(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	for _, w := range p.Warnings {
		if w == msg {
			return
		}
	}
	p.Warnings = append(p.Warnings, msg)
	p.Stats.Warnings++
}

// ==========================================================================
// dispatch — provider key -> PlanParser
// ==========================================================================

var planParsers = map[string]PlanParser{
	"auth0":    auth0PlanParser{},
	"clerk":    clerkPlanParser{},
	"cognito":  cognitoPlanParser{},
	"firebase": firebasePlanParser{},
	"supabase": supabasePlanParser{},
	"workos":   workosPlanParser{},
	"stytch":   stytchPlanParser{},
	"descope":  descopePlanParser{},
}

// PlanParserFor returns the registered PlanParser for the given provider
// key, or nil + a helpful error.
func PlanParserFor(provider string) (PlanParser, error) {
	p, ok := planParsers[strings.ToLower(provider)]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (auth0|clerk|cognito|firebase|supabase|workos|stytch|descope)", provider)
	}
	return p, nil
}
