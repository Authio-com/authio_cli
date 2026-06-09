package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// workosLivePuller paginates through WorkOS Admin endpoints and bundles
// them into a workosBundle, then delegates to workosPlanParser to do
// the merge logic + SSO/SCIM mapping. That keeps the file-based and
// live-based code paths identical past the network layer.
type workosLivePuller struct{}

func (workosLivePuller) Name() string { return "workos" }

func (workosLivePuller) PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error) {
	key := creds.APIKey
	if key == "" {
		key = creds.SecretKey
	}
	if key == "" {
		return nil, fmt.Errorf("workos: missing api_key (sk_live_…)")
	}
	base := "https://api.workos.com"
	if opts.BaseURLOverride != "" {
		base = strings.TrimRight(opts.BaseURLOverride, "/")
	}
	h := newLiveHTTP(opts, "workos")
	progress := opts.ProgressFn
	if progress == nil {
		progress = func(string, int) {}
	}

	bundle := workosBundle{}

	// Helper to paginate WorkOS list endpoints (their cursor field is
	// `after` and the response wraps in `{data:[…], list_metadata:{after}}`).
	pull := func(path string, extraQuery url.Values, into func(json.RawMessage) error) error {
		after := ""
		pages := 0
		for {
			if opts.MaxPages > 0 && pages >= opts.MaxPages {
				return nil
			}
			q := url.Values{}
			q.Set("limit", "100")
			if after != "" {
				q.Set("after", after)
			}
			for k, vs := range extraQuery {
				for _, v := range vs {
					q.Add(k, v)
				}
			}
			u := fmt.Sprintf("%s%s?%s", base, path, q.Encode())
			body, err := bearerGet(ctx, h, u, key)
			if err != nil {
				return err
			}
			var wrap struct {
				Data         json.RawMessage `json:"data"`
				ListMetadata struct {
					After string `json:"after"`
				} `json:"list_metadata"`
			}
			if err := json.Unmarshal(body, &wrap); err != nil {
				return err
			}
			if err := into(wrap.Data); err != nil {
				return err
			}
			pages++
			if wrap.ListMetadata.After == "" {
				return nil
			}
			after = wrap.ListMetadata.After
		}
	}

	// Users
	if err := pull("/user_management/users", nil, func(raw json.RawMessage) error {
		var page []workosUser
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		bundle.Users = append(bundle.Users, page...)
		progress("users", len(bundle.Users))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("workos users: %w", err)
	}

	// Organizations
	if err := pull("/organizations", nil, func(raw json.RawMessage) error {
		var page []workosOrganization
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		bundle.Organizations = append(bundle.Organizations, page...)
		progress("orgs", len(bundle.Organizations))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("workos organizations: %w", err)
	}

	// Memberships — WorkOS requires organization_id or user_id; list per org.
	for _, org := range bundle.Organizations {
		q := url.Values{}
		q.Set("organization_id", org.ID)
		if err := pull("/user_management/organization_memberships", q, func(raw json.RawMessage) error {
			var page []workosMembership
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			bundle.OrganizationMemberships = append(bundle.OrganizationMemberships, page...)
			progress("memberships", len(bundle.OrganizationMemberships))
			return nil
		}); err != nil {
			return nil, fmt.Errorf("workos memberships (org %s): %w", org.ID, err)
		}
	}

	// SSO connections
	if err := pull("/connections", nil, func(raw json.RawMessage) error {
		var page []workosSsoConnection
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		bundle.SsoConnections = append(bundle.SsoConnections, page...)
		progress("sso", len(bundle.SsoConnections))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("workos sso: %w", err)
	}

	// SCIM directories
	if err := pull("/directories", nil, func(raw json.RawMessage) error {
		var page []workosDirectory
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		bundle.Directories = append(bundle.Directories, page...)
		progress("scim", len(bundle.Directories))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("workos directories: %w", err)
	}

	// Hand off to the existing file-based parser. It performs the
	// 1-user-1-org merge + SSO/SCIM mapping; sharing it guarantees
	// behavior parity between live and file paths.
	buf, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	return workosPlanParser{}.ParsePlan(ctx, strings.NewReader(string(buf)), PlanOptions{MergeDuplicateEmails: true})
}
