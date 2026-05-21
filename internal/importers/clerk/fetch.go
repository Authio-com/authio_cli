package clerk

import (
	"context"
	"encoding/json"
	"fmt"
)

// PageSize is the limit used on every Clerk paginated GET.
// Clerk caps `/v1/users` at 500/page and `/v1/organizations` + their
// memberships at 100/page.
const (
	UsersPageSize         = 500
	OrganizationsPageSize = 100
	MembershipsPageSize   = 100
)

// UserPage is one page of `GET /v1/users`. Clerk historically returned a
// bare JSON array but, on certain plans, wraps the response in
// `{data: [...], total_count: N}`. We accept either via decodeUsersPage.
type UserPage struct {
	Users []ClerkUser
	// Total is the server-reported total when present (wrapped form),
	// or 0 when unknown.
	Total int
}

// OrgPage is one page of `GET /v1/organizations`.
type OrgPage struct {
	Orgs  []ClerkOrganization
	Total int
}

// MembershipPage is one page of `GET /v1/organizations/{id}/memberships`.
type MembershipPage struct {
	Memberships []ClerkMembership
	Total       int
}

// FetchUsersPage pulls one page starting at offset.
func (c *ClerkClient) FetchUsersPage(ctx context.Context, offset int) (UserPage, error) {
	path := fmt.Sprintf("/v1/users?limit=%d&offset=%d&order_by=-created_at", UsersPageSize, offset)
	raw, err := c.Get(ctx, path)
	if err != nil {
		return UserPage{}, err
	}
	return decodeUsersPage(raw)
}

// FetchOrganizationsPage pulls one page starting at offset.
func (c *ClerkClient) FetchOrganizationsPage(ctx context.Context, offset int) (OrgPage, error) {
	path := fmt.Sprintf("/v1/organizations?limit=%d&offset=%d", OrganizationsPageSize, offset)
	raw, err := c.Get(ctx, path)
	if err != nil {
		return OrgPage{}, err
	}
	return decodeOrgsPage(raw)
}

// FetchMembershipsPage pulls one page for `orgID` starting at offset.
func (c *ClerkClient) FetchMembershipsPage(ctx context.Context, orgID string, offset int) (MembershipPage, error) {
	path := fmt.Sprintf("/v1/organizations/%s/memberships?limit=%d&offset=%d", orgID, MembershipsPageSize, offset)
	raw, err := c.Get(ctx, path)
	if err != nil {
		return MembershipPage{}, err
	}
	return decodeMembershipsPage(raw)
}

// IterateUsers calls cb once per fetched page. The walk stops when a
// page returns fewer than UsersPageSize rows, or when cb returns false.
// startOffset is the initial offset — non-zero when resuming.
func (c *ClerkClient) IterateUsers(ctx context.Context, startOffset int, cb func(page UserPage, offset int) (bool, error)) error {
	offset := startOffset
	for {
		page, err := c.FetchUsersPage(ctx, offset)
		if err != nil {
			return err
		}
		cont, err := cb(page, offset)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
		if len(page.Users) < UsersPageSize {
			return nil
		}
		offset += UsersPageSize
	}
}

// IterateOrganizations calls cb once per fetched page.
func (c *ClerkClient) IterateOrganizations(ctx context.Context, startOffset int, cb func(page OrgPage, offset int) (bool, error)) error {
	offset := startOffset
	for {
		page, err := c.FetchOrganizationsPage(ctx, offset)
		if err != nil {
			return err
		}
		cont, err := cb(page, offset)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
		if len(page.Orgs) < OrganizationsPageSize {
			return nil
		}
		offset += OrganizationsPageSize
	}
}

// IterateMemberships calls cb once per fetched page for the given org.
func (c *ClerkClient) IterateMemberships(ctx context.Context, orgID string, cb func(page MembershipPage, offset int) (bool, error)) error {
	offset := 0
	for {
		page, err := c.FetchMembershipsPage(ctx, orgID, offset)
		if err != nil {
			return err
		}
		cont, err := cb(page, offset)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
		if len(page.Memberships) < MembershipsPageSize {
			return nil
		}
		offset += MembershipsPageSize
	}
}

// ---------------------------------------------------------------------
// Decoders — handle both the bare-array and wrapped {data:[…]} forms.
// ---------------------------------------------------------------------

func decodeUsersPage(raw []byte) (UserPage, error) {
	var bare []ClerkUser
	if err := json.Unmarshal(raw, &bare); err == nil {
		return UserPage{Users: bare}, nil
	}
	var wrapped struct {
		Data       []ClerkUser `json:"data"`
		TotalCount int         `json:"total_count"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return UserPage{}, fmt.Errorf("decode users page: %w", err)
	}
	return UserPage{Users: wrapped.Data, Total: wrapped.TotalCount}, nil
}

func decodeOrgsPage(raw []byte) (OrgPage, error) {
	var bare []ClerkOrganization
	if err := json.Unmarshal(raw, &bare); err == nil {
		return OrgPage{Orgs: bare}, nil
	}
	var wrapped struct {
		Data       []ClerkOrganization `json:"data"`
		TotalCount int                 `json:"total_count"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return OrgPage{}, fmt.Errorf("decode organizations page: %w", err)
	}
	return OrgPage{Orgs: wrapped.Data, Total: wrapped.TotalCount}, nil
}

func decodeMembershipsPage(raw []byte) (MembershipPage, error) {
	var bare []ClerkMembership
	if err := json.Unmarshal(raw, &bare); err == nil {
		return MembershipPage{Memberships: bare}, nil
	}
	var wrapped struct {
		Data       []ClerkMembership `json:"data"`
		TotalCount int               `json:"total_count"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return MembershipPage{}, fmt.Errorf("decode memberships page: %w", err)
	}
	return MembershipPage{Memberships: wrapped.Data, Total: wrapped.TotalCount}, nil
}
