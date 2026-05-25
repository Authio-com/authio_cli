package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// cognitoLivePuller uses the Cognito Identity Provider JSON API with
// AWS SigV4 signing (stdlib-only). Maps users, groups, and memberships
// identically to cognitoPlanParser.
type cognitoLivePuller struct{}

func (cognitoLivePuller) Name() string { return "cognito" }

func (cognitoLivePuller) PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error) {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("cognito: missing access_key_id / secret_access_key")
	}
	region := strings.TrimSpace(creds.Region)
	if region == "" {
		return nil, fmt.Errorf("cognito: region is required")
	}
	poolID := strings.TrimSpace(creds.UserPoolID)
	if poolID == "" {
		return nil, fmt.Errorf("cognito: user_pool_id is required")
	}

	host := fmt.Sprintf("cognito-idp.%s.amazonaws.com", region)
	signer := newAWSSigV4(creds.AccessKeyID, creds.SecretAccessKey, region, "cognito-idp")
	h := newLiveHTTP(opts, "cognito")
	progress := opts.ProgressFn
	if progress == nil {
		progress = func(string, int) {}
	}

	plan := &ImportPlan{Provider: "cognito"}
	users := newUserIndex(true)
	orgs := map[string]*OrgRecord{}
	groupMeta := map[string]cognitoGroup{}

	// ---- Groups (become Authio orgs) ----
	nextToken := ""
	pages := 0
	for {
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			break
		}
		body := map[string]any{"UserPoolId": poolID, "Limit": 60}
		if nextToken != "" {
			body["NextToken"] = nextToken
		}
		raw, err := cognitoCall(ctx, h, signer, host,
			"AWSCognitoIdentityProviderService.ListGroups", body)
		if err != nil {
			return nil, fmt.Errorf("cognito list-groups: %w", err)
		}
		var resp struct {
			Groups    []cognitoGroup `json:"Groups"`
			NextToken string         `json:"NextToken"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("cognito list-groups decode: %w", err)
		}
		for _, g := range resp.Groups {
			if g.GroupName == "" {
				continue
			}
			groupMeta[g.GroupName] = g
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
		}
		nextToken = resp.NextToken
		pages++
		if nextToken == "" {
			break
		}
	}

	// ---- Users ----
	nextToken = ""
	pages = 0
	totalUsers := 0
	for {
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			plan.addWarning("cognito: hit --max-pages=%d on users", opts.MaxPages)
			break
		}
		body := map[string]any{"UserPoolId": poolID, "Limit": 60}
		if nextToken != "" {
			body["PaginationToken"] = nextToken
		}
		raw, err := cognitoCall(ctx, h, signer, host,
			"AWSCognitoIdentityProviderService.ListUsers", body)
		if err != nil {
			return nil, fmt.Errorf("cognito list-users: %w", err)
		}
		var resp struct {
			Users           []cognitoRecord `json:"Users"`
			PaginationToken string          `json:"PaginationToken"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("cognito list-users decode: %w", err)
		}
		for _, rec := range resp.Users {
			plan.Stats.SourceUsers++
			enabled := rec.Enabled == nil || *rec.Enabled
			if !enabled {
				continue
			}
			if rec.UserStatus != "" && rec.UserStatus != "CONFIRMED" && rec.UserStatus != "EXTERNAL_PROVIDER" {
				continue
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
				case a.Name == "sub":
					sub = a.Value
					meta["sub"] = a.Value
				case strings.HasPrefix(a.Name, "custom:"):
					custom[strings.TrimPrefix(a.Name, "custom:")] = a.Value
				}
			}
			if len(custom) > 0 {
				meta["custom"] = custom
			}
			email = normEmail(email)
			if email == "" {
				continue
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

			// Group memberships for this user.
			groupsRaw, err := cognitoCall(ctx, h, signer, host,
				"AWSCognitoIdentityProviderService.AdminListGroupsForUser", map[string]any{
					"UserPoolId": poolID,
					"Username":   rec.Username,
					"Limit":      60,
				})
			if err != nil {
				plan.addWarning("cognito: groups for %s: %v", rec.Username, err)
				continue
			}
			var gResp struct {
				Groups []struct {
					GroupName string `json:"GroupName"`
					RoleArn   string `json:"RoleArn"`
				} `json:"Groups"`
			}
			if err := json.Unmarshal(groupsRaw, &gResp); err != nil {
				continue
			}
			for _, g := range gResp.Groups {
				if g.GroupName == "" {
					continue
				}
				ext := extID("cognito", "group:"+g.GroupName)
				if _, exists := orgs[ext]; !exists {
					meta := groupMeta[g.GroupName]
					name := meta.Description
					if name == "" {
						name = g.GroupName
					}
					orgs[ext] = &OrgRecord{
						ExternalID: ext,
						Name:       name,
						Slug:       slugify(g.GroupName),
					}
				}
				role := mapRole(groupMeta[g.GroupName].Role)
				plan.Memberships = append(plan.Memberships, MembershipRecord{
					UserExternalID: extID("cognito", rec.Username),
					OrgExternalID:  ext,
					Role:           role,
					Status:         "active",
				})
			}
			totalUsers++
		}
		progress("users", totalUsers)
		nextToken = resp.PaginationToken
		pages++
		if nextToken == "" {
			break
		}
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	for _, o := range orgs {
		plan.Orgs = append(plan.Orgs, *o)
	}
	return plan, nil
}

func cognitoCall(
	ctx context.Context,
	h *liveHTTP,
	signer *awsSigV4,
	host, target string,
	body map[string]any,
) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := signer.postJSON(target, host, payload)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	resp, err := h.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, &statusErr{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	return b, nil
}
