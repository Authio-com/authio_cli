package cmd

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// firebaseLivePuller uses the Identity Toolkit REST API with a service-
// account JWT (stdlib-only). Maps users into the same ImportPlan shape
// as firebasePlanParser.
type firebaseLivePuller struct{}

func (firebaseLivePuller) Name() string { return "firebase" }

func (firebaseLivePuller) PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error) {
	saJSON := strings.TrimSpace(creds.ServiceAccountJSON)
	if saJSON == "" {
		return nil, fmt.Errorf("firebase: missing service_account_json")
	}
	var sa struct {
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return nil, fmt.Errorf("firebase: parse service account: %w", err)
	}
	if sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("firebase: service account missing project_id, client_email, or private_key")
	}

	token, err := googleAccessToken(ctx, sa.ClientEmail, sa.PrivateKey,
		"https://www.googleapis.com/auth/identitytoolkit")
	if err != nil {
		return nil, fmt.Errorf("firebase: oauth token: %w", err)
	}

	base := "https://identitytoolkit.googleapis.com"
	if opts.BaseURLOverride != "" {
		base = strings.TrimRight(opts.BaseURLOverride, "/")
	}
	h := newLiveHTTP(opts, "firebase")
	progress := opts.ProgressFn
	if progress == nil {
		progress = func(string, int) {}
	}

	plan := &ImportPlan{Provider: "firebase"}
	users := newUserIndex(true)
	defaultOrgName := "Default"
	defaultOrgExt := extID("firebase", "org:default")
	plan.Orgs = append(plan.Orgs, OrgRecord{
		ExternalID: defaultOrgExt,
		Name:       defaultOrgName,
		Slug:       slugify(defaultOrgName),
	})
	tenants := map[string]string{}

	offset := 0
	pages := 0
	totalUsers := 0
	for {
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			break
		}
		endpoint := fmt.Sprintf("%s/v1/projects/%s/accounts:query", base, sa.ProjectID)
		body, err := json.Marshal(map[string]any{
			"returnUserInfo": true,
			"limit":          1000,
			"offset":         offset,
		})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token) // AUTHIO_REDACT
		req.Header.Set("Content-Type", "application/json")
		resp, err := h.Do(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("firebase accounts:query offset %d: %w", offset, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, &statusErr{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
		}
		var wrap struct {
			UserInfo []firebaseRecord `json:"userInfo"`
		}
		if err := json.Unmarshal(b, &wrap); err != nil {
			return nil, fmt.Errorf("firebase decode: %w", err)
		}
		if len(wrap.UserInfo) == 0 {
			break
		}
		for _, rec := range wrap.UserInfo {
			plan.Stats.SourceUsers++
			if rec.Disabled {
				continue
			}
			email := normEmail(rec.Email)
			if email == "" {
				continue
			}
			orgExt := defaultOrgExt
			if rec.TenantID != "" {
				if ext, ok := tenants[rec.TenantID]; ok {
					orgExt = ext
				} else {
					ext = extID("firebase", "tenant:"+rec.TenantID)
					tenants[rec.TenantID] = ext
					plan.Orgs = append(plan.Orgs, OrgRecord{
						ExternalID: ext,
						Name:       rec.TenantID,
						Slug:       slugify(rec.TenantID),
					})
					orgExt = ext
				}
			}
			meta := map[string]any{}
			if rec.CustomAttributes != "" {
				var claims map[string]any
				if json.Unmarshal([]byte(rec.CustomAttributes), &claims) == nil {
					meta["claims"] = claims
				}
			}
			users.upsert(UserRecord{
				ExternalID:            extID("firebase", rec.LocalID),
				Email:                 email,
				EmailVerified:         rec.EmailVerified,
				Name:                  rec.DisplayName,
				AvatarURL:             rec.PhotoURL,
				Metadata:              meta,
				MigrationPendingEmail: true,
				MfaEnrolled:           len(rec.MfaInfo) > 0,
				SourceExternalIDs:     []string{extID("firebase", rec.LocalID)},
			})
			for _, p := range rec.ProviderUserInfo {
				kind := mapFirebaseProvider(p.ProviderID)
				subject := p.RawID
				if subject == "" {
					subject = p.FederatedID
				}
				if kind == "" || subject == "" {
					continue
				}
				plan.Identities = append(plan.Identities, IdentityRecord{
					UserExternalID: extID("firebase", rec.LocalID),
					Kind:           kind,
					Subject:        subject,
				})
			}
			plan.Memberships = append(plan.Memberships, MembershipRecord{
				UserExternalID: extID("firebase", rec.LocalID),
				OrgExternalID:  orgExt,
				Role:           "member",
				Status:         "active",
			})
			totalUsers++
		}
		progress("users", totalUsers)
		offset += len(wrap.UserInfo)
		pages++
		if len(wrap.UserInfo) < 1000 {
			break
		}
	}

	plan.Users = users.list()
	plan.Stats.MergedUsers = users.merged
	return plan, nil
}

func mapFirebaseProvider(id string) string {
	switch id {
	case "google.com":
		return "oauth_google"
	case "facebook.com":
		return "oauth_facebook"
	case "apple.com":
		return "oauth_apple"
	case "github.com":
		return "oauth_github"
	case "twitter.com":
		return "oauth_twitter"
	case "microsoft.com":
		return "oauth_microsoft"
	case "password", "phone":
		return ""
	default:
		if id == "" {
			return ""
		}
		return "oauth_" + strings.ReplaceAll(id, ".", "_")
	}
}

func googleAccessToken(ctx context.Context, clientEmail, privateKeyPEM, scope string) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":   clientEmail,
		"sub":   clientEmail,
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"scope": scope,
	}
	assertion, err := signServiceAccountJWT(claims, privateKeyPEM)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange: %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token exchange: empty access_token")
	}
	return tok.AccessToken, nil
}

func signServiceAccountJWT(claims map[string]any, privateKeyPEM string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid private_key PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		keyAny, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private_key is not RSA")
	}
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
