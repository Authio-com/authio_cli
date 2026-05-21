package clerk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, name string, out any) {
	t.Helper()
	path := filepath.Join("fixtures", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
}

func TestTransformUser_FullMapping(t *testing.T) {
	var users []ClerkUser
	loadFixture(t, "users_page1.json", &users)
	if len(users) < 1 {
		t.Fatal("expected at least one user in fixture")
	}
	ada := users[0]
	got, _, ok := TransformUser(ada, TransformOptions{
		IncludeOAuthBindings: true,
		IncludeMFA:           true,
	})
	if !ok {
		t.Fatalf("expected ada to be importable")
	}
	if got.Email != "ada@example.com" {
		t.Errorf("email=%q", got.Email)
	}
	if !got.EmailVerified {
		t.Errorf("expected email_verified=true")
	}
	if got.EmailVerifiedAt == nil {
		t.Errorf("expected email_verified_at to be populated when verified")
	}
	if got.PhoneE164 != "+15555550100" {
		t.Errorf("phone_e164=%q", got.PhoneE164)
	}
	if got.PhoneVerifiedAt == nil {
		t.Errorf("expected phone_verified_at when verified")
	}
	if got.Name != "Ada Lovelace" {
		t.Errorf("name=%q", got.Name)
	}
	if got.AvatarURL != "https://img.clerk.com/ada.png" {
		t.Errorf("avatar=%q", got.AvatarURL)
	}
	if got.CreatedAt == nil {
		t.Errorf("expected created_at to be set")
	}
	if got.LastSignInAt == nil {
		t.Errorf("expected last_sign_in_at to be set")
	}
	if got.Metadata["clerk_user_id"] != "user_2NfABCdef" {
		t.Errorf("metadata.clerk_user_id=%v", got.Metadata["clerk_user_id"])
	}
	if got.Metadata["clerk_public_metadata"] == nil {
		t.Errorf("expected clerk_public_metadata to be preserved")
	}
	if got.Metadata["clerk_private_metadata"] == nil {
		t.Errorf("expected clerk_private_metadata to be preserved")
	}
	if len(got.Identities) != 1 {
		t.Fatalf("identities count=%d want 1", len(got.Identities))
	}
	if got.Identities[0].Kind != "oauth_google" {
		t.Errorf("oauth kind=%q", got.Identities[0].Kind)
	}
	if got.Identities[0].Subject != "100100100" {
		t.Errorf("oauth subject=%q", got.Identities[0].Subject)
	}
	if len(got.WebAuthnCredentials) != 1 {
		t.Fatalf("webauthn count=%d want 1", len(got.WebAuthnCredentials))
	}
	if got.WebAuthnCredentials[0].CredentialID != "Y3JlZF9hYmM" {
		t.Errorf("webauthn credential_id=%q", got.WebAuthnCredentials[0].CredentialID)
	}
	if got.WebAuthnCredentials[0].SignCount != 12 {
		t.Errorf("webauthn sign_count=%d", got.WebAuthnCredentials[0].SignCount)
	}
	// Three MFA factors expected: totp + backup_code + sms (verified phone).
	if len(got.MFAFactors) != 3 {
		t.Fatalf("mfa factors=%d want 3", len(got.MFAFactors))
	}
	kinds := map[string]bool{}
	for _, m := range got.MFAFactors {
		kinds[m.Kind] = true
	}
	for _, k := range []string{"totp", "backup_code", "sms"} {
		if !kinds[k] {
			t.Errorf("missing MFA kind: %s", k)
		}
	}
}

func TestTransformUser_FallbacksToUsername(t *testing.T) {
	var users []ClerkUser
	loadFixture(t, "users_page1.json", &users)
	grace := users[1]
	got, _, ok := TransformUser(grace, TransformOptions{IncludeOAuthBindings: true})
	if !ok {
		t.Fatalf("expected grace to import")
	}
	if got.Name != "grace_h" {
		t.Errorf("expected fallback to username, got %q", got.Name)
	}
	if got.AvatarURL != "" {
		t.Errorf("expected empty avatar_url, got %q", got.AvatarURL)
	}
	// No private/public metadata to preserve.
	if _, ok := got.Metadata["clerk_public_metadata"]; ok {
		t.Errorf("public_metadata should not be preserved when null in source")
	}
}

func TestTransformUser_SkipsBanned(t *testing.T) {
	var users []ClerkUser
	loadFixture(t, "users_page1.json", &users)
	banned := users[2]
	_, reason, ok := TransformUser(banned, TransformOptions{})
	if ok {
		t.Fatal("expected banned user to be skipped")
	}
	if reason == "" {
		t.Fatal("expected non-empty skip reason")
	}
}

func TestTransformUser_SkipsNoEmail(t *testing.T) {
	var users []ClerkUser
	loadFixture(t, "users_page1.json", &users)
	noEmail := users[3]
	_, reason, ok := TransformUser(noEmail, TransformOptions{})
	if ok {
		t.Fatal("expected no-email user to be skipped")
	}
	if reason == "" {
		t.Fatal("expected non-empty skip reason")
	}
}

func TestTransformUser_OAuthDisabled(t *testing.T) {
	var users []ClerkUser
	loadFixture(t, "users_page1.json", &users)
	ada := users[0]
	got, _, ok := TransformUser(ada, TransformOptions{IncludeOAuthBindings: false, IncludeMFA: false})
	if !ok {
		t.Fatal("expected ada to import")
	}
	if len(got.Identities) != 0 {
		t.Errorf("expected zero identities when oauth bindings disabled, got %d", len(got.Identities))
	}
	if len(got.MFAFactors) != 0 {
		t.Errorf("expected zero mfa factors when MFA disabled, got %d", len(got.MFAFactors))
	}
	// Passkeys are still imported (Clerk's CBOR pub-key is interop-compatible).
	if len(got.WebAuthnCredentials) != 1 {
		t.Errorf("expected webauthn to import regardless of mfa flag, got %d", len(got.WebAuthnCredentials))
	}
}

func TestTransformOrganization(t *testing.T) {
	var body struct {
		Data []ClerkOrganization `json:"data"`
	}
	loadFixture(t, "organizations.json", &body)
	if len(body.Data) < 2 {
		t.Fatal("expected two orgs in fixture")
	}
	acme := TransformOrganization(body.Data[0])
	if acme.ClerkOrgID != "org_acme" {
		t.Errorf("clerk_org_id=%q", acme.ClerkOrgID)
	}
	if acme.Name != "Acme Corp" {
		t.Errorf("name=%q", acme.Name)
	}
	if acme.Slug != "acme-corp" {
		t.Errorf("slug=%q", acme.Slug)
	}
	if acme.LogoURL != "https://img.clerk.com/orgs/acme.png" {
		t.Errorf("logo=%q", acme.LogoURL)
	}
	if acme.CreatedAt == nil {
		t.Errorf("expected created_at to be set")
	}
	if acme.Metadata["clerk_org_id"] != "org_acme" {
		t.Errorf("expected metadata.clerk_org_id")
	}

	// org_globex has only image_url, no logo_url. The transform should
	// fall back to image_url.
	globex := TransformOrganization(body.Data[1])
	if globex.LogoURL != "https://img.clerk.com/orgs/globex.png" {
		t.Errorf("expected fallback to image_url for logo, got %q", globex.LogoURL)
	}
}

func TestTransformOrganization_SlugifiesUnsafeInput(t *testing.T) {
	o := ClerkOrganization{ID: "org_x", Name: "Café del Mar!!!", Slug: ""}
	got := TransformOrganization(o)
	// Slugify should strip non-ASCII + punctuation.
	if got.Slug == "" {
		t.Fatal("expected non-empty slug")
	}
	for _, r := range got.Slug {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			t.Errorf("slug has invalid char %q in %q", r, got.Slug)
		}
	}
}

func TestTransformMembership(t *testing.T) {
	var rows []ClerkMembership
	loadFixture(t, "memberships_acme.json", &rows)
	if len(rows) < 2 {
		t.Fatal("expected two memberships")
	}
	adminRow := rows[0]
	got := TransformMembership(adminRow)
	if got.Role != "owner" {
		t.Errorf("expected admin -> owner, got %q", got.Role)
	}
	if got.ClerkUserID != "user_2NfABCdef" {
		t.Errorf("user_id=%q", got.ClerkUserID)
	}
	if got.Status != "active" {
		t.Errorf("status=%q", got.Status)
	}

	memberRow := rows[1]
	got = TransformMembership(memberRow)
	if got.Role != "member" {
		t.Errorf("expected basic_member -> member, got %q", got.Role)
	}
}

func TestMapClerkProvider(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"oauth_google", "oauth_google"},
		{"google", "oauth_google"},
		{"oauth_github", "oauth_github"},
		{"oauth_x", "oauth_twitter"},
		{"saml", "saml_clerk"},
		{"oauth_zoom", "oauth_zoom"},
		{"custom", "oauth_custom"},
		{"", ""},
	}
	for _, c := range cases {
		if got := MapClerkProvider(c.in); got != c.want {
			t.Errorf("MapClerkProvider(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestMapClerkRole(t *testing.T) {
	cases := []struct{ in, want string }{
		{"admin", "owner"},
		{"org:admin", "owner"},
		{"basic_member", "member"},
		{"org:basic_member", "member"},
		{"manager", "admin"},
		{"unknown_role", "member"},
		{"", "member"},
	}
	for _, c := range cases {
		if got := MapClerkRole(c.in); got != c.want {
			t.Errorf("MapClerkRole(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
