package clearance

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"testing"
)

func TestPKCE_VerifierAndChallenge(t *testing.T) {
	v, err := NewCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7636 §4.1: 43–128 chars from the unreserved set.
	if len(v) < 43 || len(v) > 128 || !regexp.MustCompile(`^[A-Za-z0-9._~-]+$`).MatchString(v) {
		t.Fatalf("verifier out of spec: %q", v)
	}
	want := base64.RawURLEncoding.EncodeToString(func() []byte { s := sha256.Sum256([]byte(v)); return s[:] }())
	if got := ChallengeS256(v); got != want {
		t.Fatalf("challenge = %q want %q", got, want)
	}
	// RFC 7636 appendix B vector.
	if got := ChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("appendix B vector mismatch: %q", got)
	}
	v2, _ := NewCodeVerifier()
	if v2 == v {
		t.Fatal("verifiers must be random")
	}
	s, _ := NewState()
	if len(s) < 16 {
		t.Fatalf("state too short: %q", s)
	}
}
