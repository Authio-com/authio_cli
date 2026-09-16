package clearance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// PKCE (RFC 7636) S256. The verifier is 32 random bytes, base64url without
// padding (43 chars, inside the 43–128 range); the challenge is the
// base64url SHA-256 of the verifier's ASCII bytes.

func NewCodeVerifier() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func NewState() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
