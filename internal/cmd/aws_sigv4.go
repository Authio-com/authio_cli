package cmd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// awsSigV4 signs JSON POST requests to AWS service endpoints (Cognito,
// etc.) using the standard SigV4 algorithm. Stdlib-only — no AWS SDK.
type awsSigV4 struct {
	accessKeyID     string
	secretAccessKey string
	region          string
	service         string
}

func newAWSSigV4(accessKeyID, secretAccessKey, region, service string) *awsSigV4 {
	return &awsSigV4{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		region:          region,
		service:         service,
	}
}

func (s *awsSigV4) postJSON(
	target string,
	host string,
	body []byte,
) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, "https://"+host+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Host", host)

	canonicalHeaders := fmt.Sprintf(
		"content-type:application/x-amz-json-1.1\nhost:%s\nx-amz-date:%s\nx-amz-target:%s\n",
		host, amzDate, target,
	)
	signedHeaders := "content-type;host;x-amz-date;x-amz-target"
	payloadHash := sha256Hex(body)
	canonicalRequest := strings.Join([]string{
		"POST",
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, s.region, s.service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := s.deriveSigningKey(dateStamp)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKeyID, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", auth)
	return req, nil
}

func (s *awsSigV4) deriveSigningKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+s.secretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(s.region))
	kService := hmacSHA256(kRegion, []byte(s.service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
