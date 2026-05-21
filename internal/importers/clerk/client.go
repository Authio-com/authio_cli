// Package clerk is the dedicated Clerk -> Authio importer used by
// `authio import clerk --secret-key sk_live_... --authio-project proj_...`.
//
// Why this lives in internal/importers/clerk and not in internal/cmd:
//
//   internal/cmd/import_provider_clerk.go and import_live_clerk.go feed
//   the migrate-wizard plan-builder + plan-runner pipeline. They emit a
//   generic ImportPlan that flows through the cross-provider PlanRunner
//   in internal/cmd/import_plan_runner.go.
//
//   This package is the customer-facing, Clerk-specific surface: it
//   takes a Clerk Secret Key and an Authio api-key, pulls users +
//   organizations + memberships + OAuth bindings + MFA factors from
//   Clerk's Backend API, and writes them via the management-api's bulk
//   migration endpoints. State is checkpointed to disk so a killed run
//   resumes. Failed rows are recorded in a CSV report.
//
//   The two paths share zero state at runtime, but transform.go's role-
//   mapping mirrors import_provider_clerk.go's so a wizard-driven and
//   CLI-driven import of the same Clerk tenant produce identical Authio
//   rows.
//
// AUTHIO_REDACT — both creds.SecretKey (Clerk) and creds.AuthioAPIKey
// are high-risk secrets. Never log either; never include them in error
// messages or progress events.
package clerk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultClerkBaseURL is Clerk's public Backend API. The Importer lets
// callers override this for tests via Options.ClerkBaseURL.
const DefaultClerkBaseURL = "https://api.clerk.com"

// DefaultRateLimit caps reads from Clerk + writes to Authio. Clerk's
// public rate limit is 1000 req/min on the Backend API; 50/sec leaves
// plenty of headroom for retries.
const DefaultRateLimit = 50.0

// ClerkClient is a thin wrapper around http.Client with:
//   - Bearer authentication via the Clerk Secret Key.
//   - Token-bucket rate limiting (default DefaultRateLimit).
//   - Retry on 429/5xx that honors Retry-After.
//   - Exponential backoff with jitter for transport errors.
type ClerkClient struct {
	BaseURL    string
	SecretKey  string
	HTTPClient *http.Client
	Limiter    *RateLimiter
	UserAgent  string
	MaxRetries int
}

// NewClerkClient builds a client with sane defaults. baseURL == "" picks
// DefaultClerkBaseURL.
func NewClerkClient(secretKey, baseURL string, rate float64) *ClerkClient {
	if baseURL == "" {
		baseURL = DefaultClerkBaseURL
	}
	if rate <= 0 {
		rate = DefaultRateLimit
	}
	return &ClerkClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		SecretKey:  secretKey,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Limiter:    NewRateLimiter(rate),
		UserAgent:  "authio-cli-import-clerk/0.1",
		MaxRetries: 3,
	}
}

// Get performs a GET against the Clerk API. Path is relative and
// includes the query string. Returns the response body bytes on 2xx.
func (c *ClerkClient) Get(ctx context.Context, path string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, path, nil)
}

func (c *ClerkClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	url := c.BaseURL + path
	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.SecretKey) // AUTHIO_REDACT
		req.Header.Set("User-Agent", c.UserAgent)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			sleepBackoff(ctx, attempt)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return raw, nil
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			ra := parseRetryAfter(resp.Header.Get("Retry-After"))
			if ra > 0 {
				if err := sleepCtx(ctx, ra); err != nil {
					return nil, err
				}
			} else {
				sleepBackoff(ctx, attempt)
			}
			lastErr = &ClerkAPIError{Status: resp.StatusCode, Body: trimBody(raw)}
			continue
		}
		return nil, &ClerkAPIError{Status: resp.StatusCode, Body: trimBody(raw)}
	}
	if lastErr == nil {
		lastErr = errors.New("clerk: exhausted retries")
	}
	return nil, lastErr
}

// ClerkAPIError is returned for non-2xx responses. The body is
// truncated so a 200-page-of-JSON 401 doesn't dump the world into a
// terminal.
type ClerkAPIError struct {
	Status int
	Body   string
}

func (e *ClerkAPIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("clerk api: status %d", e.Status)
	}
	return fmt.Sprintf("clerk api: status %d: %s", e.Status, e.Body)
}

// IsAuthError reports whether the error is an auth-like 401/403.
func IsAuthError(err error) bool {
	var e *ClerkAPIError
	if errors.As(err, &e) {
		return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
	}
	return false
}

// AuthioClient writes to the Authio management-api's bulk-migration
// endpoints (POST /v1/migrate/bulk-users, /v1/migrate/bulk-organizations,
// /v1/migrate/bulk-memberships). The endpoints are idempotent on the
// clerk_user_id / clerk_org_id metadata keys, so a re-run skips rows
// already imported.
type AuthioClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	Limiter    *RateLimiter
	UserAgent  string
	MaxRetries int
}

// NewAuthioClient builds an AuthioClient. apiURL falls back to the
// public management-api when empty.
func NewAuthioClient(apiURL, apiKey string, rate float64) *AuthioClient {
	if apiURL == "" {
		apiURL = "https://authiomanagement-api-production.up.railway.app"
	}
	if rate <= 0 {
		rate = DefaultRateLimit
	}
	return &AuthioClient{
		BaseURL:    strings.TrimRight(apiURL, "/"),
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Limiter:    NewRateLimiter(rate),
		UserAgent:  "authio-cli-import-clerk/0.1",
		MaxRetries: 3,
	}
}

// BulkResult is the per-row outcome returned by the bulk endpoints.
type BulkResult struct {
	SourceID string `json:"source_id"`
	AuthioID string `json:"authio_id,omitempty"`
	Status   string `json:"status"` // created | existed | error
	Error    string `json:"error,omitempty"`
}

// PostBulkUsers ships a batch of user objects. The endpoint inserts
// each row in a single transaction; per-row failures don't fail the
// batch.
func (a *AuthioClient) PostBulkUsers(ctx context.Context, rows []AuthioUserPayload) ([]BulkResult, error) {
	return a.postBulk(ctx, "/v1/migrate/bulk-users", map[string]any{"users": rows})
}

// PostBulkOrganizations ships a batch of organization objects.
func (a *AuthioClient) PostBulkOrganizations(ctx context.Context, rows []AuthioOrgPayload) ([]BulkResult, error) {
	return a.postBulk(ctx, "/v1/migrate/bulk-organizations", map[string]any{"organizations": rows})
}

// PostBulkMemberships ships a batch of membership rows. The endpoint
// resolves user_id and organization_id from the metadata keys on each
// row.
func (a *AuthioClient) PostBulkMemberships(ctx context.Context, rows []AuthioMembershipPayload) ([]BulkResult, error) {
	return a.postBulk(ctx, "/v1/migrate/bulk-memberships", map[string]any{"memberships": rows})
}

func (a *AuthioClient) postBulk(ctx context.Context, path string, payload any) ([]BulkResult, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt <= a.MaxRetries; attempt++ {
		if err := a.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+path, bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+a.APIKey) // AUTHIO_REDACT
		req.Header.Set("User-Agent", a.UserAgent)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := a.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			sleepBackoff(ctx, attempt)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var body struct {
				Results []BulkResult `json:"results"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				return nil, fmt.Errorf("authio bulk: decode %s: %w", path, err)
			}
			return body.Results, nil
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			ra := parseRetryAfter(resp.Header.Get("Retry-After"))
			if ra > 0 {
				if err := sleepCtx(ctx, ra); err != nil {
					return nil, err
				}
			} else {
				sleepBackoff(ctx, attempt)
			}
			lastErr = fmt.Errorf("authio bulk %s: status %d", path, resp.StatusCode)
			continue
		}
		return nil, fmt.Errorf("authio bulk %s: status %d: %s", path, resp.StatusCode, trimBody(raw))
	}
	if lastErr == nil {
		lastErr = errors.New("authio bulk: exhausted retries")
	}
	return nil, lastErr
}

// ---------------------------------------------------------------------
// Rate limiter — small token bucket. nowFunc + sleep are injectable so
// tests can verify pacing without wall-clock waits.
// ---------------------------------------------------------------------

// RateLimiter is a goroutine-safe token bucket emitting `rate` ops/sec
// with uniform spacing.
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

// NewRateLimiter builds a RateLimiter that emits at most `rate` ops/sec.
// A rate <= 0 falls back to DefaultRateLimit.
func NewRateLimiter(rate float64) *RateLimiter {
	if rate <= 0 {
		rate = DefaultRateLimit
	}
	return &RateLimiter{
		interval: time.Duration(float64(time.Second) / rate),
		now:      time.Now,
		sleep:    sleepCtx,
	}
}

// Wait blocks until the next token is available or ctx is cancelled.
func (l *RateLimiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := l.now()
	wait := time.Duration(0)
	if l.next.After(now) {
		wait = l.next.Sub(now)
		l.next = l.next.Add(l.interval)
	} else {
		l.next = now.Add(l.interval)
	}
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	return l.sleep(ctx, wait)
}

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

func parseRetryAfter(s string) time.Duration {
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		// Cap at 60s — a misconfigured upstream should not pin an
		// importer for hours.
		if n > 60 {
			n = 60
		}
		return time.Duration(n) * time.Second
	}
	// Clerk doesn't use HTTP-date Retry-After, but be lenient.
	if t, err := http.ParseTime(s); err == nil {
		d := time.Until(t)
		if d > 0 && d < 60*time.Second {
			return d
		}
	}
	return 0
}

func sleepBackoff(ctx context.Context, attempt int) {
	if attempt < 0 {
		attempt = 0
	}
	base := 250 * time.Millisecond
	d := base * time.Duration(1<<attempt)
	if d > 4*time.Second {
		d = 4 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(d / 4)))
	_ = sleepCtx(ctx, d+jitter)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func trimBody(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 256 {
		return s[:256] + "..."
	}
	return s
}
