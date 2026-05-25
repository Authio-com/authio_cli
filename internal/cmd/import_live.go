package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LiveCredentials is the union of every provider's admin-API credential
// shape. Most fields are nil for any single provider; the registered
// PullLive picks the ones it needs.
//
// AUTHIO_REDACT — every field on this struct is a high-risk secret.
// Never log, never include in error messages verbatim, never write to
// stdout. The management-api ships these to the CLI via decrypted
// import_credentials.envelope and the CLI tosses them when the job
// terminates.
type LiveCredentials struct {
	// Auth0
	Domain string `json:"domain,omitempty"`
	Token  string `json:"token,omitempty"`

	// Clerk
	SecretKey string `json:"secret_key,omitempty"`

	// WorkOS
	APIKey string `json:"api_key,omitempty"`

	// Stytch (also reused by Descope for ProjectID)
	ProjectID     string `json:"project_id,omitempty"`
	ProjectSecret string `json:"project_secret,omitempty"`

	// Descope
	MgmtKey string `json:"mgmt_key,omitempty"`

	// Cognito
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	Region          string `json:"region,omitempty"`
	UserPoolID      string `json:"user_pool_id,omitempty"`

	// Firebase
	ServiceAccountJSON string `json:"service_account_json,omitempty"`

	// Supabase
	PAT        string `json:"pat,omitempty"`
	ProjectRef string `json:"project_ref,omitempty"`
}

// LiveOptions tweaks the puller's behavior (max page size, rate limit,
// base URL override for tests).
type LiveOptions struct {
	// BaseURLOverride lets tests redirect provider API calls at a
	// localhost httptest.Server. Empty means use the real provider host.
	BaseURLOverride string
	// MaxPages caps pagination so a runaway export doesn't dominate a
	// dev machine. 0 = unbounded.
	MaxPages int
	// RateLimitPerSec caps requests/sec. 0 falls back to providerDefault.
	RateLimitPerSec float64
	// HTTPClient lets the caller inject a custom transport (used by the
	// migrate-run command for retries + telemetry).
	HTTPClient *http.Client
	// ProgressFn, if set, is called every batch with (kind, count). It
	// powers the import_jobs.progress JSONB updates.
	ProgressFn func(kind string, completed int)
}

// LivePuller is what each provider implements.
type LivePuller interface {
	Name() string
	PullLive(ctx context.Context, creds LiveCredentials, opts LiveOptions) (*ImportPlan, error)
}

var livePullers = map[string]LivePuller{
	"auth0":    auth0LivePuller{},
	"clerk":    clerkLivePuller{},
	"workos":   workosLivePuller{},
	"stytch":   stytchLivePuller{},
	"descope":  descopeLivePuller{},
	"cognito":  cognitoLivePuller{},
	"firebase": firebaseLivePuller{},
	"supabase": supabaseLivePuller{},
}

// LivePullerFor returns the registered puller or a helpful error.
func LivePullerFor(provider string) (LivePuller, error) {
	p, ok := livePullers[strings.ToLower(provider)]
	if !ok {
		return nil, fmt.Errorf("no live puller for %q", provider)
	}
	return p, nil
}

// notLiveYetPuller is a stub for providers without a live importer yet
// (Cognito needs the AWS SDK; Firebase needs the Admin SDK). The
// management-api's probe surfaces this before a job is even queued, but
// we still register a stub so `authio migrate run` exits with a sane
// message if someone forces the path.
type notLiveYetPuller struct{ name string }

func (n notLiveYetPuller) Name() string { return n.name }
func (n notLiveYetPuller) PullLive(ctx context.Context, _ LiveCredentials, _ LiveOptions) (*ImportPlan, error) {
	return nil, fmt.Errorf(
		"%s: live import not implemented yet — use --input <file> with an export bundle. "+
			"Track at https://github.com/authio-com/authio_cli/issues",
		n.name,
	)
}

// ---------------------------------------------------------------------
// Shared HTTP helpers
// ---------------------------------------------------------------------

// liveHTTP wraps an http.Client with per-host rate limiting + retries
// for 5xx and 429 responses. Keeps the per-provider PullLive
// implementations tiny.
type liveHTTP struct {
	client  *http.Client
	limiter *tokenBucket
	ua      string
}

func newLiveHTTP(opts LiveOptions, providerName string) *liveHTTP {
	rate := opts.RateLimitPerSec
	if rate <= 0 {
		rate = 10
	}
	c := opts.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	return &liveHTTP{
		client:  c,
		limiter: newTokenBucket(rate),
		ua:      "authio-cli-live/" + providerName,
	}
}

func (h *liveHTTP) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := h.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", h.ua)
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		resp, err := h.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(backoff(attempt))
			continue
		}
		// Respect provider Retry-After on 429/503.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("transient: %d", resp.StatusCode)
			if retryAfter > 0 {
				time.Sleep(retryAfter)
			} else {
				time.Sleep(backoff(attempt))
			}
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("exhausted retries")
	}
	return nil, lastErr
}

func backoff(attempt int) time.Duration {
	return time.Duration(250*(1<<attempt)) * time.Millisecond
}

func parseRetryAfter(s string) time.Duration {
	if s == "" {
		return 0
	}
	// Seconds variant.
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > 0 && n < 600 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// ---------------------------------------------------------------------
// Tiny token bucket (no external deps; we're stdlib-only).
// ---------------------------------------------------------------------

type tokenBucket struct {
	rate  float64
	next  time.Time
	delta time.Duration
}

func newTokenBucket(ratePerSec float64) *tokenBucket {
	d := time.Duration(float64(time.Second) / ratePerSec)
	if d <= 0 {
		d = 100 * time.Millisecond
	}
	return &tokenBucket{rate: ratePerSec, delta: d, next: time.Now()}
}

func (b *tokenBucket) Wait(ctx context.Context) error {
	now := time.Now()
	if now.Before(b.next) {
		wait := time.Until(b.next)
		b.next = b.next.Add(b.delta)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			return nil
		}
	}
	b.next = now.Add(b.delta)
	return nil
}

// ---------------------------------------------------------------------
// Pull-side flag parsing for `authio import <provider> --live-token`.
// ---------------------------------------------------------------------

// liveFlagsFromArgs scans rest-args for `--live-token <token>` and the
// provider-specific extras (--auth0-domain, --stytch-project-id, etc).
// Returns nil when --live-token is absent.
func liveCredsFromArgs(provider string, args []string) *LiveCredentials {
	creds := &LiveCredentials{}
	var hasLive bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--live-token":
			if i+1 < len(args) {
				hasLive = true
				switch strings.ToLower(provider) {
				case "auth0":
					creds.Token = args[i+1]
				case "clerk":
					creds.SecretKey = args[i+1]
				case "workos":
					creds.APIKey = args[i+1]
				case "descope":
					creds.MgmtKey = args[i+1]
				case "supabase":
					creds.PAT = args[i+1]
				default:
					creds.Token = args[i+1]
				}
				i++
			}
		case "--auth0-domain":
			if i+1 < len(args) {
				creds.Domain = args[i+1]
				i++
			}
		case "--stytch-project-id":
			if i+1 < len(args) {
				creds.ProjectID = args[i+1]
				i++
			}
		case "--stytch-secret":
			if i+1 < len(args) {
				creds.ProjectSecret = args[i+1]
				i++
			}
		case "--descope-project-id":
			if i+1 < len(args) {
				creds.ProjectID = args[i+1]
				i++
			}
		case "--supabase-ref":
			if i+1 < len(args) {
				creds.ProjectRef = args[i+1]
				i++
			}
		}
	}
	if !hasLive {
		return nil
	}
	return creds
}
