package cmd

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// cliUserAgent is sent on every CLI-originated request so the platform
// can distinguish CLI traffic from SDK traffic in logs.
const cliUserAgent = "authio-cli"

// sharedHTTPClient has a sane timeout so `doctor`/`whoami` never hang on a
// black-holed network. `listen` builds its own client with a longer
// timeout for the local-forward leg.
var sharedHTTPClient = &http.Client{Timeout: 15 * time.Second}

// resolveProfileName returns the profile to operate on. An explicit
// `--profile <name>` flag always wins; otherwise the active profile
// selected via `authio env use` (default: "default").
func resolveProfileName(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--profile" && i+1 < len(args) {
			return args[i+1]
		}
	}
	store, err := credentials.DefaultStore()
	if err != nil {
		return "default"
	}
	return store.ActiveProfile()
}

// loadProfile resolves and loads the credentials for the chosen profile.
func loadProfile(name string) (*credentials.Profile, string, error) {
	if name == "" {
		name = "default"
	}
	store, err := credentials.DefaultStore()
	if err != nil {
		return nil, name, err
	}
	p, err := store.Load(name)
	if err != nil {
		return nil, name, err
	}
	return p, name, nil
}

// apiResult captures everything the diagnostics commands need from a
// single management-api call: the status, decoded body bytes, response
// headers (for clock-skew via Date), and the round-trip latency.
type apiResult struct {
	status  int
	body    []byte
	header  http.Header
	latency time.Duration
}

// apiGet performs an authenticated GET against the profile's management
// API. The returned error is non-nil only for transport failures; HTTP
// error statuses come back in apiResult.status so callers can render
// them as warnings rather than hard failures.
func apiGet(p *credentials.Profile, path string) (*apiResult, error) {
	base := strings.TrimRight(p.APIURL, "/")
	if base == "" {
		base = defaultMgmtAPI
	}
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("User-Agent", cliUserAgent)
	start := time.Now()
	resp, err := sharedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return &apiResult{
		status:  resp.StatusCode,
		body:    body,
		header:  resp.Header,
		latency: time.Since(start),
	}, nil
}

// getUnauthed performs an unauthenticated GET (health checks, JWKS,
// GitHub release lookups) and reports status + latency.
func getUnauthed(url string) (*apiResult, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cliUserAgent)
	start := time.Now()
	resp, err := sharedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return &apiResult{
		status:  resp.StatusCode,
		body:    body,
		header:  resp.Header,
		latency: time.Since(start),
	}, nil
}

// keyFamily classifies an api key by its prefix: "live", "test", or ""
// when it is neither a recognised secret nor publishable key.
func keyFamily(key string) string {
	switch {
	case strings.HasPrefix(key, "sk_live_"), strings.HasPrefix(key, "pk_live_"):
		return "live"
	case strings.HasPrefix(key, "sk_test_"), strings.HasPrefix(key, "pk_test_"):
		return "test"
	default:
		return ""
	}
}

// projectMe is the subset of GET /v1/projects/me the CLI consumes.
type projectMe struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Environment string `json:"environment"`
	CreatedAt   string `json:"created_at"`
	Tenant      struct {
		Name string `json:"name"`
	} `json:"tenant"`
}

// describeEnv renders a human label for an environment given its legacy
// environment enum value.
func describeEnv(environment string) string {
	switch environment {
	case "production":
		return "Production"
	case "staging":
		return "Staging"
	case "development":
		return "Development"
	case "":
		return "unknown"
	default:
		return environment
	}
}

func maskKeyShort(s string) string {
	if len(s) < 12 {
		return "<key>"
	}
	return fmt.Sprintf("%s…%s", s[:8], s[len(s)-4:])
}
