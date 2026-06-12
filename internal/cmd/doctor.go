package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// errDoctorFailed is returned (quietly) when one or more checks FAIL so
// the process exits non-zero — useful in CI ("authio doctor && deploy").
var errDoctorFailed = errors.New("doctor: one or more checks failed")

const (
	statusPass = "pass"
	statusWarn = "warn"
	statusFail = "fail"
	statusSkip = "skip"
)

type check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// defaultReleaseRepo is the GitHub repo doctor checks for newer releases.
// Overridable with --repo for forks / self-hosted mirrors.
const defaultReleaseRepo = "authio-com/authio_cli"

// Doctor diagnoses the local Authio setup and prints a pass/warn/fail
// checklist (or JSON with --json). `version` is the running CLI version,
// injected from main.
//
//	authio doctor [--profile name] [--json] [--repo owner/name] [--no-webhook-ping]
func Doctor(version string, args []string) error {
	asJSON := false
	repo := defaultReleaseRepo
	pingWebhooks := true
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--no-webhook-ping":
			pingWebhooks = false
		case "--repo":
			if i+1 < len(args) {
				repo = args[i+1]
				i++
			}
		}
	}

	name := resolveProfileName(args)
	var checks []check

	// --- 1. CLI version vs latest GitHub release ---
	checks = append(checks, checkVersion(version, repo))

	// --- credentials load (gates the API checks) ---
	p, _, err := loadProfile(name)
	if err != nil {
		checks = append(checks, check{
			Name:   "credentials",
			Status: statusFail,
			Detail: err.Error(),
		})
		return finish(checks, asJSON)
	}

	// --- 2 + 4 + 5. credentials valid / key↔env sanity / clock skew ---
	// One /v1/projects/me call feeds three checks.
	credCheck, me, meRes := checkCredentials(p, name)
	checks = append(checks, credCheck)

	// --- 3. API reachability + latency (management-api + auth-core) ---
	checks = append(checks, checkManagementAPI(p))
	checks = append(checks, checkAuthCore(p))

	if me != nil {
		checks = append(checks, checkKeyEnvSanity(p, me))
	}
	if meRes != nil {
		checks = append(checks, checkClockSkew(meRes))
	}

	// --- 6. webhook endpoints (configured + reachability) ---
	checks = append(checks, checkWebhooks(p, pingWebhooks)...)

	return finish(checks, asJSON)
}

func finish(checks []check, asJSON bool) error {
	failed := false
	for _, c := range checks {
		if c.Status == statusFail {
			failed = true
		}
	}
	if asJSON {
		out := map[string]any{
			"ok":     !failed,
			"checks": checks,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Println()
		fmt.Println("  authio doctor")
		fmt.Println()
		for _, c := range checks {
			fmt.Printf("  %s  %-22s %s\n", glyph(c.Status), c.Name, c.Detail)
		}
		fmt.Println()
		if failed {
			fmt.Println("  Some checks failed. See details above.")
		} else {
			fmt.Println("  All good.")
		}
		fmt.Println()
	}
	if failed {
		return errDoctorFailed
	}
	return nil
}

func glyph(status string) string {
	switch status {
	case statusPass:
		return "\033[32m✓\033[0m"
	case statusWarn:
		return "\033[33m!\033[0m"
	case statusFail:
		return "\033[31m✗\033[0m"
	default:
		return "\033[90m–\033[0m"
	}
}

// =====================================================================
// individual checks
// =====================================================================

func checkVersion(version, repo string) check {
	latest, err := latestReleaseTag(repo)
	if err != nil {
		return check{"cli version", statusWarn, fmt.Sprintf("running %s (couldn't reach GitHub: %v)", version, err)}
	}
	if latest == "" {
		return check{"cli version", statusSkip, fmt.Sprintf("running %s (no published releases yet)", version)}
	}
	if normalizeVersion(latest) == normalizeVersion(version) {
		return check{"cli version", statusPass, fmt.Sprintf("running %s (latest)", version)}
	}
	return check{
		"cli version",
		statusWarn,
		fmt.Sprintf("running %s, latest is %s — upgrade: curl -fsSL https://raw.githubusercontent.com/%s/main/scripts/install.sh | sh", version, latest, repo),
	}
}

func checkCredentials(p *credentials.Profile, name string) (check, *projectMe, *apiResult) {
	res, err := apiGet(p, "/v1/projects/me")
	if err != nil {
		return check{"credentials", statusFail, fmt.Sprintf("cannot reach management API: %v", err)}, nil, nil
	}
	switch {
	case res.status == 401:
		return check{"credentials", statusFail, fmt.Sprintf("key for profile %q is invalid or revoked — run `authio login --profile %s`", name, name)}, nil, res
	case res.status != 200:
		return check{"credentials", statusWarn, fmt.Sprintf("/v1/projects/me returned %d", res.status)}, nil, res
	}
	var me projectMe
	if err := json.Unmarshal(res.body, &me); err != nil {
		return check{"credentials", statusWarn, "valid key but response did not decode"}, nil, res
	}
	return check{
		"credentials",
		statusPass,
		fmt.Sprintf("authenticated as %s · %s (%s)", orDash(me.Tenant.Name), me.Name, describeEnv(me.Environment)),
	}, &me, res
}

func checkManagementAPI(p *credentials.Profile) check {
	base := strings.TrimRight(p.APIURL, "/")
	if base == "" {
		base = defaultMgmtAPI
	}
	res, err := getUnauthed(base + "/healthz")
	if err != nil {
		return check{"management-api", statusFail, fmt.Sprintf("%s unreachable: %v", base, err)}
	}
	if res.status != 200 {
		return check{"management-api", statusWarn, fmt.Sprintf("%s/healthz → %d", base, res.status)}
	}
	return check{"management-api", latencyStatus(res.latency), fmt.Sprintf("%s healthy (%s)", base, res.latency.Round(time.Millisecond))}
}

func checkAuthCore(p *credentials.Profile) check {
	base := strings.TrimRight(p.AuthCoreURL, "/")
	if base == "" {
		base = defaultAuthCore
	}
	res, err := getUnauthed(base + "/v1/auth/.well-known/jwks.json")
	if err != nil {
		return check{"auth-core (identity)", statusFail, fmt.Sprintf("%s unreachable: %v", base, err)}
	}
	if res.status != 200 {
		return check{"auth-core (identity)", statusWarn, fmt.Sprintf("%s JWKS → %d", base, res.status)}
	}
	return check{"auth-core (identity)", latencyStatus(res.latency), fmt.Sprintf("%s reachable (%s)", base, res.latency.Round(time.Millisecond))}
}

func checkKeyEnvSanity(p *credentials.Profile, me *projectMe) check {
	family := keyFamily(p.APIKey)
	isProd := me.Environment == "production"
	switch {
	case family == "":
		return check{"key ↔ environment", statusWarn, "key prefix is neither sk_live_/sk_test_ nor pk_*"}
	case family == "live" && isProd:
		return check{"key ↔ environment", statusPass, "live key on the production environment"}
	case family == "test" && !isProd:
		return check{"key ↔ environment", statusPass, fmt.Sprintf("test key on the %s environment", describeEnv(me.Environment))}
	case family == "live" && !isProd:
		return check{"key ↔ environment", statusWarn, fmt.Sprintf("LIVE key pointed at a non-production environment (%s) — double-check this is intended", describeEnv(me.Environment))}
	default: // test key on production
		return check{"key ↔ environment", statusWarn, "test key on the production environment (likely a grandfathered key; test keys normally map to non-prod)"}
	}
}

func checkClockSkew(res *apiResult) check {
	dateHdr := res.header.Get("Date")
	if dateHdr == "" {
		return check{"clock skew", statusSkip, "server did not return a Date header"}
	}
	serverTime, err := http.ParseTime(dateHdr)
	if err != nil {
		return check{"clock skew", statusSkip, "could not parse server Date header"}
	}
	// Approximate: server stamps Date when it handles the request; we
	// subtract half the round trip so latency doesn't masquerade as skew.
	local := time.Now().Add(-res.latency / 2)
	skew := local.Sub(serverTime)
	abs := skew
	if abs < 0 {
		abs = -abs
	}
	detail := fmt.Sprintf("local clock is %s vs server", signedDuration(skew))
	switch {
	case abs <= 5*time.Second:
		return check{"clock skew", statusPass, detail}
	case abs <= 120*time.Second:
		return check{"clock skew", statusWarn, detail + " — TOTP codes may be rejected; consider enabling NTP"}
	default:
		return check{"clock skew", statusFail, detail + " — TOTP and webhook signature verification will fail; sync your clock (NTP)"}
	}
}

func checkWebhooks(p *credentials.Profile, ping bool) []check {
	res, err := apiGet(p, "/v1/webhooks")
	if err != nil {
		return []check{{"webhooks", statusWarn, fmt.Sprintf("could not list endpoints: %v", err)}}
	}
	if res.status != 200 {
		return []check{{"webhooks", statusWarn, fmt.Sprintf("GET /v1/webhooks → %d", res.status)}}
	}
	var endpoints []struct {
		ID            string `json:"id"`
		URL           string `json:"url"`
		Status        string `json:"status"`
		FailureStreak int    `json:"failure_streak"`
	}
	if err := json.Unmarshal(res.body, &endpoints); err != nil {
		return []check{{"webhooks", statusWarn, "could not decode endpoint list"}}
	}
	active := 0
	for _, e := range endpoints {
		if e.Status == "active" {
			active++
		}
	}
	if active == 0 {
		return []check{{"webhooks", statusSkip, "no active webhook endpoints configured"}}
	}

	out := []check{{"webhooks", statusPass, fmt.Sprintf("%d active endpoint(s)", active)}}
	for _, e := range endpoints {
		if e.Status != "active" {
			continue
		}
		name := "webhook " + shortURL(e.URL)
		if e.FailureStreak > 0 {
			out = append(out, check{name, statusWarn, fmt.Sprintf("%d consecutive delivery failures", e.FailureStreak)})
			continue
		}
		if ping {
			out = append(out, pingEndpoint(name, e.URL))
		} else {
			out = append(out, check{name, statusPass, "configured (reachability ping skipped)"})
		}
	}
	return out
}

func pingEndpoint(name, url string) check {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return check{name, statusWarn, "invalid URL"}
	}
	req.Header.Set("User-Agent", cliUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return check{name, statusWarn, fmt.Sprintf("unreachable from this machine: %v", err)}
	}
	defer resp.Body.Close()
	// Any HTTP response (even 4xx/405) proves the host is reachable.
	return check{name, statusPass, fmt.Sprintf("reachable (HEAD → %d)", resp.StatusCode)}
}

// =====================================================================
// helpers
// =====================================================================

func latencyStatus(d time.Duration) string {
	if d > 1500*time.Millisecond {
		return statusWarn
	}
	return statusPass
}

func signedDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d >= 0 {
		return "+" + d.String() + " ahead"
	}
	return (-d).String() + " behind"
}

func shortURL(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if len(u) > 40 {
		return u[:37] + "..."
	}
	return u
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "authio ")
	v = strings.TrimPrefix(v, "v")
	return v
}

// githubAPIBase is the GitHub REST host. A package var (not a const) so
// tests can point it at an httptest server.
var githubAPIBase = "https://api.github.com"

// latestReleaseTag returns the tag_name of the latest GitHub release, or
// "" when the repo has no published releases (404). Network/HTTP errors
// propagate so the caller can render them as a warning.
func latestReleaseTag(repo string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(githubAPIBase, "/"), repo)
	res, err := getUnauthed(url)
	if err != nil {
		return "", err
	}
	if res.status == 404 {
		return "", nil
	}
	if res.status != 200 {
		return "", fmt.Errorf("github returned %d", res.status)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(res.body, &rel); err != nil {
		return "", err
	}
	return rel.TagName, nil
}
