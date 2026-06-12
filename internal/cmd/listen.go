package cmd

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// Listen forwards Authio events to a local HTTP endpoint — the Authio
// answer to `stripe listen`.
//
//	authio listen --forward http://localhost:3000/webhooks [flags]
//
// Implementation (v1, zero server changes): the CLI POLLS the existing
// sk_-authed Events API (GET /v1/events) — the same cursor-paginated,
// project-scoped surface SDK consumers use — and replays each new event
// to the local target as a fully-formed Authio webhook: identical JSON
// envelope, an `Authio-Signature` HMAC computed with the exact scheme the
// webhooks worker uses, plus `Authio-Event-Id` / `Authio-Event-Action`
// headers. Because it polls, deliveries arrive with up to one poll
// interval of latency (default 2s) — fine for local development, not a
// production transport.
//
// Signature passthrough: pass `--secret whsec_…` (a real endpoint's
// signing secret) to reproduce that endpoint's exact signature so your
// existing verification code runs unchanged locally. Omit it and the CLI
// generates a throwaway secret and prints it — set it in your local
// handler to verify.
func Listen(args []string) error {
	var (
		forward     string
		secret      string
		eventsCSV   string
		intervalSec = 2
		replayN     = 0
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--forward", "--to":
			if i+1 < len(args) {
				forward = args[i+1]
				i++
			}
		case "--secret":
			if i+1 < len(args) {
				secret = args[i+1]
				i++
			}
		case "--events":
			if i+1 < len(args) {
				eventsCSV = args[i+1]
				i++
			}
		case "--interval":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n >= 1 {
					intervalSec = n
				}
				i++
			}
		case "--replay":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n >= 0 {
					replayN = n
				}
				i++
			}
		}
	}
	if forward == "" {
		return errors.New("usage: authio listen --forward <local-url> [--secret whsec_…] [--events a,b] [--interval secs] [--replay N]")
	}
	if !strings.HasPrefix(forward, "http://") && !strings.HasPrefix(forward, "https://") {
		return errors.New("--forward must be an http(s) URL, e.g. http://localhost:3000/webhooks")
	}

	name := resolveProfileName(args)
	p, _, err := loadProfile(name)
	if err != nil {
		return err
	}

	// Resolve project so the replayed payload carries the right
	// project_id (the Events API omits it from the envelope on purpose).
	meRes, err := apiGet(p, "/v1/projects/me")
	if err != nil {
		return fmt.Errorf("reach management API: %w", err)
	}
	if meRes.status == 401 {
		return fmt.Errorf("credentials for profile %q are invalid — run `authio login --profile %s`", name, name)
	}
	if meRes.status != 200 {
		return fmt.Errorf("GET /v1/projects/me returned %d: %s", meRes.status, string(meRes.body))
	}
	var me projectMe
	if err := json.Unmarshal(meRes.body, &me); err != nil {
		return err
	}

	generated := false
	if secret == "" {
		secret = generateSecret()
		generated = true
	}

	var types []string
	for _, t := range strings.Split(eventsCSV, ",") {
		if t = strings.TrimSpace(t); t != "" {
			types = append(types, t)
		}
	}

	fmt.Println()
	fmt.Printf("  authio listen — forwarding %s · %s (%s)\n", orDash(me.Tenant.Name), me.Name, describeEnv(me.Environment))
	fmt.Printf("  → %s\n", forward)
	if len(types) > 0 {
		fmt.Printf("  events: %s\n", strings.Join(types, ", "))
	}
	if generated {
		fmt.Printf("  signing secret (set this in your handler to verify): %s\n", secret)
	} else {
		fmt.Println("  signing with the provided --secret")
	}
	fmt.Printf("  polling every %ds — deliveries arrive with up to ~%ds latency. Ctrl+C to stop.\n", intervalSec, intervalSec)
	fmt.Println()

	l := &listener{
		profile:   p,
		forward:   forward,
		secret:    secret,
		types:     types,
		projectID: me.ID,
		client:    &http.Client{Timeout: 20 * time.Second},
	}

	// Establish a baseline: the newest existing event. Without --replay we
	// only forward events that occur after `listen` starts.
	baseline, err := l.fetchPage("", 100)
	if err != nil {
		return fmt.Errorf("prime event cursor: %w", err)
	}
	if len(baseline) > 0 {
		l.last = &eventPos{ts: baseline[0].CreatedAt, id: baseline[0].ID}
	}
	if replayN > 0 && len(baseline) > 0 {
		n := replayN
		if n > len(baseline) {
			n = len(baseline)
		}
		// baseline is newest-first; replay oldest-first.
		replay := make([]apiEvent, n)
		for i := 0; i < n; i++ {
			replay[i] = baseline[n-1-i]
		}
		fmt.Printf("  replaying %d recent event(s)...\n\n", n)
		for _, e := range replay {
			l.deliver(e)
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			l.printSummary()
			return nil
		case <-ticker.C:
			if err := l.poll(); err != nil {
				fmt.Printf("  \033[33mpoll error:\033[0m %v\n", err)
			}
		}
	}
}

type eventPos struct {
	ts string
	id string
}

type apiEvent struct {
	ID        string `json:"id"`
	Event     string `json:"event"`
	CreatedAt string `json:"created_at"`
	Data      struct {
		OrganizationID *string         `json:"organization_id"`
		UserID         *string         `json:"user_id"`
		ActorType      string          `json:"actor_type"`
		ActorID        *string         `json:"actor_id"`
		TargetType     *string         `json:"target_type"`
		TargetID       *string         `json:"target_id"`
		Metadata       json.RawMessage `json:"metadata"`
	} `json:"data"`
}

type listener struct {
	profile   *credentials.Profile
	forward   string
	secret    string
	types     []string
	projectID string
	client    *http.Client
	last      *eventPos

	delivered int
	failed    int
}

// poll fetches every event newer than l.last (draining multiple pages if
// a burst exceeded one page), then forwards them oldest-first.
func (l *listener) poll() error {
	var fresh []apiEvent
	after := ""
	for {
		page, err := l.fetchPage(after, 100)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		stop := false
		for _, e := range page {
			if l.last == nil || newer(e, *l.last) {
				fresh = append(fresh, e)
			} else {
				stop = true
				break
			}
		}
		// last==nil means a previously-empty project: take only the first
		// page to avoid replaying unbounded history, then set the baseline.
		if stop || l.last == nil || len(page) < 100 {
			break
		}
		tail := page[len(page)-1]
		after = encodeCursor(tail.CreatedAt, tail.ID)
	}
	if len(fresh) == 0 {
		return nil
	}
	// fetched newest-first; deliver oldest-first.
	sort.SliceStable(fresh, func(i, j int) bool {
		return newer(fresh[j], eventPos{ts: fresh[i].CreatedAt, id: fresh[i].ID})
	})
	for _, e := range fresh {
		l.deliver(e)
		l.last = &eventPos{ts: e.CreatedAt, id: e.ID}
	}
	return nil
}

func (l *listener) fetchPage(after string, limit int) ([]apiEvent, error) {
	q := fmt.Sprintf("/v1/events?limit=%d", limit)
	if after != "" {
		q += "&after=" + after
	} else if l.last != nil {
		// Bound the scan to events at/after our baseline.
		q += "&range_start=" + url.QueryEscape(l.last.ts)
	}
	for _, t := range l.types {
		q += "&events[]=" + url.QueryEscape(t)
	}
	res, err := apiGet(l.profile, q)
	if err != nil {
		return nil, err
	}
	if res.status == 429 {
		return nil, errors.New("rate limited (429) — increase --interval")
	}
	if res.status != 200 {
		return nil, fmt.Errorf("GET /v1/events → %d: %s", res.status, string(res.body))
	}
	var parsed struct {
		Data []apiEvent `json:"data"`
	}
	if err := json.Unmarshal(res.body, &parsed); err != nil {
		return nil, err
	}
	return parsed.Data, nil
}

// deliver POSTs one event to the local target as an Authio-shaped webhook.
func (l *listener) deliver(e apiEvent) {
	body := buildWebhookBody(e, l.projectID)
	sig := signPayload(l.secret, body, time.Now())

	req, err := http.NewRequest(http.MethodPost, l.forward, bytes.NewReader(body))
	if err != nil {
		l.failed++
		fmt.Printf("  %s  %-28s build request failed: %v\n", glyph(statusFail), e.Event, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authio-Signature", sig)
	req.Header.Set("Authio-Event-Id", e.ID)
	req.Header.Set("Authio-Event-Action", e.Event)
	req.Header.Set("User-Agent", "authio-cli-listen/0.1")

	start := time.Now()
	resp, err := l.client.Do(req)
	latency := time.Since(start).Round(time.Millisecond)
	if err != nil {
		l.failed++
		fmt.Printf("  %s  %-28s → %v\n", glyph(statusFail), e.Event, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		l.delivered++
		fmt.Printf("  %s  %-28s → %d (%s)\n", glyph(statusPass), e.Event, resp.StatusCode, latency)
	} else {
		l.failed++
		fmt.Printf("  %s  %-28s → %d (%s)\n", glyph(statusWarn), e.Event, resp.StatusCode, latency)
	}
}

func (l *listener) printSummary() {
	fmt.Println()
	fmt.Printf("  stopped. delivered=%d failed=%d\n", l.delivered, l.failed)
	fmt.Println()
}

// =====================================================================
// payload + signing — mirrors authio_webhooks worker exactly
// =====================================================================

// buildWebhookBody reconstructs the exact JSON envelope the webhooks
// worker sends (cmd/worker/main.go), so a local handler sees a real
// Authio webhook.
func buildWebhookBody(e apiEvent, projectID string) []byte {
	metadata := json.RawMessage(e.Data.Metadata)
	if len(metadata) == 0 {
		metadata = json.RawMessage("{}")
	}
	body := map[string]any{
		"id":              e.ID,
		"action":          e.Event,
		"created_at":      e.CreatedAt,
		"project_id":      projectID,
		"organization_id": e.Data.OrganizationID,
		"user_id":         e.Data.UserID,
		"target_type":     e.Data.TargetType,
		"target_id":       e.Data.TargetID,
		"metadata":        metadata,
		"actor": map[string]any{
			"type": e.Data.ActorType,
			"id":   e.Data.ActorID,
		},
	}
	out, _ := json.Marshal(body)
	return out
}

// signPayload reproduces authio_webhooks/internal/signing.Sign:
//
//	Authio-Signature: t=<unix>,v1=<hex hmac-sha256(secret, "<t>.<body>")>
func signPayload(secret string, body []byte, ts time.Time) string {
	t := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(t))
	mac.Write([]byte("."))
	mac.Write(body)
	return fmt.Sprintf("t=%s,v1=%s", t, hex.EncodeToString(mac.Sum(nil)))
}

func generateSecret() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "whsec_" + base64.RawURLEncoding.EncodeToString(b)
}

// =====================================================================
// small helpers
// =====================================================================

// newer reports whether event e is strictly newer than position p,
// ordering by created_at then id (matching the Events API keyset order).
func newer(e apiEvent, p eventPos) bool {
	et, eok := parseTime(e.CreatedAt)
	pt, pok := parseTime(p.ts)
	if eok && pok {
		if et.After(pt) {
			return true
		}
		if et.Before(pt) {
			return false
		}
		return e.ID > p.id
	}
	// Fall back to lexical comparison of the raw strings.
	if e.CreatedAt != p.ts {
		return e.CreatedAt > p.ts
	}
	return e.ID > p.id
}

func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func encodeCursor(ts, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(ts + "|" + id))
}
