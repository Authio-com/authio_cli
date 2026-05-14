package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeFile(t *testing.T, name, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// userFixture is a tiny set used by many runner tests: 1 valid, 1 disabled
// (skipped), 1 missing email (skipped). Each maps onto Clerk's shape so we
// can drive the full pipeline end-to-end without inventing a fake parser.
const clerkFixture = `[
  {"id":"u1","email_addresses":[{"email_address":"a@x.com","verification":{"status":"verified"}}],"first_name":"Ada"},
  {"id":"u2","email_addresses":[]},
  {"id":"u3","email_addresses":[{"email_address":"b@x.com","verification":{"status":"verified"}}]}
]`

// =====================================================================
// cursor save/load round-trip
// =====================================================================

func TestCursorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "users.json.authio-import.cursor")
	c := &Cursor{
		Provider:  "clerk",
		File:      "users.json",
		FileSize:  4242,
		LastIndex: 17,
		Summary:   CursorSummary{Created: 12, Existed: 4, Skipped: 1},
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := saveCursor(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := loadCursor(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastIndex != 17 || got.Summary.Created != 12 || got.Provider != "clerk" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestCursorMissingFileReturnsNil(t *testing.T) {
	got, err := loadCursor(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil cursor, got %+v", got)
	}
}

// =====================================================================
// rate limiter
// =====================================================================

func TestRateLimiterPaces(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	var slept []time.Duration
	sleeper := func(d time.Duration) {
		slept = append(slept, d)
		now = now.Add(d)
	}
	l := newRateLimiter(10, clock, sleeper)
	for i := 0; i < 5; i++ {
		l.Wait()
	}
	// 5 calls @ 10 rps == 4 sleeps of 100ms each (the first call is free).
	if len(slept) != 4 {
		t.Fatalf("want 4 sleeps, got %d (%v)", len(slept), slept)
	}
	for _, d := range slept {
		if d != 100*time.Millisecond {
			t.Fatalf("want 100ms, got %v", d)
		}
	}
}

func TestRateLimiterAllowsBurstWhenIdle(t *testing.T) {
	t0 := time.Now()
	calls := 0
	clock := func() time.Time {
		calls++
		// Advance the clock by 10s on the second call so the limiter sees an idle gap.
		if calls > 1 {
			return t0.Add(10 * time.Second)
		}
		return t0
	}
	var slept []time.Duration
	sleeper := func(d time.Duration) { slept = append(slept, d) }
	l := newRateLimiter(10, clock, sleeper)
	l.Wait() // first call: free
	l.Wait() // 10s later, so no sleep needed
	if len(slept) != 0 {
		t.Fatalf("unexpected sleep on idle gap: %v", slept)
	}
}

// =====================================================================
// runner: dry-run never POSTs
// =====================================================================

func TestRunnerDryRunDoesNotPOST(t *testing.T) {
	posts := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	file := writeFile(t, "users.json", clerkFixture)
	runner := &ImportRunner{
		Parser: clerkParser{},
		File:   file,
		APIURL: srv.URL,
		APIKey: "sk_test",
		DryRun: true,
		Out:    &bytes.Buffer{},
	}
	c, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 0 {
		t.Fatalf("dry-run made %d POSTs", posts.Load())
	}
	// 2 valid + 1 skipped (no email)
	if c.Summary.Created != 2 || c.Summary.Skipped != 1 {
		t.Fatalf("dry-run summary wrong: %+v", c.Summary)
	}
}

// =====================================================================
// runner: live POSTs hit the API; existed vs created tally correctly
// =====================================================================

func TestRunnerCountsCreatedExistedSkipped(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := n.Add(1)
		if r.URL.Path != "/v1/users" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk_test" {
			t.Errorf("missing/wrong bearer")
		}
		// First request: created. Second: already existed.
		if count == 1 {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	file := writeFile(t, "users.json", clerkFixture)
	runner := &ImportRunner{
		Parser:    clerkParser{},
		File:      file,
		APIURL:    srv.URL,
		APIKey:    "sk_test",
		RateLimit: 1000,
		Out:       &bytes.Buffer{},
	}
	c, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Summary.Created != 1 || c.Summary.Existed != 1 || c.Summary.Skipped != 1 {
		t.Fatalf("wrong tallies: %+v", c.Summary)
	}
	if n.Load() != 2 {
		t.Fatalf("expected 2 POSTs, got %d", n.Load())
	}
	// Cursor should be cleaned up on success.
	if _, err := os.Stat(file + ".authio-import.cursor"); !os.IsNotExist(err) {
		t.Fatalf("cursor should have been removed on clean success")
	}
}

// =====================================================================
// runner: resume from cursor
// =====================================================================

func TestRunnerResumesFromCursor(t *testing.T) {
	var posts atomic.Int32
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if e, ok := body["email"].(string); ok {
			seen = append(seen, e)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	file := writeFile(t, "users.json", clerkFixture)
	stat, _ := os.Stat(file)
	// Pre-seed cursor as if we processed indices 0 & 1 already.
	pre := &Cursor{
		Provider:  "clerk",
		File:      file,
		FileSize:  stat.Size(),
		LastIndex: 2,
		Summary:   CursorSummary{Created: 1, Skipped: 1},
		StartedAt: time.Now().UTC(),
	}
	if err := saveCursor(file+".authio-import.cursor", pre); err != nil {
		t.Fatal(err)
	}

	runner := &ImportRunner{
		Parser:    clerkParser{},
		File:      file,
		APIURL:    srv.URL,
		APIKey:    "sk_test",
		RateLimit: 1000,
		Out:       &bytes.Buffer{},
	}
	c, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 {
		t.Fatalf("expected 1 POST (only index 2 unprocessed), got %d", posts.Load())
	}
	if len(seen) != 1 || seen[0] != "b@x.com" {
		t.Fatalf("expected only b@x.com, got %v", seen)
	}
	// Final tallies should accumulate on top of the pre-seeded cursor.
	if c.Summary.Created != 2 || c.Summary.Skipped != 1 {
		t.Fatalf("summary did not accumulate: %+v", c.Summary)
	}
}

// =====================================================================
// runner: refuses to resume on file-size mismatch without --force
// =====================================================================

func TestRunnerRefusesFileSizeMismatchWithoutForce(t *testing.T) {
	file := writeFile(t, "users.json", clerkFixture)
	pre := &Cursor{
		Provider:  "clerk",
		File:      file,
		FileSize:  9999, // intentionally wrong
		LastIndex: 1,
		StartedAt: time.Now().UTC(),
	}
	if err := saveCursor(file+".authio-import.cursor", pre); err != nil {
		t.Fatal(err)
	}

	runner := &ImportRunner{
		Parser: clerkParser{},
		File:   file,
		DryRun: true,
		Out:    &bytes.Buffer{},
	}
	_, err := runner.Run(context.Background())
	if err == nil {
		t.Fatal("expected error on size mismatch without --force")
	}
	if !strings.Contains(err.Error(), "force") {
		t.Fatalf("error should mention --force, got: %v", err)
	}

	// With --force it should succeed.
	runner.Force = true
	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatalf("unexpected error with --force: %v", err)
	}
}

// =====================================================================
// runner: rate limiter is invoked
// =====================================================================

func TestRunnerCallsRateLimiter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	file := writeFile(t, "users.json", clerkFixture)
	now := time.Now()
	clock := func() time.Time {
		now = now.Add(1 * time.Microsecond)
		return now
	}
	var slept []time.Duration
	sleeper := func(d time.Duration) {
		slept = append(slept, d)
		now = now.Add(d)
	}

	runner := &ImportRunner{
		Parser:    clerkParser{},
		File:      file,
		APIURL:    srv.URL,
		APIKey:    "sk_test",
		RateLimit: 5, // 200ms between calls
		NowFunc:   clock,
		SleepFunc: sleeper,
		Out:       &bytes.Buffer{},
	}
	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 2 valid records => 1 sleep (first is free, second waits ~200ms).
	if len(slept) < 1 {
		t.Fatalf("expected ≥1 rate-limiter sleep, got %d (%v)", len(slept), slept)
	}
	want := 200 * time.Millisecond
	if slept[0] < want-time.Millisecond || slept[0] > want+time.Millisecond {
		t.Fatalf("rate-limiter slept %v, want ~%v", slept[0], want)
	}
}

// =====================================================================
// runner: detects user-with-no-email in the runner accounting (not the
// parser layer) by passing an explicit fixture
// =====================================================================

func TestRunnerCountsNoEmailAsSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	// Auth0 record with email == "" (which decodeAuth0Record currently
	// emits unchanged) — the runner is what counts it as skipped.
	file := writeFile(t, "users.json", `[{"user_id":"a","email":""},{"user_id":"b","email":"b@x.com"}]`)
	runner := &ImportRunner{
		Parser:    auth0Parser{},
		File:      file,
		APIURL:    srv.URL,
		APIKey:    "sk_test",
		RateLimit: 1000,
		Out:       &bytes.Buffer{},
	}
	c, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Summary.Skipped != 1 || c.Summary.Created != 1 {
		t.Fatalf("expected 1 skipped, 1 created: %+v", c.Summary)
	}
}

// =====================================================================
// runner: provider mismatch errors clearly
// =====================================================================

func TestRunnerRejectsCursorFromDifferentProvider(t *testing.T) {
	file := writeFile(t, "users.json", clerkFixture)
	stat, _ := os.Stat(file)
	pre := &Cursor{Provider: "auth0", File: file, FileSize: stat.Size(), StartedAt: time.Now().UTC()}
	if err := saveCursor(file+".authio-import.cursor", pre); err != nil {
		t.Fatal(err)
	}
	runner := &ImportRunner{Parser: clerkParser{}, File: file, DryRun: true, Out: &bytes.Buffer{}}
	_, err := runner.Run(context.Background())
	if err == nil {
		t.Fatal("expected provider-mismatch error")
	}
	if !strings.Contains(err.Error(), "auth0") {
		t.Fatalf("error should mention old provider, got: %v", err)
	}
}
