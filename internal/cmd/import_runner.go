package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// SourceUser is the canonical shape every parser emits. The runner doesn't
// care which provider it came from — it just calls POST /v1/users with
// (email, name, email_verified) and emits enrollment for created users.
type SourceUser struct {
	Email          string
	Name           string
	EmailVerified  bool
	SourceID       string
	SourceProvider string
	Metadata       map[string]any
}

// Parser streams users from a provider-specific export format. The runner
// passes a fresh `emit` callback each run; returning a non-nil error from
// emit (e.g. context cancellation) aborts parsing cleanly.
type Parser interface {
	// Name is the provider key used in cursor + UA.
	Name() string
	// Help returns a short string describing the expected file format.
	// Surfaced via `authio import <provider> --help`.
	Help() string
	// Parse reads from r and calls emit for every record. Records that
	// should be skipped (disabled, banned, missing email, etc.) are
	// emitted with Email == "" so the runner can count them as skipped
	// without breaking the cursor's count-of-records-seen invariant.
	Parse(ctx context.Context, r io.Reader, emit func(SourceUser) error) error
}

// CursorSummary tallies what the runner did across this import.
type CursorSummary struct {
	Created int `json:"created"`
	Existed int `json:"existed"`
	Skipped int `json:"skipped"`
	Errored int `json:"errored"`
}

// Cursor is what gets written next to the input file as a resume marker.
// We key resume safety on (provider, file, fileSize); a size mismatch
// indicates the source file changed and we refuse to continue without
// --force.
type Cursor struct {
	Provider      string        `json:"provider"`
	File          string        `json:"file"`
	FileSize      int64         `json:"file_size"`
	LastIndex     int           `json:"last_index"`
	Completed     bool          `json:"completed"`
	StartedAt     time.Time     `json:"started_at"`
	LastUpdatedAt time.Time     `json:"last_updated_at"`
	Summary       CursorSummary `json:"summary"`
}

// =====================================================================
// rateLimiter
// =====================================================================

// rateLimiter is a tiny token bucket emitting exactly `rps` ops/sec with
// jitter-free uniform spacing. Both `nowFunc` and `sleep` are injectable
// so tests can verify pacing without actually waiting.
type rateLimiter struct {
	interval time.Duration
	nowFunc  func() time.Time
	sleep    func(time.Duration)
	last     time.Time
}

func newRateLimiter(rps int, nowFunc func() time.Time, sleep func(time.Duration)) *rateLimiter {
	if rps <= 0 {
		rps = 1
	}
	if nowFunc == nil {
		nowFunc = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	return &rateLimiter{
		interval: time.Second / time.Duration(rps),
		nowFunc:  nowFunc,
		sleep:    sleep,
	}
}

func (l *rateLimiter) Wait() {
	now := l.nowFunc()
	if l.last.IsZero() {
		l.last = now
		return
	}
	next := l.last.Add(l.interval)
	if d := next.Sub(now); d > 0 {
		l.sleep(d)
		l.last = next
		return
	}
	l.last = now
}

// =====================================================================
// cursor I/O
// =====================================================================

func cursorPathFor(file string) string {
	return file + ".authio-import.cursor"
}

func loadCursor(path string) (*Cursor, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var c Cursor
	if err := json.Unmarshal(bytes.TrimSpace(b), &c); err != nil {
		return nil, fmt.Errorf("parse cursor %s: %w", path, err)
	}
	return &c, nil
}

func saveCursor(path string, c *Cursor) error {
	c.LastUpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// =====================================================================
// ImportRunner
// =====================================================================

// ImportRunner drives the standardized import flow: stream from a Parser,
// dedupe by cursor, rate-limit, POST /v1/users, count summaries.
type ImportRunner struct {
	Parser     Parser
	File       string
	APIKey     string
	APIURL     string
	DryRun     bool
	Force      bool
	RateLimit  int           // requests per second; defaults to 50
	HTTP       *http.Client  // injectable for tests
	Out        io.Writer     // pretty-prints progress; defaults to os.Stdout
	NowFunc    func() time.Time
	SleepFunc  func(time.Duration)
	UserAgent  string
}

// Run reads the file, validates the cursor, streams through the parser,
// and dispatches each user. Returns the final cursor + summary.
func (r *ImportRunner) Run(ctx context.Context) (*Cursor, error) {
	if r.Parser == nil {
		return nil, errors.New("ImportRunner.Parser is required")
	}
	if r.File == "" {
		return nil, errors.New("ImportRunner.File is required")
	}
	if !r.DryRun {
		if r.APIKey == "" {
			return nil, errors.New("ImportRunner.APIKey is required (run `authio login` or pass --profile)")
		}
		if r.APIURL == "" {
			return nil, errors.New("ImportRunner.APIURL is required")
		}
	}
	if r.RateLimit <= 0 {
		r.RateLimit = 50
	}
	if r.HTTP == nil {
		r.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if r.Out == nil {
		r.Out = os.Stdout
	}
	if r.NowFunc == nil {
		r.NowFunc = time.Now
	}
	if r.UserAgent == "" {
		r.UserAgent = "authio-cli-import-" + r.Parser.Name() + "/0.1"
	}

	stat, err := os.Stat(r.File)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", r.File, err)
	}
	cursorPath := cursorPathFor(r.File)
	existing, err := loadCursor(cursorPath)
	if err != nil {
		return nil, err
	}

	cursor := &Cursor{
		Provider:  r.Parser.Name(),
		File:      r.File,
		FileSize:  stat.Size(),
		StartedAt: r.NowFunc().UTC(),
	}
	if existing != nil {
		switch {
		case existing.Provider != r.Parser.Name():
			return nil, fmt.Errorf("cursor at %s belongs to provider %q (you ran %q); pass a different file or delete the cursor", cursorPath, existing.Provider, r.Parser.Name())
		case existing.FileSize != stat.Size() && !r.Force:
			return nil, fmt.Errorf("cursor at %s expected file size %d, got %d (file was modified). Pass --force to ignore and restart from the cursor's last_index, or delete the cursor to start fresh", cursorPath, existing.FileSize, stat.Size())
		case existing.Completed:
			fmt.Fprintf(r.Out, "  Cursor reports this import is complete. Delete %s to re-run.\n", cursorPath)
			return existing, nil
		default:
			cursor = existing
			fmt.Fprintf(r.Out, "  Resuming from index %d (created=%d existed=%d skipped=%d errored=%d)\n",
				cursor.LastIndex, cursor.Summary.Created, cursor.Summary.Existed, cursor.Summary.Skipped, cursor.Summary.Errored)
		}
	}

	f, err := os.Open(r.File)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	limiter := newRateLimiter(r.RateLimit, r.NowFunc, r.SleepFunc)

	startIndex := cursor.LastIndex
	idx := -1
	processed := 0

	emit := func(u SourceUser) error {
		idx++
		if idx < startIndex {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		processed++

		if u.Email == "" {
			cursor.Summary.Skipped++
			cursor.LastIndex = idx + 1
			r.maybeProgress(processed, cursor)
			return nil
		}

		if r.DryRun {
			cursor.Summary.Created++ // dry-run optimistically counts as create
			cursor.LastIndex = idx + 1
			r.maybeProgress(processed, cursor)
			return nil
		}

		limiter.Wait()
		status, _, err := r.postUser(ctx, u)
		switch {
		case err != nil:
			cursor.Summary.Errored++
			fmt.Fprintf(r.Out, "    err   %s — %v\n", u.Email, err)
		case status == http.StatusCreated:
			cursor.Summary.Created++
		case status == http.StatusOK:
			cursor.Summary.Existed++
		default:
			cursor.Summary.Errored++
		}
		cursor.LastIndex = idx + 1
		// Persist cursor every 25 records so a kill-9 doesn't lose much.
		if processed%25 == 0 {
			_ = saveCursor(cursorPath, cursor)
		}
		r.maybeProgress(processed, cursor)
		return nil
	}

	if err := r.Parser.Parse(ctx, f, emit); err != nil {
		_ = saveCursor(cursorPath, cursor)
		return cursor, err
	}

	cursor.Completed = true
	if err := saveCursor(cursorPath, cursor); err != nil {
		return cursor, err
	}
	if cursor.Summary.Errored == 0 {
		_ = os.Remove(cursorPath)
	}

	fmt.Fprintf(r.Out, "  Done. created=%d existed=%d skipped=%d errored=%d\n",
		cursor.Summary.Created, cursor.Summary.Existed, cursor.Summary.Skipped, cursor.Summary.Errored)
	return cursor, nil
}

func (r *ImportRunner) maybeProgress(processed int, c *Cursor) {
	if processed > 0 && processed%50 == 0 {
		fmt.Fprintf(r.Out, "  ... %d processed (created=%d existed=%d skipped=%d errored=%d)\n",
			processed, c.Summary.Created, c.Summary.Existed, c.Summary.Skipped, c.Summary.Errored)
	}
}

func (r *ImportRunner) postUser(ctx context.Context, u SourceUser) (int, []byte, error) {
	body, _ := json.Marshal(map[string]any{
		"email":          strings.ToLower(strings.TrimSpace(u.Email)),
		"name":           u.Name,
		"email_verified": u.EmailVerified,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.APIURL+"/v1/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.APIKey)
	req.Header.Set("User-Agent", r.UserAgent)
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, nil
}

// =====================================================================
// dispatch helper used by Import (one entry per provider)
// =====================================================================

type importFlags struct {
	File      string
	Profile   string
	DryRun    bool
	Force     bool
	RateLimit int
	APIURL    string
}

func parseImportFlags(args []string) (*importFlags, error) {
	f := &importFlags{Profile: "default", RateLimit: 50}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file":
			if i+1 < len(args) {
				f.File = args[i+1]
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				f.Profile = args[i+1]
				i++
			}
		case "--api-url":
			if i+1 < len(args) {
				f.APIURL = args[i+1]
				i++
			}
		case "--rate-limit-rps":
			if i+1 < len(args) {
				var n int
				if _, err := fmt.Sscanf(args[i+1], "%d", &n); err == nil && n > 0 {
					f.RateLimit = n
				}
				i++
			}
		case "--dry-run":
			f.DryRun = true
		case "--force":
			f.Force = true
		}
	}
	if f.File == "" {
		return nil, errors.New("--file <path> is required")
	}
	return f, nil
}

// runProviderImport wires the flags + credentials lookup + runner for one
// provider. Used by every provider-specific Import* function.
func runProviderImport(parser Parser, args []string) error {
	flags, err := parseImportFlags(args)
	if err != nil {
		return err
	}
	runner := &ImportRunner{
		Parser:    parser,
		File:      flags.File,
		DryRun:    flags.DryRun,
		Force:     flags.Force,
		RateLimit: flags.RateLimit,
	}
	if !flags.DryRun {
		store, err := credentials.DefaultStore()
		if err != nil {
			return err
		}
		creds, err := store.Load(flags.Profile)
		if err != nil {
			return err
		}
		apiURL := flags.APIURL
		if apiURL == "" {
			apiURL = creds.APIURL
		}
		if apiURL == "" {
			apiURL = defaultMgmtAPI
		}
		runner.APIKey = creds.APIKey
		runner.APIURL = strings.TrimRight(apiURL, "/")
	}
	_, err = runner.Run(context.Background())
	return err
}
