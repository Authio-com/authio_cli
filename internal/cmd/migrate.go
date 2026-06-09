package cmd

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Migrate dispatches `authio migrate <subcommand>`.
//
// The only public subcommand today is `migrate run --job-id <id>`,
// invoked by the authio_management-api when it queues a live-credentials
// import. The CLI:
//
//   1. Asks the management-api for the job + the credential envelope
//      (over HTTP, using AUTHIO_MIGRATE_WORKER_TOKEN as bearer).
//   2. Decrypts the envelope using AUTHIO_IMPORT_CREDS_KEY.
//   3. Runs the per-provider PullLive.
//   4. Pipes the resulting plan through PlanRunner against the
//      Authio management-API (using the same bearer).
//   5. PATCHes progress / POSTs finish back to /v1/migrate/jobs/...
//      so the dashboard's polling UI sees live updates.
//
// `migrate plan --provider <p> --live-token <t> [--auth0-domain …]`
// bypasses the DB and prints the plan as JSON — useful for previews
// and for the e2e harness.
func Migrate(args []string) error {
	if len(args) == 0 {
		return errors.New(migrateUsage())
	}
	switch args[0] {
	case "run":
		return migrateRun(args[1:])
	case "plan":
		return migratePlan(args[1:])
	case "help", "--help", "-h":
		fmt.Println(migrateUsage())
		return nil
	}
	return errors.New("unknown migrate subcommand: " + args[0])
}

func migrateUsage() string {
	return `usage: authio migrate <subcommand>

SUBCOMMANDS
  run --job-id <id>           Execute a queued import job. Talks to
                              authio_management-api over HTTP.
                              Requires AUTHIO_MGMT_API_URL,
                              AUTHIO_MIGRATE_WORKER_TOKEN,
                              AUTHIO_IMPORT_CREDS_KEY.

  plan --provider <p>         Pull a plan via live credentials and print
       --live-token <token>   as JSON. No DB, no writes.
       [--auth0-domain <d>]   (Auth0 only)
       [--stytch-project-id … --stytch-secret …]
       [--descope-project-id …]
       [--supabase-ref …]
       [--max-pages N]
       [--base-url <url>]     Override provider host (testing).`
}

// =====================================================================
// migrate plan — live pull + JSON print, no DB.
// =====================================================================

type migratePlanFlags struct {
	Provider string
	BaseURL  string
	MaxPages int
	Creds    LiveCredentials
}

func parseMigratePlanFlags(args []string) (*migratePlanFlags, error) {
	f := &migratePlanFlags{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--provider":
			if i+1 < len(args) {
				f.Provider = args[i+1]
				i++
			}
		case "--live-token":
			if i+1 < len(args) {
				switch strings.ToLower(f.Provider) {
				case "auth0":
					f.Creds.Token = args[i+1]
				case "clerk":
					f.Creds.SecretKey = args[i+1]
				case "workos":
					f.Creds.APIKey = args[i+1]
				case "descope":
					f.Creds.MgmtKey = args[i+1]
				case "supabase":
					f.Creds.PAT = args[i+1]
				default:
					f.Creds.Token = args[i+1]
				}
				i++
			}
		case "--auth0-domain":
			if i+1 < len(args) {
				f.Creds.Domain = args[i+1]
				i++
			}
		case "--stytch-project-id":
			if i+1 < len(args) {
				f.Creds.ProjectID = args[i+1]
				i++
			}
		case "--stytch-secret":
			if i+1 < len(args) {
				f.Creds.ProjectSecret = args[i+1]
				i++
			}
		case "--descope-project-id":
			if i+1 < len(args) {
				f.Creds.ProjectID = args[i+1]
				i++
			}
		case "--supabase-ref":
			if i+1 < len(args) {
				f.Creds.ProjectRef = args[i+1]
				i++
			}
		case "--base-url":
			if i+1 < len(args) {
				f.BaseURL = args[i+1]
				i++
			}
		case "--max-pages":
			if i+1 < len(args) {
				var n int
				fmt.Sscanf(args[i+1], "%d", &n)
				f.MaxPages = n
				i++
			}
		}
	}
	if f.Provider == "" {
		return nil, errors.New("--provider is required")
	}
	return f, nil
}

func migratePlan(args []string) error {
	f, err := parseMigratePlanFlags(args)
	if err != nil {
		return err
	}
	puller, err := LivePullerFor(f.Provider)
	if err != nil {
		return err
	}
	plan, err := puller.PullLive(context.Background(), f.Creds, LiveOptions{
		BaseURLOverride: f.BaseURL,
		MaxPages:        f.MaxPages,
	})
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(plan)
}

// =====================================================================
// migrate run — talks back to the management-api over HTTP.
// =====================================================================

type migrateRunFlags struct {
	JobID string
}

func parseMigrateRunFlags(args []string) (*migrateRunFlags, error) {
	f := &migrateRunFlags{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--job-id" && i+1 < len(args) {
			f.JobID = args[i+1]
			i++
		}
	}
	if f.JobID == "" {
		return nil, errors.New("--job-id is required")
	}
	return f, nil
}

func migrateRun(args []string) error {
	f, err := parseMigrateRunFlags(args)
	if err != nil {
		return err
	}
	mgmtURL := os.Getenv("AUTHIO_MGMT_API_URL")
	if mgmtURL == "" {
		mgmtURL = defaultMgmtAPI
	}
	workerToken := os.Getenv("AUTHIO_MIGRATE_WORKER_TOKEN")
	if workerToken == "" {
		return errors.New("AUTHIO_MIGRATE_WORKER_TOKEN is required (the worker auth header)")
	}
	wc := &workerClient{
		BaseURL: strings.TrimRight(mgmtURL, "/"),
		Token:   workerToken,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	job, err := wc.fetchJob(ctx, f.JobID)
	if err != nil {
		return fmt.Errorf("fetch job: %w", err)
	}
	if job.Source != "live_credentials" {
		return fmt.Errorf("migrate run: unexpected source %q", job.Source)
	}
	if job.CredentialID == nil || *job.CredentialID == "" {
		return errors.New("migrate run: job has no credential_id")
	}

	cred, err := wc.fetchCredential(ctx, *job.CredentialID)
	if err != nil {
		return fmt.Errorf("fetch credential: %w", err)
	}
	creds, err := openCredEnvelope(job.ProjectID, cred.Envelope)
	if err != nil {
		return fmt.Errorf("open credential envelope: %w", err)
	}
	puller, err := LivePullerFor(job.Provider)
	if err != nil {
		return err
	}

	var lastPushed atomic.Int64
	progress := map[string]int{}
	pushProgress := func(force bool) {
		now := time.Now().UnixMilli()
		if !force && now-lastPushed.Load() < 1500 {
			return
		}
		lastPushed.Store(now)
		_ = wc.patchProgress(ctx, job.ID, progress)
	}
	progFn := func(kind string, completed int) {
		progress[kind] = completed
		pushProgress(false)
	}

	plan, err := puller.PullLive(ctx, creds, LiveOptions{ProgressFn: progFn})
	if err != nil {
		_ = wc.finishJob(ctx, job.ID, "failed", nil, err.Error(), nil)
		return err
	}
	pushProgress(true)

	runner := &PlanRunner{
		APIURL:   wc.BaseURL,
		APIKey:   wc.Token,
		HTTP:     wc.HTTP,
		Out:      progressWriter(func(line string) { _ = wc.appendLog(ctx, job.ID, line) }),
		EmitJSON: true,
		ExtraHeaders: map[string]string{
			"X-Authio-Worker":     "1",
			"X-Authio-Project-Id": job.ProjectID,
		},
	}
	stats, err := runner.Run(ctx, plan)
	if err != nil {
		_ = wc.finishJob(ctx, job.ID, "failed", &stats, err.Error(), runner.RecordErrors)
		return err
	}
	status := "succeeded"
	if stats.Errored > 0 {
		status = "partial"
	}
	if err := wc.finishJob(ctx, job.ID, status, &stats, "", runner.RecordErrors); err != nil {
		return err
	}
	return nil
}

// =====================================================================
// progressWriter adapts a per-line callback to io.Writer.
// =====================================================================

type progressWriterFn func(line string)

func (f progressWriterFn) Write(p []byte) (int, error) {
	for _, ln := range strings.Split(string(p), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			f(ln)
		}
	}
	return len(p), nil
}

func progressWriter(fn func(line string)) progressWriterFn { return progressWriterFn(fn) }

// =====================================================================
// workerClient — tiny HTTP wrapper for the management-api worker
// endpoints. Authorization is `Bearer <worker token>`. Worker requests
// hit /v1/migrate/* with an `x-authio-worker: 1` header so the
// management-api routes them to the worker-only paths.
// =====================================================================

type workerClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

type jobRecord struct {
	ID           string  `json:"id"`
	ProjectID    string  `json:"project_id"`
	Provider     string  `json:"provider"`
	Source       string  `json:"source"`
	CredentialID *string `json:"credential_id"`
	Status       string  `json:"status"`
}

type credRecord struct {
	ID       string          `json:"id"`
	Envelope CredEnvelopeRaw `json:"envelope"`
}

// CredEnvelopeRaw mirrors the JSONB envelope the management-api stores.
// See authio_management-api/src/import_credentials.ts for the canonical
// shape; both sides MUST stay in lockstep.
type CredEnvelopeRaw struct {
	KekID         string `json:"kek_id"`
	Alg           string `json:"alg"`
	Nonce         string `json:"nonce"`
	Tag           string `json:"tag"`
	Ciphertext    string `json:"ciphertext"`
	DekNonce      string `json:"dek_nonce"`
	DekTag        string `json:"dek_tag"`
	DekCiphertext string `json:"dek_ciphertext"`
}

func (w *workerClient) do(ctx context.Context, method, path string, body any, into any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, w.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	req.Header.Set("User-Agent", "authio-cli-migrate-worker/0.1")
	req.Header.Set("X-Authio-Worker", "1")
	resp, err := w.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: %d (%s)", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if into != nil {
		return json.NewDecoder(resp.Body).Decode(into)
	}
	return nil
}

func (w *workerClient) fetchJob(ctx context.Context, id string) (*jobRecord, error) {
	var r jobRecord
	if err := w.do(ctx, http.MethodGet, "/v1/migrate-worker/jobs/"+id, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (w *workerClient) fetchCredential(ctx context.Context, id string) (*credRecord, error) {
	var r credRecord
	if err := w.do(ctx, http.MethodGet, "/v1/migrate-worker/credentials/"+id, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (w *workerClient) patchProgress(ctx context.Context, jobID string, progress map[string]int) error {
	return w.do(ctx, http.MethodPatch, "/v1/migrate-worker/jobs/"+jobID+"/progress",
		map[string]any{"progress": progress}, nil)
}

func (w *workerClient) appendLog(ctx context.Context, jobID, line string) error {
	return w.do(ctx, http.MethodPost, "/v1/migrate-worker/jobs/"+jobID+"/log",
		map[string]any{"line": line}, nil)
}

func (w *workerClient) finishJob(ctx context.Context, jobID, status string, stats *PlanStats, errMsg string, recordErrors []RecordError) error {
	body := map[string]any{"status": status}
	if stats != nil {
		body["stats"] = stats
	}
	if errMsg != "" {
		body["error"] = errMsg
	}
	if len(recordErrors) > 0 {
		body["record_errors"] = recordErrors
	}
	return w.do(ctx, http.MethodPost, "/v1/migrate-worker/jobs/"+jobID+"/finish", body, nil)
}

// =====================================================================
// Envelope unwrap — mirrors authio_management-api/src/import_credentials.ts.
// Algorithm: AES-256-GCM AEAD with per-row DEK wrapped by per-project KEK.
// AUTHIO_REDACT — the returned LiveCredentials carries the operator's
// admin token; treat as high-risk.
// =====================================================================

func openCredEnvelope(projectID string, env CredEnvelopeRaw) (LiveCredentials, error) {
	if env.Alg != "aes-256-gcm" {
		return LiveCredentials{}, fmt.Errorf("unsupported envelope alg %q", env.Alg)
	}
	kekMaster := os.Getenv("AUTHIO_IMPORT_CREDS_KEY")
	if kekMaster == "" {
		return LiveCredentials{}, errors.New("AUTHIO_IMPORT_CREDS_KEY not set on worker; cannot decrypt envelope")
	}
	if env.KekID != "env" {
		return LiveCredentials{}, fmt.Errorf("envelope sealed with kek_id=%q (need 'env')", env.KekID)
	}
	master := deriveMasterKey(kekMaster)
	kek := deriveProjectKEK(master, projectID)

	dekNonce, err1 := base64.StdEncoding.DecodeString(env.DekNonce)
	dekTag, err2 := base64.StdEncoding.DecodeString(env.DekTag)
	dekCt, err3 := base64.StdEncoding.DecodeString(env.DekCiphertext)
	if err := firstErr(err1, err2, err3); err != nil {
		return LiveCredentials{}, fmt.Errorf("decode dek envelope: %w", err)
	}
	dek, err := gcmOpen(kek, dekNonce, append(dekCt, dekTag...))
	if err != nil {
		return LiveCredentials{}, fmt.Errorf("unwrap dek: %w", err)
	}

	nonce, err4 := base64.StdEncoding.DecodeString(env.Nonce)
	tag, err5 := base64.StdEncoding.DecodeString(env.Tag)
	ct, err6 := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err := firstErr(err4, err5, err6); err != nil {
		return LiveCredentials{}, fmt.Errorf("decode payload envelope: %w", err)
	}
	plain, err := gcmOpen(dek, nonce, append(ct, tag...))
	if err != nil {
		return LiveCredentials{}, fmt.Errorf("unwrap payload: %w", err)
	}
	var creds LiveCredentials
	if err := json.Unmarshal(plain, &creds); err != nil {
		return LiveCredentials{}, fmt.Errorf("decode creds json: %w", err)
	}
	return creds, nil
}

func deriveMasterKey(raw string) []byte {
	// Accept base64 ≥32 bytes, else sha256(raw). Matches the management-
	// api's masterKey() helper exactly.
	if dec, err := base64.StdEncoding.DecodeString(raw); err == nil && len(dec) >= 32 {
		return dec[:32]
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func deriveProjectKEK(master []byte, projectID string) []byte {
	hash := sha256.New()
	hash.Write(master)
	hash.Write([]byte{0})
	hash.Write([]byte(projectID))
	return hash.Sum(nil)
}

func gcmOpen(key, nonce, ctAndTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ctAndTag) < aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, nonce, ctAndTag, nil)
}

func gcmSeal(key, nonce, plaintext []byte) (ct []byte, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	if len(sealed) < aead.Overhead() {
		return nil, nil, errors.New("seal too short")
	}
	overhead := aead.Overhead()
	ct = sealed[:len(sealed)-overhead]
	tag = sealed[len(sealed)-overhead:]
	return ct, tag, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// Exported test helpers — used by the e2e tests in authio_e2e-tests
// and the in-package tests in import_live_*_test.go.
//
// SealForTest produces an envelope identical to what the management-api
// would write for `creds`. Tests use this to fake an import_credentials
// row without booting Postgres.
func SealForTest(projectID, masterKey string, creds LiveCredentials) (CredEnvelopeRaw, error) {
	master := deriveMasterKey(masterKey)
	kek := deriveProjectKEK(master, projectID)
	dek := sha256.Sum256([]byte("test-dek-" + projectID))
	dekNonce := []byte("test-dek-non")
	payloadNonce := []byte("test-pay-non")
	payload, err := json.Marshal(creds)
	if err != nil {
		return CredEnvelopeRaw{}, err
	}
	ctDek, tagDek, err := gcmSeal(kek, dekNonce, dek[:])
	if err != nil {
		return CredEnvelopeRaw{}, err
	}
	ctPay, tagPay, err := gcmSeal(dek[:], payloadNonce, payload)
	if err != nil {
		return CredEnvelopeRaw{}, err
	}
	return CredEnvelopeRaw{
		KekID:         "env",
		Alg:           "aes-256-gcm",
		Nonce:         base64.StdEncoding.EncodeToString(payloadNonce),
		Tag:           base64.StdEncoding.EncodeToString(tagPay),
		Ciphertext:    base64.StdEncoding.EncodeToString(ctPay),
		DekNonce:      base64.StdEncoding.EncodeToString(dekNonce),
		DekTag:        base64.StdEncoding.EncodeToString(tagDek),
		DekCiphertext: base64.StdEncoding.EncodeToString(ctDek),
	}, nil
}
