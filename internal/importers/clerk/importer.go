package clerk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Options controls a single import run. Zero-valued options are sensible
// defaults (rate=DefaultRateLimit, all include-* flags true).
type Options struct {
	// DryRun fetches from Clerk and writes nothing to Authio. Useful
	// for the customer's pre-flight check.
	DryRun bool

	// Include* gate optional pieces. All default to true via NewImporter.
	IncludeUsers          bool
	IncludeOrgs           bool
	IncludeMemberships    bool
	IncludeOAuthBindings  bool
	IncludeMFA            bool

	// SendWelcomeEmail, if true, is forwarded to the management-api so
	// it queues an "your account moved" email per imported user.
	SendWelcomeEmail bool

	// RateLimit caps requests/sec to BOTH Clerk and Authio. Defaults to
	// DefaultRateLimit (50/sec).
	RateLimit float64

	// BatchSize controls how many rows are sent per bulk POST. Defaults
	// to 100. Higher values exchange tail-latency for fewer round-trips.
	BatchSize int

	// ResumeFrom, when non-empty, loads cursor state from that path
	// instead of the default $HOME/.authio/clerk-import-state.json.
	ResumeFrom string

	// StatePath overrides the default state file path. Useful for
	// tests that don't want to touch $HOME.
	StatePath string

	// ReportPath overrides the default CSV report path (next to the
	// state file).
	ReportPath string

	// ClerkBaseURL overrides https://api.clerk.com — used by tests with
	// httptest.Server.
	ClerkBaseURL string

	// HomeDir overrides os.UserHomeDir() for state-path resolution.
	HomeDir string
}

// Importer is one configured Clerk -> Authio import. Construct via
// NewImporter, then call Run.
type Importer struct {
	SecretKey       string // Clerk Backend API secret_key
	AuthioAPIURL    string
	AuthioAPIKey    string
	AuthioProjectID string
	Options         Options

	Out      io.Writer // progress sink; defaults to os.Stdout
	NowFunc  func() time.Time
	Reporter *Reporter

	clerk  *ClerkClient
	authio *AuthioClient
}

// NewImporter wires the two clients and validates required fields.
// Sets all include-* options to true when they're zero (Go's default
// for bool flag-parsing is "not set" -> false; the caller in the CLI
// dispatcher pre-fills them).
func NewImporter(secretKey, authioAPIURL, authioAPIKey, authioProjectID string, opts Options) (*Importer, error) {
	if secretKey == "" {
		return nil, errors.New("clerk: secret_key required")
	}
	if authioAPIKey == "" {
		return nil, errors.New("authio: api_key required (run `authio login` or pass --api-key)")
	}
	if authioProjectID == "" {
		return nil, errors.New("authio: project_id required (pass --authio-project)")
	}
	if opts.RateLimit <= 0 {
		opts.RateLimit = DefaultRateLimit
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 100
	}
	imp := &Importer{
		SecretKey:       secretKey,
		AuthioAPIURL:    authioAPIURL,
		AuthioAPIKey:    authioAPIKey,
		AuthioProjectID: authioProjectID,
		Options:         opts,
		Out:             os.Stdout,
		NowFunc:         time.Now,
		Reporter:        NewReporter(),
	}
	imp.clerk = NewClerkClient(secretKey, opts.ClerkBaseURL, opts.RateLimit)
	imp.authio = NewAuthioClient(authioAPIURL, authioAPIKey, opts.RateLimit)
	return imp, nil
}

// Summary is the end-of-run aggregate the CLI prints.
type Summary struct {
	Started   time.Time
	Finished  time.Time
	State     *State
	Imported  int
	Existed   int
	Skipped   int
	Errored   int
	ReportPath string
}

// Run executes the import: fetch users (paginated) -> bulk import;
// fetch orgs -> bulk import; fetch each org's memberships -> bulk
// import. State is checkpointed after every batch. Failures within a
// batch don't abort — they get logged to the CSV report and the run
// continues.
func (i *Importer) Run(ctx context.Context) (*Summary, error) {
	statePath := i.Options.StatePath
	if statePath == "" {
		p, err := StateFilePath(i.Options.HomeDir)
		if err != nil {
			return nil, err
		}
		statePath = p
	}
	resumePath := i.Options.ResumeFrom
	if resumePath == "" {
		resumePath = statePath
	}
	state, err := LoadState(resumePath)
	if err != nil {
		return nil, fmt.Errorf("load resume state: %w", err)
	}
	if state == nil {
		state = &State{
			Version:         1,
			AuthioProjectID: i.AuthioProjectID,
			ClerkBaseURL:    i.Options.ClerkBaseURL,
			StartedAt:       i.NowFunc().UTC(),
		}
	} else if state.AuthioProjectID != "" && state.AuthioProjectID != i.AuthioProjectID {
		return nil, fmt.Errorf("resume state belongs to project %q but importer targets %q — delete %s or use --resume-from",
			state.AuthioProjectID, i.AuthioProjectID, resumePath)
	}

	summary := &Summary{
		Started: i.NowFunc().UTC(),
		State:   state,
	}

	fmt.Fprintf(i.Out, "  Importing from Clerk -> Authio project %s\n", i.AuthioProjectID)
	if i.Options.DryRun {
		fmt.Fprintln(i.Out, "  Mode: DRY-RUN (no writes)")
	}

	if i.Options.IncludeUsers && !state.UsersDone {
		if err := i.importUsers(ctx, state, statePath); err != nil {
			i.persistAndReport(statePath, state, summary)
			return summary, err
		}
		state.UsersDone = true
		if err := SaveState(statePath, state); err != nil {
			return summary, err
		}
	}

	if i.Options.IncludeOrgs && !state.OrgsDone {
		if err := i.importOrgs(ctx, state, statePath); err != nil {
			i.persistAndReport(statePath, state, summary)
			return summary, err
		}
		state.OrgsDone = true
		if err := SaveState(statePath, state); err != nil {
			return summary, err
		}
	}

	if i.Options.IncludeMemberships {
		if err := i.importMemberships(ctx, state, statePath); err != nil {
			i.persistAndReport(statePath, state, summary)
			return summary, err
		}
	}

	state.Completed = true
	if err := SaveState(statePath, state); err != nil {
		return summary, err
	}

	i.persistAndReport(statePath, state, summary)
	summary.Finished = i.NowFunc().UTC()
	imp, ex, sk, errd := i.Reporter.Counts()
	summary.Imported = imp
	summary.Existed = ex
	summary.Skipped = sk
	summary.Errored = errd
	// Clean up the state file on a clean run (no errors). Customers can
	// re-run with --include-mfa later without tripping the resume.
	if errd == 0 && !i.Options.DryRun {
		_ = ClearState(statePath)
	}
	fmt.Fprintf(i.Out, "  Done. %s\n", i.Reporter.FormatSummary())
	if summary.ReportPath != "" {
		fmt.Fprintf(i.Out, "  Per-row report: %s\n", summary.ReportPath)
	}
	return summary, nil
}

// importUsers paginates Clerk users and ships each page as a single
// bulk POST. Failed rows are recorded; the batch continues.
func (i *Importer) importUsers(ctx context.Context, state *State, statePath string) error {
	fmt.Fprintln(i.Out, "  Step 1/3: importing users...")
	opts := TransformOptions{
		IncludeOAuthBindings: i.Options.IncludeOAuthBindings,
		IncludeMFA:           i.Options.IncludeMFA,
	}
	return i.clerk.IterateUsers(ctx, state.LastUserOffset, func(page UserPage, offset int) (bool, error) {
		var batch []AuthioUserPayload
		for _, u := range page.Users {
			state.UsersSeen++
			payload, reason, ok := TransformUser(u, opts)
			if !ok {
				state.UsersSkipped++
				i.Reporter.Add(ReportRow{
					Kind:     "user",
					SourceID: u.ID,
					Status:   "skipped",
					Message:  reason,
				})
				continue
			}
			batch = append(batch, payload)
		}
		if len(batch) > 0 {
			if err := i.shipUserBatch(ctx, batch, state); err != nil {
				return false, err
			}
		}
		state.LastUserOffset = offset + len(page.Users)
		if err := SaveState(statePath, state); err != nil {
			return false, err
		}
		fmt.Fprintf(i.Out, "    users batch offset=%d size=%d (cumulative imported=%d existed=%d skipped=%d errored=%d)\n",
			offset, len(page.Users), state.UsersImported, state.UsersExisted, state.UsersSkipped, state.UsersErrored)
		return true, nil
	})
}

// shipUserBatch posts a batch to bulk-users and records per-row results.
// In dry-run mode we record imported but skip the network call.
func (i *Importer) shipUserBatch(ctx context.Context, batch []AuthioUserPayload, state *State) error {
	if i.Options.DryRun {
		for _, u := range batch {
			state.UsersImported++
			i.Reporter.Add(ReportRow{
				Kind:     "user",
				SourceID: u.ClerkUserID,
				Status:   "imported",
				Message:  "dry-run",
			})
		}
		return nil
	}
	for chunk := range chunks(batch, i.Options.BatchSize) {
		results, err := i.authio.PostBulkUsers(ctx, chunk)
		if err != nil {
			// Treat the entire chunk as errored so the report has
			// per-row visibility even when the request itself failed.
			for _, u := range chunk {
				state.UsersErrored++
				i.Reporter.Add(ReportRow{
					Kind:     "user",
					SourceID: u.ClerkUserID,
					Status:   "error",
					Message:  err.Error(),
				})
			}
			continue
		}
		applyResults(results, batchSourceIDs(chunk), state, i.Reporter, "user",
			&state.UsersImported, &state.UsersExisted, &state.UsersErrored)
	}
	return nil
}

func (i *Importer) importOrgs(ctx context.Context, state *State, statePath string) error {
	fmt.Fprintln(i.Out, "  Step 2/3: importing organizations...")
	return i.clerk.IterateOrganizations(ctx, state.LastOrgOffset, func(page OrgPage, offset int) (bool, error) {
		var batch []AuthioOrgPayload
		for _, o := range page.Orgs {
			state.OrgsSeen++
			batch = append(batch, TransformOrganization(o))
		}
		if len(batch) > 0 {
			if err := i.shipOrgBatch(ctx, batch, state); err != nil {
				return false, err
			}
		}
		state.LastOrgOffset = offset + len(page.Orgs)
		if err := SaveState(statePath, state); err != nil {
			return false, err
		}
		fmt.Fprintf(i.Out, "    orgs batch offset=%d size=%d (cumulative imported=%d existed=%d errored=%d)\n",
			offset, len(page.Orgs), state.OrgsImported, state.OrgsExisted, state.OrgsErrored)
		return true, nil
	})
}

func (i *Importer) shipOrgBatch(ctx context.Context, batch []AuthioOrgPayload, state *State) error {
	if i.Options.DryRun {
		for _, o := range batch {
			state.OrgsImported++
			i.Reporter.Add(ReportRow{
				Kind:     "organization",
				SourceID: o.ClerkOrgID,
				Status:   "imported",
				Message:  "dry-run",
			})
		}
		return nil
	}
	for chunk := range chunks(batch, i.Options.BatchSize) {
		results, err := i.authio.PostBulkOrganizations(ctx, chunk)
		if err != nil {
			for _, o := range chunk {
				state.OrgsErrored++
				i.Reporter.Add(ReportRow{
					Kind:     "organization",
					SourceID: o.ClerkOrgID,
					Status:   "error",
					Message:  err.Error(),
				})
			}
			continue
		}
		applyResults(results, orgSourceIDs(chunk), state, i.Reporter, "organization",
			&state.OrgsImported, &state.OrgsExisted, &state.OrgsErrored)
	}
	return nil
}

func (i *Importer) importMemberships(ctx context.Context, state *State, statePath string) error {
	fmt.Fprintln(i.Out, "  Step 3/3: importing memberships...")
	// Re-fetch org IDs from Clerk (lightweight) so we don't have to
	// persist them in state. This sidesteps the "what if the org list
	// changed between resume runs" question — we always read fresh.
	var orgIDs []string
	err := i.clerk.IterateOrganizations(ctx, 0, func(page OrgPage, _ int) (bool, error) {
		for _, o := range page.Orgs {
			orgIDs = append(orgIDs, o.ID)
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	if len(orgIDs) == 0 {
		fmt.Fprintln(i.Out, "    no organizations found; skipping memberships.")
		return nil
	}
	for _, orgID := range orgIDs {
		var batch []AuthioMembershipPayload
		err := i.clerk.IterateMemberships(ctx, orgID, func(page MembershipPage, _ int) (bool, error) {
			for _, m := range page.Memberships {
				state.MembershipsSeen++
				batch = append(batch, TransformMembership(m))
			}
			return true, nil
		})
		if err != nil {
			fmt.Fprintf(i.Out, "    memberships for org %s: error %v (continuing)\n", orgID, err)
			i.Reporter.Add(ReportRow{
				Kind:     "membership",
				SourceID: orgID,
				Status:   "error",
				Message:  fmt.Sprintf("fetch failed: %v", err),
			})
			continue
		}
		if len(batch) == 0 {
			continue
		}
		if err := i.shipMembershipBatch(ctx, batch, state); err != nil {
			return err
		}
		if err := SaveState(statePath, state); err != nil {
			return err
		}
	}
	return nil
}

func (i *Importer) shipMembershipBatch(ctx context.Context, batch []AuthioMembershipPayload, state *State) error {
	if i.Options.DryRun {
		for _, m := range batch {
			state.MembershipsCreated++
			i.Reporter.Add(ReportRow{
				Kind:     "membership",
				SourceID: m.ClerkMembershipID,
				Status:   "imported",
				Message:  "dry-run",
			})
		}
		return nil
	}
	for chunk := range chunks(batch, i.Options.BatchSize) {
		results, err := i.authio.PostBulkMemberships(ctx, chunk)
		if err != nil {
			for _, m := range chunk {
				state.MembershipsErrored++
				i.Reporter.Add(ReportRow{
					Kind:     "membership",
					SourceID: m.ClerkMembershipID,
					Status:   "error",
					Message:  err.Error(),
				})
			}
			continue
		}
		applyResults(results, membershipSourceIDs(chunk), state, i.Reporter, "membership",
			&state.MembershipsCreated, &state.MembershipsExisted, &state.MembershipsErrored)
	}
	return nil
}

// persistAndReport writes the CSV report and a final state save. Called
// in both success + error paths.
func (i *Importer) persistAndReport(statePath string, state *State, summary *Summary) {
	reportPath := i.Options.ReportPath
	if reportPath == "" {
		reportPath = defaultReportPath(statePath)
	}
	if err := i.Reporter.WriteFile(reportPath); err != nil {
		fmt.Fprintf(i.Out, "  WARN: write report %s: %v\n", reportPath, err)
		return
	}
	summary.ReportPath = reportPath
}

func defaultReportPath(statePath string) string {
	// Side-by-side with the state file:
	//   $HOME/.authio/clerk-import-state.json
	//   $HOME/.authio/clerk-import-report.csv
	dir := statePath
	for len(dir) > 0 && dir[len(dir)-1] != '/' {
		dir = dir[:len(dir)-1]
	}
	if dir == "" {
		dir = "./"
	}
	return dir + "clerk-import-report.csv"
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// chunks yields successive sub-slices of size n. Mirrors slices.Chunk
// from Go 1.23 but we keep the file friendly to older toolchains too.
func chunks[T any](in []T, n int) func(yield func([]T) bool) {
	return func(yield func([]T) bool) {
		if n <= 0 {
			yield(in)
			return
		}
		for start := 0; start < len(in); start += n {
			end := start + n
			if end > len(in) {
				end = len(in)
			}
			if !yield(in[start:end]) {
				return
			}
		}
	}
}

// applyResults walks the management-api's per-row response and updates
// counters + the report. Each result either reports created/existed/error
// against the source_id; any source_id absent from the response is
// reported as "error: missing in response".
func applyResults(
	results []BulkResult,
	sourceIDs []string,
	state *State,
	rep *Reporter,
	kind string,
	importedCounter, existedCounter, erroredCounter *int,
) {
	seen := map[string]struct{}{}
	for _, r := range results {
		seen[r.SourceID] = struct{}{}
		switch r.Status {
		case "created", "imported":
			*importedCounter++
			rep.Add(ReportRow{Kind: kind, SourceID: r.SourceID, AuthioID: r.AuthioID, Status: "imported"})
		case "existed":
			*existedCounter++
			rep.Add(ReportRow{Kind: kind, SourceID: r.SourceID, AuthioID: r.AuthioID, Status: "existed"})
		default:
			*erroredCounter++
			msg := r.Error
			if msg == "" {
				msg = "unknown status: " + r.Status
			}
			rep.Add(ReportRow{Kind: kind, SourceID: r.SourceID, AuthioID: r.AuthioID, Status: "error", Message: msg})
		}
	}
	for _, id := range sourceIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		*erroredCounter++
		rep.Add(ReportRow{Kind: kind, SourceID: id, Status: "error", Message: "missing from server response"})
	}
	_ = state // counters are already updated via the *int pointers
}

func batchSourceIDs(in []AuthioUserPayload) []string {
	out := make([]string, len(in))
	for i, u := range in {
		out[i] = u.ClerkUserID
	}
	return out
}

func orgSourceIDs(in []AuthioOrgPayload) []string {
	out := make([]string, len(in))
	for i, o := range in {
		out[i] = o.ClerkOrgID
	}
	return out
}

func membershipSourceIDs(in []AuthioMembershipPayload) []string {
	out := make([]string, len(in))
	for i, m := range in {
		out[i] = m.ClerkMembershipID
	}
	return out
}
