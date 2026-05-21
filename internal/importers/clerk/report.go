package clerk

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ReportRow is one line of the CSV report written at the end of an
// import. Importers collect rows as they go so a failed run still
// leaves a partial report on disk.
type ReportRow struct {
	Kind     string // user | organization | membership
	SourceID string // clerk_user_id / clerk_org_id / clerk_membership_id
	AuthioID string // resolved id post-write, if any
	Status   string // imported | existed | skipped | error
	Message  string // free-form: error text / skip reason
}

// Reporter buffers ReportRow records and flushes them as CSV. It is
// goroutine-safe.
type Reporter struct {
	mu   sync.Mutex
	rows []ReportRow
}

// NewReporter returns an empty Reporter.
func NewReporter() *Reporter { return &Reporter{} }

// Add appends a row.
func (r *Reporter) Add(row ReportRow) {
	r.mu.Lock()
	r.rows = append(r.rows, row)
	r.mu.Unlock()
}

// Rows returns a copy of the buffered rows (for tests + dry-run inspection).
func (r *Reporter) Rows() []ReportRow {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ReportRow, len(r.rows))
	copy(out, r.rows)
	return out
}

// Counts tallies rows by status.
func (r *Reporter) Counts() (imported, existed, skipped, errored int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		switch row.Status {
		case "imported", "created":
			imported++
		case "existed":
			existed++
		case "skipped":
			skipped++
		case "error":
			errored++
		}
	}
	return
}

// WriteCSV writes the report to w as CSV. The first line is the header.
func (r *Reporter) WriteCSV(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	wr := csv.NewWriter(w)
	if err := wr.Write([]string{"kind", "source_id", "authio_id", "status", "message"}); err != nil {
		return err
	}
	for _, row := range r.rows {
		if err := wr.Write([]string{row.Kind, row.SourceID, row.AuthioID, row.Status, sanitizeMessage(row.Message)}); err != nil {
			return err
		}
	}
	wr.Flush()
	return wr.Error()
}

// WriteFile writes to a file, creating parents as needed. Empty path is
// a no-op (some tests and dry-run mode skip the file).
func (r *Reporter) WriteFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.WriteCSV(f)
}

// sanitizeMessage strips control chars and clamps length so an
// unexpectedly verbose API error doesn't blow up the CSV.
func sanitizeMessage(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return strings.TrimSpace(s)
}

// FormatSummary renders a one-line summary for end-of-run output.
func (r *Reporter) FormatSummary() string {
	imp, ex, sk, err := r.Counts()
	return fmt.Sprintf("imported=%d existed=%d skipped=%d errored=%d", imp, ex, sk, err)
}
