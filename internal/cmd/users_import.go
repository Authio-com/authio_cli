package cmd

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

type usersImportFlags struct {
	File             string
	OrgID            string
	ProjectID        string
	EmailVerified    bool
	DryRun           bool
	DuplicatePolicy  string
	Format           string
	Profile          string
	APIURL           string
	APIKey           string
}

type importUserRow struct {
	Email      string `json:"email"`
	Name       string `json:"name,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
	Role       string `json:"role,omitempty"`
	OrgID      string `json:"org,omitempty"`
}

type usersImportSummary struct {
	Created            int `json:"created"`
	Existed            int `json:"existed"`
	Updated            int `json:"updated"`
	Skipped            int `json:"skipped"`
	Failed             int `json:"failed"`
	MembershipsCreated int `json:"memberships_created"`
	MembershipsExisted int `json:"memberships_existed"`
}

// UsersImport runs `authio users import`.
func UsersImport(args []string) error {
	flags, err := parseUsersImportFlags(args)
	if err != nil {
		return err
	}
	rows, err := parseUsersImportFile(flags.File, flags.Format)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("no valid user rows found in file")
	}

	apiURL := flags.APIURL
	apiKey := flags.APIKey
	if apiKey == "" || apiURL == "" {
		store, err := credentials.DefaultStore()
		if err != nil {
			return err
		}
		creds, err := store.Load(flags.Profile)
		if err != nil {
			return fmt.Errorf("load profile %q: %w", flags.Profile, err)
		}
		if apiKey == "" {
			apiKey = creds.APIKey
		}
		if apiURL == "" {
			apiURL = creds.APIURL
		}
		if flags.ProjectID == "" {
			flags.ProjectID = creds.ProjectID
		}
	}
	if apiURL == "" {
		apiURL = defaultMgmtAPI
	}
	apiURL = strings.TrimRight(apiURL, "/")
	if apiKey == "" {
		return errors.New("--api-key not provided and profile lookup failed")
	}

	fmt.Printf("Importing %d users → %s\n", len(rows), apiURL)
	if flags.OrgID != "" {
		fmt.Printf("Default org membership: %s\n", flags.OrgID)
	}
	if flags.DryRun {
		fmt.Println("Dry run — no writes.")
	}

	runner := &usersImportRunner{
		APIURL:          apiURL,
		APIKey:          apiKey,
		DefaultOrgID:    flags.OrgID,
		EmailVerified:   flags.EmailVerified,
		DuplicatePolicy: flags.DuplicatePolicy,
		DryRun:          flags.DryRun,
		HTTP:            &http.Client{Timeout: 30 * time.Second},
	}
	summary, err := runner.Run(context.Background(), rows)
	if err != nil {
		return err
	}
	fmt.Println("\n--- Summary ---")
	fmt.Printf("  created:              %d\n", summary.Created)
	fmt.Printf("  existed:              %d\n", summary.Existed)
	fmt.Printf("  updated:              %d\n", summary.Updated)
	fmt.Printf("  skipped:              %d\n", summary.Skipped)
	fmt.Printf("  failed:               %d\n", summary.Failed)
	fmt.Printf("  memberships created:  %d\n", summary.MembershipsCreated)
	fmt.Printf("  memberships existed:  %d\n", summary.MembershipsExisted)
	if summary.Failed > 0 {
		return fmt.Errorf("%d user(s) failed", summary.Failed)
	}
	return nil
}

func parseUsersImportFlags(args []string) (*usersImportFlags, error) {
	f := &usersImportFlags{
		Profile:         resolveProfileName(args),
		DuplicatePolicy: "skip",
		Format:          "auto",
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file":
			if i+1 < len(args) {
				f.File = args[i+1]
				i++
			}
		case "--org":
			if i+1 < len(args) {
				f.OrgID = args[i+1]
				i++
			}
		case "--project":
			if i+1 < len(args) {
				f.ProjectID = args[i+1]
				i++
			}
		case "--email-verified":
			f.EmailVerified = true
		case "--dry-run":
			f.DryRun = true
		case "--duplicate-policy":
			if i+1 < len(args) {
				f.DuplicatePolicy = strings.ToLower(args[i+1])
				i++
			}
		case "--format":
			if i+1 < len(args) {
				f.Format = strings.ToLower(args[i+1])
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				f.Profile = args[i+1]
				i++
			}
		case "--api-url", "--management-api-url":
			if i+1 < len(args) {
				f.APIURL = args[i+1]
				i++
			}
		case "--api-key":
			if i+1 < len(args) {
				f.APIKey = args[i+1]
				i++
			}
		}
	}
	if f.File == "" {
		return nil, errors.New("--file <path> is required")
	}
	if f.DuplicatePolicy != "skip" && f.DuplicatePolicy != "update" {
		return nil, errors.New("--duplicate-policy must be skip or update")
	}
	return f, nil
}

func parseUsersImportFile(path, format string) ([]importUserRow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if format == "auto" {
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".json":
			format = "json"
		default:
			format = "csv"
		}
	}
	switch format {
	case "csv":
		return parseUsersCSV(string(b))
	case "json":
		return parseUsersJSON(b)
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
}

func parseUsersCSV(text string) ([]importUserRow, error) {
	r := csv.NewReader(strings.NewReader(text))
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(records) < 2 {
		return nil, nil
	}
	header := make([]string, len(records[0]))
	for i, h := range records[0] {
		header[i] = strings.TrimSpace(strings.ToLower(h))
	}
	idx := func(name string) int {
		for i, h := range header {
			if h == name {
				return i
			}
		}
		return -1
	}
	emailIdx := idx("email")
	if emailIdx == -1 {
		return nil, errors.New("CSV must have an email column")
	}
	nameIdx := idx("name")
	extIdx := idx("external_id")
	roleIdx := idx("role")
	orgIdx := idx("org")

	var rows []importUserRow
	for _, rec := range records[1:] {
		if emailIdx >= len(rec) {
			continue
		}
		email := strings.TrimSpace(strings.ToLower(rec[emailIdx]))
		if email == "" || !strings.Contains(email, "@") {
			continue
		}
		row := importUserRow{Email: email}
		if nameIdx >= 0 && nameIdx < len(rec) {
			row.Name = strings.TrimSpace(rec[nameIdx])
		}
		if extIdx >= 0 && extIdx < len(rec) {
			row.ExternalID = strings.TrimSpace(rec[extIdx])
		}
		if roleIdx >= 0 && roleIdx < len(rec) {
			row.Role = strings.TrimSpace(rec[roleIdx])
		}
		if orgIdx >= 0 && orgIdx < len(rec) {
			row.OrgID = strings.TrimSpace(rec[orgIdx])
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func parseUsersJSON(b []byte) ([]importUserRow, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var rows []importUserRow
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, err
		}
	} else if trimmed[0] == '{' {
		var wrap struct {
			Users []importUserRow `json:"users"`
		}
		if err := json.Unmarshal(trimmed, &wrap); err != nil {
			return nil, err
		}
		rows = wrap.Users
	} else {
		return nil, errors.New("JSON must be an array or { users: [...] }")
	}
	out := make([]importUserRow, 0, len(rows))
	for _, r := range rows {
		email := strings.TrimSpace(strings.ToLower(r.Email))
		if email == "" || !strings.Contains(email, "@") {
			continue
		}
		r.Email = email
		r.Name = strings.TrimSpace(r.Name)
		r.ExternalID = strings.TrimSpace(r.ExternalID)
		r.Role = strings.TrimSpace(r.Role)
		r.OrgID = strings.TrimSpace(r.OrgID)
		out = append(out, r)
	}
	return out, nil
}

type usersImportRunner struct {
	APIURL          string
	APIKey          string
	DefaultOrgID    string
	EmailVerified   bool
	DuplicatePolicy string
	DryRun          bool
	HTTP            *http.Client
}

func (r *usersImportRunner) Run(ctx context.Context, rows []importUserRow) (*usersImportSummary, error) {
	summary := &usersImportSummary{}
	for _, row := range rows {
		select {
		case <-ctx.Done():
			return summary, ctx.Err()
		default:
		}
		if r.DryRun {
			summary.Created++
			continue
		}
		outcome, userID, err := r.importUser(ctx, row)
		if err != nil {
			summary.Failed++
			fmt.Fprintf(os.Stderr, "  ! %s: %v\n", row.Email, err)
			continue
		}
		switch outcome {
		case "created":
			summary.Created++
			fmt.Printf("  + %s\n", row.Email)
		case "existed":
			summary.Existed++
			fmt.Printf("  = %s (already exists)\n", row.Email)
		case "updated":
			summary.Updated++
			fmt.Printf("  ~ %s (updated)\n", row.Email)
		case "skipped":
			summary.Skipped++
			fmt.Printf("  - %s (skipped)\n", row.Email)
		}
		orgID := row.OrgID
		if orgID == "" {
			orgID = r.DefaultOrgID
		}
		if orgID == "" || userID == "" {
			continue
		}
		role := row.Role
		if role == "" {
			role = "member"
		}
		mem, err := r.ensureMembership(ctx, orgID, userID, role)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ! membership %s → %s: %v\n", row.Email, orgID, err)
			continue
		}
		if mem == "created" {
			summary.MembershipsCreated++
		} else if mem == "existed" {
			summary.MembershipsExisted++
		}
	}
	return summary, nil
}

func (r *usersImportRunner) importUser(ctx context.Context, row importUserRow) (string, string, error) {
	if r.DuplicatePolicy == "update" {
		existing, err := r.lookupUserByEmail(ctx, row.Email)
		if err != nil {
			return "", "", err
		}
		if existing != "" {
			if err := r.patchUser(ctx, existing, row); err != nil {
				return "", "", err
			}
			return "updated", existing, nil
		}
	}
	payload := map[string]any{
		"email":          row.Email,
		"email_verified": r.EmailVerified,
	}
	if row.Name != "" {
		payload["name"] = row.Name
	}
	if row.ExternalID != "" {
		payload["external_id"] = row.ExternalID
	}
	status, body, err := r.api(ctx, http.MethodPost, "/v1/users", payload)
	if err != nil {
		return "", "", err
	}
	var resp map[string]any
	_ = json.Unmarshal(body, &resp)
	userID, _ := resp["id"].(string)
	switch {
	case status == 201:
		return "created", userID, nil
	case status == 200:
		if existed, _ := resp["existed"].(bool); existed {
			if r.DuplicatePolicy == "skip" && (row.Name != "" || row.ExternalID != "") {
				_ = r.patchUser(ctx, userID, row)
			}
			return "existed", userID, nil
		}
		return "existed", userID, nil
	case status == 409:
		return "existed", userID, nil
	default:
		return "", "", fmt.Errorf("HTTP %d: %s", status, string(body))
	}
}

func (r *usersImportRunner) lookupUserByEmail(ctx context.Context, email string) (string, error) {
	status, body, err := r.api(ctx, http.MethodGet, "/v1/users?email="+email+"&limit=1", nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("lookup HTTP %d", status)
	}
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if len(resp.Data) == 0 {
		return "", nil
	}
	return resp.Data[0].ID, nil
}

func (r *usersImportRunner) patchUser(ctx context.Context, userID string, row importUserRow) error {
	payload := map[string]any{}
	if row.Name != "" {
		payload["name"] = row.Name
	}
	if row.ExternalID != "" {
		payload["external_id"] = row.ExternalID
	}
	if r.EmailVerified {
		payload["email_verified"] = true
	}
	if len(payload) == 0 {
		return nil
	}
	status, body, err := r.api(ctx, http.MethodPatch, "/v1/users/"+userID, payload)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("patch HTTP %d: %s", status, string(body))
	}
	return nil
}

func (r *usersImportRunner) ensureMembership(ctx context.Context, orgID, userID, role string) (string, error) {
	payload := map[string]any{
		"user_id": userID,
		"role":    role,
		"status":  "active",
	}
	status, body, err := r.api(ctx, http.MethodPost, "/v1/organizations/"+orgID+"/memberships", payload)
	if err != nil {
		return "", err
	}
	switch status {
	case 201:
		return "created", nil
	case 200, 409:
		return "existed", nil
	default:
		return "", fmt.Errorf("membership HTTP %d: %s", status, string(body))
	}
}

func (r *usersImportRunner) api(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.APIURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "authio-cli-users-import/1.0")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, raw, nil
}
