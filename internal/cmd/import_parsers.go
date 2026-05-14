package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// streamArrayOrNDJSON is the workhorse for providers whose export format
// is "either a top-level JSON array, or NDJSON, or a JSON object whose
// children-array field is the user list." The caller passes in the
// per-record decoder; we handle the framing.
//
//   wrapKey == ""  top-level JSON array OR NDJSON of objects (one per line).
//   wrapKey != ""  {"<wrapKey>": [...]}, OR a top-level array, OR NDJSON
//                  of records — auto-detected from the leading bytes.
//
// `decode` runs once per record on the raw JSON bytes and emits zero or
// one SourceUser via the caller's handler. Skipped records (e.g. disabled,
// no email) are emitted with Email == "" so the runner counts them.
//
// Note: we read the input fully into memory once. User-export files we
// import from are bounded by the source IdP's export endpoints (Auth0
// caps a single export at ~500MB; Clerk/Cognito/Firebase/Supabase are
// orders of magnitude smaller). If we ever want to support unbounded
// streams, swap this for a peeking bufio.Reader-based detector.
func streamArrayOrNDJSON(
	ctx context.Context,
	r io.Reader,
	wrapKey string,
	emit func(SourceUser) error,
	decode func(raw json.RawMessage) (SourceUser, bool),
) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '[':
		return streamJSONArray(ctx, bytes.NewReader(trimmed), emit, decode)
	case '{':
		// Ambiguous: NDJSON of objects vs single wrapped object. Use a
		// content-aware heuristic: if wrapKey is set AND the first
		// occurrence of `"<wrapKey>"` is followed by an opening `[`,
		// treat it as wrapped. Otherwise it's NDJSON.
		if wrapKey != "" && looksWrappedObject(trimmed, wrapKey) {
			return streamWrappedJSONArray(ctx, bytes.NewReader(trimmed), wrapKey, emit, decode)
		}
		return streamNDJSON(ctx, bytes.NewReader(trimmed), emit, decode)
	default:
		return streamNDJSON(ctx, bytes.NewReader(trimmed), emit, decode)
	}
}

// looksWrappedObject returns true if `"<wrapKey>"` appears in the first
// ~4KB of `data` and is followed (after `:` and whitespace) by an `[`.
// 4KB is enough to span any realistic JSON-object header, even when an
// export tool pretty-prints whitespace before the key.
func looksWrappedObject(data []byte, wrapKey string) bool {
	end := len(data)
	if end > 4096 {
		end = 4096
	}
	s := string(data[:end])
	needle := `"` + wrapKey + `"`
	idx := strings.Index(s, needle)
	if idx < 0 {
		return false
	}
	rest := strings.TrimLeft(s[idx+len(needle):], " \t\r\n:")
	return strings.HasPrefix(rest, "[")
}

func streamJSONArray(
	ctx context.Context,
	r io.Reader,
	emit func(SourceUser) error,
	decode func(json.RawMessage) (SourceUser, bool),
) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return fmt.Errorf("expected '[' got %v", tok)
	}
	for dec.More() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		u, ok := decode(raw)
		if !ok {
			continue
		}
		if err := emit(u); err != nil {
			return err
		}
	}
	_, _ = dec.Token() // consume trailing ']'
	return nil
}

func streamWrappedJSONArray(
	ctx context.Context,
	r io.Reader,
	wrapKey string,
	emit func(SourceUser) error,
	decode func(json.RawMessage) (SourceUser, bool),
) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected '{' got %v", tok)
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := key.(string)
		if k == wrapKey {
			arrTok, err := dec.Token()
			if err != nil {
				return err
			}
			if delim, ok := arrTok.(json.Delim); !ok || delim != '[' {
				return fmt.Errorf("expected array at .%s, got %v", wrapKey, arrTok)
			}
			for dec.More() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return err
				}
				u, ok := decode(raw)
				if !ok {
					continue
				}
				if err := emit(u); err != nil {
					return err
				}
			}
			_, _ = dec.Token() // ']'
		} else {
			// skip unknown top-level keys
			var ignored json.RawMessage
			if err := dec.Decode(&ignored); err != nil {
				return err
			}
		}
	}
	return nil
}

func streamNDJSON(
	ctx context.Context,
	r io.Reader,
	emit func(SourceUser) error,
	decode func(json.RawMessage) (SourceUser, bool),
) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		u, ok := decode(json.RawMessage(line))
		if !ok {
			continue
		}
		if err := emit(u); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// =====================================================================
// auth0
// =====================================================================

type auth0Parser struct{}

func (auth0Parser) Name() string { return "auth0" }
func (auth0Parser) Help() string {
	return `auth0: file is a JSON array (or NDJSON) of user objects in the form
  {"user_id":"...","email":"...","email_verified":true,"name":"..."}.
Auth0's Management API export and the dashboard CSV-to-JSON tool both
emit this shape. Users without email or where email is unverified AND
unconfirmed are skipped.`
}

func (auth0Parser) Parse(ctx context.Context, r io.Reader, emit func(SourceUser) error) error {
	return streamArrayOrNDJSON(ctx, r, "", emit, decodeAuth0Record)
}

func decodeAuth0Record(raw json.RawMessage) (SourceUser, bool) {
	var rec struct {
		UserID        string `json:"user_id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Nickname      string `json:"nickname"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return SourceUser{}, false
	}
	name := rec.Name
	if name == "" {
		name = rec.Nickname
	}
	return SourceUser{
		Email:          rec.Email,
		Name:           name,
		EmailVerified:  rec.EmailVerified,
		SourceID:       rec.UserID,
		SourceProvider: "auth0",
	}, true
}

// =====================================================================
// clerk
// =====================================================================

type clerkParser struct{}

func (clerkParser) Name() string { return "clerk" }
func (clerkParser) Help() string {
	return `clerk: file is a JSON array (or NDJSON) of Clerk Backend-API user objects.
Each row has email_addresses[] with the verified email; first/last_name
populate the display name. Users with no email_addresses are skipped.`
}

func (clerkParser) Parse(ctx context.Context, r io.Reader, emit func(SourceUser) error) error {
	return streamArrayOrNDJSON(ctx, r, "", emit, decodeClerkRecord)
}

func decodeClerkRecord(raw json.RawMessage) (SourceUser, bool) {
	var rec struct {
		ID             string `json:"id"`
		EmailAddresses []struct {
			EmailAddress string `json:"email_address"`
			Verification struct {
				Status string `json:"status"`
			} `json:"verification"`
		} `json:"email_addresses"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Username  string `json:"username"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return SourceUser{}, false
	}
	if len(rec.EmailAddresses) == 0 {
		return SourceUser{Email: "", SourceID: rec.ID, SourceProvider: "clerk"}, true // counted as skipped
	}
	em := rec.EmailAddresses[0].EmailAddress
	verified := rec.EmailAddresses[0].Verification.Status == "verified"

	name := strings.TrimSpace(strings.TrimSpace(rec.FirstName) + " " + strings.TrimSpace(rec.LastName))
	if name == "" {
		name = rec.Username
	}
	return SourceUser{
		Email:          em,
		Name:           name,
		EmailVerified:  verified,
		SourceID:       rec.ID,
		SourceProvider: "clerk",
	}, true
}

// =====================================================================
// cognito
// =====================================================================

type cognitoParser struct{}

func (cognitoParser) Name() string { return "cognito" }
func (cognitoParser) Help() string {
	return `cognito: file is the JSON output of "aws cognito-idp list-users" — i.e.
{"Users":[{"Username":"...","Attributes":[{"Name":"email",...}],"UserStatus":"CONFIRMED","Enabled":true}]},
or NDJSON of just the inner user records. Users with Enabled=false or
UserStatus != CONFIRMED are skipped.`
}

func (cognitoParser) Parse(ctx context.Context, r io.Reader, emit func(SourceUser) error) error {
	return streamArrayOrNDJSON(ctx, r, "Users", emit, decodeCognitoRecord)
}

func decodeCognitoRecord(raw json.RawMessage) (SourceUser, bool) {
	var rec struct {
		Username   string `json:"Username"`
		Enabled    bool   `json:"Enabled"`
		UserStatus string `json:"UserStatus"`
		Attributes []struct {
			Name  string `json:"Name"`
			Value string `json:"Value"`
		} `json:"Attributes"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return SourceUser{}, false
	}
	// Cognito leaves Enabled defaulted to false unless present — when the
	// field is missing we assume true (some `cognito-idp list-users`
	// outputs omit it for confirmed users). Decode again into a typed
	// pointer to differentiate "absent" from "false".
	var presence struct {
		Enabled *bool `json:"Enabled"`
	}
	_ = json.Unmarshal(raw, &presence)
	enabled := rec.Enabled
	if presence.Enabled == nil {
		enabled = true
	}
	if !enabled || (rec.UserStatus != "" && rec.UserStatus != "CONFIRMED" && rec.UserStatus != "EXTERNAL_PROVIDER") {
		return SourceUser{Email: "", SourceID: rec.Username, SourceProvider: "cognito"}, true
	}
	var email, name string
	var verified bool
	for _, a := range rec.Attributes {
		switch a.Name {
		case "email":
			email = a.Value
		case "email_verified":
			verified = strings.EqualFold(a.Value, "true")
		case "name", "given_name":
			if name == "" {
				name = a.Value
			}
		}
	}
	return SourceUser{
		Email:          email,
		Name:           name,
		EmailVerified:  verified,
		SourceID:       rec.Username,
		SourceProvider: "cognito",
	}, true
}

// =====================================================================
// firebase
// =====================================================================

type firebaseParser struct{}

func (firebaseParser) Name() string { return "firebase" }
func (firebaseParser) Help() string {
	return `firebase: file is the output of "firebase auth:export users.json" —
{"users":[{"localId":"...","email":"...","emailVerified":true,
"displayName":"...","disabled":false,...}]}, or NDJSON of inner records.
Disabled accounts are skipped. Password hashes are NEVER imported;
existing users get a magic-link enrollment on first sign-in attempt.`
}

func (firebaseParser) Parse(ctx context.Context, r io.Reader, emit func(SourceUser) error) error {
	return streamArrayOrNDJSON(ctx, r, "users", emit, decodeFirebaseRecord)
}

func decodeFirebaseRecord(raw json.RawMessage) (SourceUser, bool) {
	var rec struct {
		LocalID       string `json:"localId"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"emailVerified"`
		DisplayName   string `json:"displayName"`
		Disabled      bool   `json:"disabled"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return SourceUser{}, false
	}
	if rec.Disabled || rec.Email == "" {
		return SourceUser{Email: "", SourceID: rec.LocalID, SourceProvider: "firebase"}, true
	}
	return SourceUser{
		Email:          rec.Email,
		Name:           rec.DisplayName,
		EmailVerified:  rec.EmailVerified,
		SourceID:       rec.LocalID,
		SourceProvider: "firebase",
	}, true
}

// =====================================================================
// supabase
// =====================================================================

type supabaseParser struct{}

func (supabaseParser) Name() string { return "supabase" }
func (supabaseParser) Help() string {
	return `supabase: file is a JSON array (or NDJSON) dump of the auth.users table.
Each row has email, email_confirmed_at (verifiable status), and
raw_user_meta_data.full_name. Users with banned_until in the future are
skipped.`
}

func (supabaseParser) Parse(ctx context.Context, r io.Reader, emit func(SourceUser) error) error {
	return streamArrayOrNDJSON(ctx, r, "", emit, decodeSupabaseRecord)
}

func decodeSupabaseRecord(raw json.RawMessage) (SourceUser, bool) {
	var rec struct {
		ID                string  `json:"id"`
		Email             string  `json:"email"`
		EmailConfirmedAt  *string `json:"email_confirmed_at"`
		BannedUntil       *string `json:"banned_until"`
		RawUserMetaData   struct {
			FullName string `json:"full_name"`
			Name     string `json:"name"`
		} `json:"raw_user_meta_data"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return SourceUser{}, false
	}
	if rec.Email == "" {
		return SourceUser{Email: "", SourceID: rec.ID, SourceProvider: "supabase"}, true
	}
	if rec.BannedUntil != nil && *rec.BannedUntil != "" {
		if t, err := time.Parse(time.RFC3339, *rec.BannedUntil); err == nil && t.After(time.Now().UTC()) {
			return SourceUser{Email: "", SourceID: rec.ID, SourceProvider: "supabase"}, true
		}
	}
	name := rec.RawUserMetaData.FullName
	if name == "" {
		name = rec.RawUserMetaData.Name
	}
	return SourceUser{
		Email:          rec.Email,
		Name:           name,
		EmailVerified:  rec.EmailConfirmedAt != nil && *rec.EmailConfirmedAt != "",
		SourceID:       rec.ID,
		SourceProvider: "supabase",
	}, true
}
