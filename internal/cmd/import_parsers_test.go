package cmd

import (
	"context"
	"strings"
	"testing"
	"time"
)

func collect(t *testing.T, p Parser, input string) []SourceUser {
	t.Helper()
	var got []SourceUser
	err := p.Parse(context.Background(), strings.NewReader(input), func(u SourceUser) error {
		got = append(got, u)
		return nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return got
}

// =====================================================================
// auth0 (re-tested against the new parser)
// =====================================================================

func TestAuth0ParserArray(t *testing.T) {
	got := collect(t, auth0Parser{}, `[
	  {"user_id":"a","email":"a@x.com","email_verified":true,"name":"A"},
	  {"user_id":"b","email":"b@x.com","email_verified":false,"nickname":"B"}
	]`)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	if got[0].Email != "a@x.com" || !got[0].EmailVerified {
		t.Fatalf("first wrong: %+v", got[0])
	}
	if got[1].Name != "B" {
		t.Fatalf("nickname fallback failed: %+v", got[1])
	}
}

func TestAuth0ParserNDJSON(t *testing.T) {
	got := collect(t, auth0Parser{}, "{\"user_id\":\"a\",\"email\":\"a@x.com\",\"email_verified\":true}\n{\"user_id\":\"b\",\"email\":\"b@x.com\"}\n")
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
}

// =====================================================================
// clerk
// =====================================================================

func TestClerkParserArray(t *testing.T) {
	got := collect(t, clerkParser{}, `[
	  {"id":"u1","email_addresses":[{"email_address":"a@x.com","verification":{"status":"verified"}}],"first_name":"Ada","last_name":"Lovelace"},
	  {"id":"u2","email_addresses":[{"email_address":"b@x.com","verification":{"status":"pending"}}],"username":"bob"},
	  {"id":"u3","email_addresses":[]}
	]`)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	if got[0].Name != "Ada Lovelace" || !got[0].EmailVerified {
		t.Fatalf("u1 wrong: %+v", got[0])
	}
	if got[1].EmailVerified {
		t.Fatalf("u2 should be unverified: %+v", got[1])
	}
	if got[1].Name != "bob" {
		t.Fatalf("u2 username fallback failed: %+v", got[1])
	}
	if got[2].Email != "" {
		t.Fatalf("u3 (no emails) should skip with empty Email")
	}
}

// =====================================================================
// cognito
// =====================================================================

func TestCognitoParserAWSCLIShape(t *testing.T) {
	got := collect(t, cognitoParser{}, `{
	  "Users": [
	    {
	      "Username": "u1",
	      "UserStatus": "CONFIRMED",
	      "Enabled": true,
	      "Attributes": [
	        {"Name":"email","Value":"a@x.com"},
	        {"Name":"email_verified","Value":"true"},
	        {"Name":"name","Value":"Ada"}
	      ]
	    },
	    {
	      "Username": "u2",
	      "UserStatus": "CONFIRMED",
	      "Enabled": false,
	      "Attributes": [{"Name":"email","Value":"b@x.com"}]
	    },
	    {
	      "Username": "u3",
	      "UserStatus": "UNCONFIRMED",
	      "Enabled": true,
	      "Attributes": [{"Name":"email","Value":"c@x.com"}]
	    }
	  ]
	}`)
	if len(got) != 3 {
		t.Fatalf("want 3 (incl skipped), got %d", len(got))
	}
	if got[0].Email != "a@x.com" || !got[0].EmailVerified || got[0].Name != "Ada" {
		t.Fatalf("u1 wrong: %+v", got[0])
	}
	if got[1].Email != "" {
		t.Fatalf("u2 disabled should skip")
	}
	if got[2].Email != "" {
		t.Fatalf("u3 unconfirmed should skip")
	}
}

func TestCognitoParserNDJSON(t *testing.T) {
	got := collect(t, cognitoParser{},
		`{"Username":"u1","UserStatus":"CONFIRMED","Attributes":[{"Name":"email","Value":"a@x.com"}]}`+"\n"+
			`{"Username":"u2","UserStatus":"CONFIRMED","Attributes":[{"Name":"email","Value":"b@x.com"}]}`+"\n")
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	// Enabled was absent in this NDJSON; default-true must apply.
	if got[0].Email != "a@x.com" {
		t.Fatalf("u1 default-enabled failed: %+v", got[0])
	}
}

// =====================================================================
// firebase
// =====================================================================

func TestFirebaseParser(t *testing.T) {
	got := collect(t, firebaseParser{}, `{
	  "users": [
	    {"localId":"f1","email":"a@x.com","emailVerified":true,"displayName":"Ada","disabled":false},
	    {"localId":"f2","email":"b@x.com","disabled":true},
	    {"localId":"f3","disabled":false}
	  ]
	}`)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	if got[0].Email != "a@x.com" || !got[0].EmailVerified || got[0].Name != "Ada" {
		t.Fatalf("f1 wrong: %+v", got[0])
	}
	if got[1].Email != "" {
		t.Fatalf("f2 disabled should skip")
	}
	if got[2].Email != "" {
		t.Fatalf("f3 no-email should skip")
	}
}

// =====================================================================
// supabase
// =====================================================================

func TestSupabaseParser(t *testing.T) {
	pastBan := "2020-01-01T00:00:00Z"
	futureBan := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	confirmed := "2024-06-01T00:00:00Z"

	got := collect(t, supabaseParser{}, `[
	  {"id":"s1","email":"a@x.com","email_confirmed_at":"`+confirmed+`","raw_user_meta_data":{"full_name":"Ada"}},
	  {"id":"s2","email":"b@x.com","email_confirmed_at":null,"raw_user_meta_data":{"name":"B"}},
	  {"id":"s3","email":"c@x.com","banned_until":"`+futureBan+`"},
	  {"id":"s4","email":"d@x.com","banned_until":"`+pastBan+`"},
	  {"id":"s5","raw_user_meta_data":{"full_name":"NoEmail"}}
	]`)
	if len(got) != 5 {
		t.Fatalf("want 5, got %d", len(got))
	}
	if !got[0].EmailVerified || got[0].Name != "Ada" {
		t.Fatalf("s1 wrong: %+v", got[0])
	}
	if got[1].EmailVerified {
		t.Fatalf("s2 unconfirmed should not be verified")
	}
	if got[1].Name != "B" {
		t.Fatalf("s2 name-fallback failed: %+v", got[1])
	}
	if got[2].Email != "" {
		t.Fatalf("s3 future-banned should skip")
	}
	if got[3].Email == "" {
		t.Fatalf("s4 past-banned should NOT skip")
	}
	if got[4].Email != "" {
		t.Fatalf("s5 no-email should skip")
	}
}

// =====================================================================
// streamArrayOrNDJSON edge cases
// =====================================================================

func TestParserHandlesEmptyInput(t *testing.T) {
	for _, p := range []Parser{auth0Parser{}, clerkParser{}, cognitoParser{}, firebaseParser{}, supabaseParser{}} {
		got := collect(t, p, "")
		if len(got) != 0 {
			t.Fatalf("%s: empty input emitted %d records", p.Name(), len(got))
		}
	}
}

func TestParserHonorsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled
	err := clerkParser{}.Parse(ctx, strings.NewReader(`[{"id":"u1","email_addresses":[{"email_address":"a@x.com"}]}]`),
		func(u SourceUser) error { return nil })
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
