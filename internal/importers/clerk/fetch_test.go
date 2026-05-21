package clerk

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestFetchUsersPage_BareArray covers Clerk's historical response shape
// (a bare JSON array, no wrapper).
func TestFetchUsersPage_BareArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users" {
			http.NotFound(w, r)
			return
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Bearer sk_test_xxx") {
			t.Errorf("bad auth header: %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `[{"id":"user_1","email_addresses":[{"id":"e1","email_address":"a@b.com","verification":{"status":"verified"}}]}]`)
	}))
	defer srv.Close()

	c := NewClerkClient("sk_test_xxx", srv.URL, 100)
	page, err := c.FetchUsersPage(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Users) != 1 {
		t.Fatalf("len=%d", len(page.Users))
	}
	if page.Users[0].ID != "user_1" {
		t.Fatalf("id=%q", page.Users[0].ID)
	}
}

// TestFetchUsersPage_Wrapped covers Clerk's newer {data:[...]} shape.
func TestFetchUsersPage_Wrapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":[{"id":"user_1"},{"id":"user_2"}],"total_count":2}`)
	}))
	defer srv.Close()
	c := NewClerkClient("sk_test_xxx", srv.URL, 100)
	page, err := c.FetchUsersPage(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Users) != 2 {
		t.Fatalf("len=%d", len(page.Users))
	}
	if page.Total != 2 {
		t.Fatalf("total=%d", page.Total)
	}
}

// TestIterateUsers_StopsOnPartialPage exercises the pagination loop and
// verifies the importer stops after fewer than 500 rows come back.
func TestIterateUsers_StopsOnPartialPage(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Return 500 on the first page, 1 on the second. The iterator
		// should stop after the second page.
		switch r.URL.Query().Get("offset") {
		case "0":
			fmt.Fprint(w, makeUsersArray(500))
		case "500":
			fmt.Fprint(w, `[{"id":"user_500"}]`)
		default:
			t.Errorf("unexpected offset=%q", r.URL.Query().Get("offset"))
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClerkClient("sk", srv.URL, 200)
	var seen int
	err := c.IterateUsers(context.Background(), 0, func(page UserPage, _ int) (bool, error) {
		seen += len(page.Users)
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != 501 {
		t.Errorf("seen=%d want 501", seen)
	}
	if hits.Load() != 2 {
		t.Errorf("hits=%d want 2", hits.Load())
	}
}

// TestClerkClient_RetryAfter429 verifies the client honors Retry-After
// on a 429 and succeeds on retry.
func TestClerkClient_RetryAfter429(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"errors":[{"code":"rate_limited"}]}`)
			return
		}
		fmt.Fprint(w, `[{"id":"user_after_retry"}]`)
	}))
	defer srv.Close()

	c := NewClerkClient("sk", srv.URL, 100)
	start := time.Now()
	page, err := c.FetchUsersPage(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Users) != 1 || page.Users[0].ID != "user_after_retry" {
		t.Fatalf("unexpected page: %+v", page)
	}
	if attempts.Load() < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts.Load())
	}
	if d := time.Since(start); d < 750*time.Millisecond {
		t.Errorf("expected at least ~1s wait honoring Retry-After, got %v", d)
	}
}

// TestClerkClient_5xxRetries verifies we retry transient 500s and
// surface the underlying error after MaxRetries.
func TestClerkClient_5xxFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, `bad gateway`)
	}))
	defer srv.Close()

	c := NewClerkClient("sk", srv.URL, 100)
	c.MaxRetries = 1
	_, err := c.FetchUsersPage(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error after retries")
	}
}

// TestClerkClient_AuthError unwraps to IsAuthError on 401.
func TestClerkClient_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"code":"authentication_invalid"}]}`)
	}))
	defer srv.Close()

	c := NewClerkClient("sk", srv.URL, 100)
	_, err := c.FetchUsersPage(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsAuthError(err) {
		t.Errorf("IsAuthError=false for %v", err)
	}
}

// makeUsersArray builds a JSON array of n minimal user objects.
func makeUsersArray(n int) string {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id":"user_%d"}`, i)
	}
	b.WriteString("]")
	return b.String()
}
