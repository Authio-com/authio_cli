package clearance

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The loopback callback must never echo query values into HTML — the
// listener is reachable by any page open in the same browser.
func TestAwaitCallback_NeverReflectsInput(t *testing.T) {
	ln, redirect, err := LoopbackListener(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type res struct {
		code string
		err  error
	}
	done := make(chan res, 1)
	go func() { c, e := AwaitCallback(ctx, ln, "st_expected"); done <- res{c, e} }()

	payload := `<script>alert(1)</script>`
	resp, err := http.Get(redirect + "?error=access_denied&error_description=" + strings.ReplaceAll(payload, " ", "%20"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), "<script") || strings.Contains(string(body), "alert(1)") || strings.Contains(string(body), "access_denied") {
		t.Fatalf("callback reflected untrusted input into HTML: %s", body)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
	r := <-done
	if r.err == nil || !strings.Contains(r.err.Error(), "access_denied") {
		t.Fatalf("terminal error should carry the detail: %v", r.err)
	}
}

func TestAwaitCallback_StateMismatchAndSuccess(t *testing.T) {
	// mismatch
	ln, redirect, _ := LoopbackListener(0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := AwaitCallback(ctx, ln, "good"); done <- e }()
	resp, _ := http.Get(redirect + "?code=abc&state=evil")
	resp.Body.Close()
	if e := <-done; e == nil || !strings.Contains(e.Error(), "state mismatch") {
		t.Fatalf("want state mismatch, got %v", e)
	}
	// success
	ln2, redirect2, _ := LoopbackListener(0)
	type res struct {
		code string
		err  error
	}
	done2 := make(chan res, 1)
	go func() { c, e := AwaitCallback(ctx, ln2, "good"); done2 <- res{c, e} }()
	resp, _ = http.Get(redirect2 + "?code=abc123&state=good")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Signed in") {
		t.Fatalf("success page: %s", body)
	}
	if r := <-done2; r.err != nil || r.code != "abc123" {
		t.Fatalf("success: %+v", r)
	}
}
