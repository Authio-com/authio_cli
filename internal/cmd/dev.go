package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

// Dev runs a local HTTP proxy that forwards to the configured auth-core
// (or --target=...) and pretty-prints every request/response in real time.
// Useful for SDK customers debugging integrations against the live alpha.
func Dev(args []string) error {
	port := "8089"
	target := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port":
			if i+1 < len(args) {
				port = args[i+1]
				i++
			}
		case "--target":
			if i+1 < len(args) {
				target = args[i+1]
				i++
			}
		}
	}

	if target == "" {
		store, err := credentials.DefaultStore()
		if err == nil {
			if p, err := store.Load("default"); err == nil && p.AuthCoreURL != "" {
				target = p.AuthCoreURL
			}
		}
	}
	if target == "" {
		target = defaultAuthCore
	}
	target = strings.TrimRight(target, "/")
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid --target: %w", err)
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			req.Host = u.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			fmt.Printf("    %s %d %s\n",
				colorStatus(resp.StatusCode), resp.StatusCode, resp.Request.URL.Path)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			fmt.Printf("    err   %s %s: %v\n", r.Method, r.URL.Path, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		fmt.Printf("→ %s %s\n", r.Method, r.URL.RequestURI())
		rp.ServeHTTP(w, r)
		_ = start
	})

	addr := ":" + port
	fmt.Println()
	fmt.Printf("  authio dev — proxy on http://localhost%s → %s\n", addr, target)
	fmt.Println("  Hit Ctrl+C to stop.")
	fmt.Println()
	return http.ListenAndServe(addr, mux)
}

// colorStatus returns an ANSI-colored 3-letter prefix.
func colorStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "\033[32mok \033[0m"
	case code >= 300 && code < 400:
		return "\033[36m3xx\033[0m"
	case code >= 400 && code < 500:
		return "\033[33m4xx\033[0m"
	default:
		return "\033[31m5xx\033[0m"
	}
}

// _ = io.EOF for future buffered logging hooks
var _ = io.EOF
