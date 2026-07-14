package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/tcast/authio_cli/internal/credentials"
)

const (
	defaultMgmtAPI       = "https://authiomanagement-api-production.up.railway.app"
	defaultAuthCore      = "https://authioauth-core-production.up.railway.app"
	localMgmtAPI         = "http://localhost:8080"
	localAuthCore        = "http://localhost:8081"
	cliDevEnvironmentVar = "AUTHIO_CLI_DEV"
)

type loginOptions struct {
	apiURL      string
	authCoreURL string
	profile     string
	noBrowser   bool
}

func parseLoginOptions(args []string) (loginOptions, error) {
	opts := loginOptions{
		apiURL:      defaultMgmtAPI,
		authCoreURL: defaultAuthCore,
		profile:     "default",
	}
	if os.Getenv(cliDevEnvironmentVar) == "1" || strings.EqualFold(os.Getenv(cliDevEnvironmentVar), "true") {
		opts.apiURL = localMgmtAPI
		opts.authCoreURL = localAuthCore
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dev":
			opts.apiURL = localMgmtAPI
			opts.authCoreURL = localAuthCore
		case "--api-url":
			if i+1 >= len(args) {
				return loginOptions{}, errors.New("--api-url requires a value")
			}
			opts.apiURL = args[i+1]
			i++
		case "--auth-core-url":
			if i+1 >= len(args) {
				return loginOptions{}, errors.New("--auth-core-url requires a value")
			}
			opts.authCoreURL = args[i+1]
			i++
		case "--profile":
			if i+1 >= len(args) {
				return loginOptions{}, errors.New("--profile requires a value")
			}
			opts.profile = strings.TrimSpace(args[i+1])
			if opts.profile == "" {
				return loginOptions{}, errors.New("--profile requires a non-empty value")
			}
			i++
		case "--no-browser":
			opts.noBrowser = true
		}
	}
	opts.apiURL = strings.TrimRight(opts.apiURL, "/")
	opts.authCoreURL = strings.TrimRight(opts.authCoreURL, "/")
	return opts, nil
}

// Login runs the device-code flow against the management-api.
func Login(args []string) error {
	opts, err := parseLoginOptions(args)
	if err != nil {
		return err
	}

	// 1. POST /v1/cli/device-codes
	type startResp struct {
		UserCode        string `json:"user_code"`
		DeviceCode      string `json:"device_code"`
		VerificationURL string `json:"verification_url"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	resp, err := postJSON(opts.apiURL+"/v1/cli/device-codes", nil)
	if err != nil {
		return fmt.Errorf("start device flow: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("start device flow: %s: %s", resp.Status, body)
	}
	var start startResp
	if err := json.NewDecoder(resp.Body).Decode(&start); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("  Visit this URL in your browser to authorize:")
	fmt.Println()
	fmt.Println("    " + start.VerificationURL)
	fmt.Println()
	fmt.Printf("  Your code: %s\n", start.UserCode)
	fmt.Println()
	if !opts.noBrowser {
		_ = openBrowser(start.VerificationURL)
	}
	fmt.Println("  Waiting for approval (Ctrl+C to cancel)...")

	interval := start.Interval
	if interval < 1 {
		interval = 3
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return errors.New("device code expired before approval")
		}
		time.Sleep(time.Duration(interval) * time.Second)
		status, projectID, secret, err := pollOnce(opts.apiURL, start.DeviceCode)
		if err != nil {
			return err
		}
		switch status {
		case "pending":
			continue
		case "denied":
			return errors.New("approval denied in the dashboard")
		case "expired":
			return errors.New("device code expired before approval")
		case "approved":
			store, err := credentials.DefaultStore()
			if err != nil {
				return err
			}
			if err := store.Save(opts.profile, credentials.Profile{
				APIKey:      secret,
				ProjectID:   projectID,
				APIURL:      opts.apiURL,
				AuthCoreURL: opts.authCoreURL,
			}); err != nil {
				return fmt.Errorf("save credentials: %w", err)
			}
			fmt.Println()
			fmt.Println("  ✓ Authorized.")
			fmt.Printf("  Saved %s\n", store.Path)
			fmt.Printf("  Environment: %s  (API: project_id)\n", projectID)
			return nil
		default:
			return fmt.Errorf("unexpected status: %s", status)
		}
	}
}

func pollOnce(apiURL, deviceCode string) (status, projectID, apiKey string, err error) {
	body, _ := json.Marshal(map[string]string{"device_code": deviceCode})
	resp, err := http.Post(apiURL+"/v1/cli/device-codes/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	var raw struct {
		Status    string `json:"status"`
		ProjectID string `json:"project_id"`
		APIKey    *struct {
			Secret string `json:"secret"`
		} `json:"api_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		// Status 202 with empty body is acceptable.
		if resp.StatusCode == http.StatusAccepted {
			return "pending", "", "", nil
		}
		return "", "", "", err
	}
	if raw.Status == "approved" && raw.APIKey != nil {
		return raw.Status, raw.ProjectID, raw.APIKey.Secret, nil
	}
	return raw.Status, raw.ProjectID, "", nil
}

func postJSON(url string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(http.MethodPost, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "authio-cli/0.1")
	return http.DefaultClient.Do(req)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return errors.New("unknown platform")
	}
	return cmd.Start()
}
