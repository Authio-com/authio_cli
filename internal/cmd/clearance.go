package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tcast/authio_cli/internal/clearance"
	"github.com/tcast/authio_cli/internal/credentials"
)

// Clearance is `authio clearance <login|serve|init|explain>` — the local
// sidecar for Authio Clearance (agent authorization). See internal/clearance.
func Clearance(args []string) error {
	if len(args) == 0 {
		printClearanceHelp()
		return nil
	}
	switch args[0] {
	case "login":
		return clearanceLogin(args[1:])
	case "serve":
		return clearanceServe(args[1:])
	case "init":
		return clearanceInit(args[1:])
	case "explain":
		return clearanceExplain(args[1:])
	case "logout":
		return clearanceLogout(args[1:])
	case "help", "--help", "-h":
		printClearanceHelp()
		return nil
	}
	return errors.New("unknown clearance subcommand: " + args[0] + " (try `authio clearance help`)")
}

func printClearanceHelp() {
	fmt.Println(`authio clearance — put your AI agents behind Authio Clearance

USAGE
  authio clearance login  --agent <agent_id> [--client-id <id>] [--project <proj_id>]
                          [--clearance-url URL] [--auth-core-url URL] [--no-browser]
  authio clearance serve  --agent <agent_id> [--config authio.yaml]
  authio clearance init   --agent <agent_id>
  authio clearance explain --agent <agent_id>
  authio clearance logout --agent <agent_id>

login    Signs in as the agent's Connect client (OAuth authorization code +
         PKCE on a loopback redirect) and saves a rotating refresh token in
         ~/.authio/clearance/<agent>.json (mode 0600). The agent's client_id
         and project are read from your Authio profile (authio login) via
         GET /v1/session/clearance/agents/:id; pass --client-id/--project
         to skip that lookup.
serve    Runs a stdio MCP server for Claude Code / Cursor: the agent's hosted
         tools (Valet-backed), plus exec.run and any stdio MCP servers listed
         under clearance.providers in authio.yaml — every call judged by
         Clearance first. Policy lives in Authio, never on this machine.
init     Prints the MCP config to paste into Claude Code or Cursor.
explain  Prints the agent's resolved policy chain.`)
}

// ---------------------------------------------------------------- flags

type clearanceFlags struct {
	agent        string
	clientID     string
	project      string
	clearanceURL string
	authCoreURL  string
	apiURL       string
	config       string
	profile      string
	noBrowser    bool
	port         int
}

func parseClearanceFlags(args []string) (clearanceFlags, error) {
	f := clearanceFlags{
		clearanceURL: envOrDefault("AUTHIO_CLEARANCE_URL", "https://clearance.authio.com"),
		authCoreURL:  envOrDefault("AUTHIO_AUTH_CORE_URL", defaultAuthCore),
		apiURL:       envOrDefault("AUTHIO_API_URL", defaultMgmtAPI),
		config:       "authio.yaml",
	}
	need := func(i int, name string) (string, error) {
		if i+1 >= len(args) {
			return "", errors.New(name + " requires a value")
		}
		return strings.TrimSpace(args[i+1]), nil
	}
	for i := 0; i < len(args); i++ {
		var err error
		switch args[i] {
		case "--agent":
			f.agent, err = need(i, "--agent")
			i++
		case "--client-id":
			f.clientID, err = need(i, "--client-id")
			i++
		case "--project":
			f.project, err = need(i, "--project")
			i++
		case "--clearance-url":
			f.clearanceURL, err = need(i, "--clearance-url")
			i++
		case "--auth-core-url":
			f.authCoreURL, err = need(i, "--auth-core-url")
			i++
		case "--api-url":
			f.apiURL, err = need(i, "--api-url")
			i++
		case "--config", "-f":
			f.config, err = need(i, "--config")
			i++
		case "--profile":
			f.profile, err = need(i, "--profile")
			i++
		case "--port":
			var v string
			v, err = need(i, "--port")
			if err == nil {
				_, err = fmt.Sscanf(v, "%d", &f.port)
			}
			i++
		case "--no-browser":
			f.noBrowser = true
		default:
			return f, errors.New("unknown flag: " + args[i])
		}
		if err != nil {
			return f, err
		}
	}
	if f.agent == "" {
		return f, clearance.ErrAgentRequired
	}
	f.clearanceURL = strings.TrimRight(f.clearanceURL, "/")
	f.authCoreURL = strings.TrimRight(f.authCoreURL, "/")
	f.apiURL = strings.TrimRight(f.apiURL, "/")
	return f, nil
}

func envOrDefault(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------- login

// lookupAgent reads the agent row through the operator's management-api
// profile (authio login) to learn its Connect client_id and project.
func lookupAgent(f clearanceFlags) (clientID, projectID string, err error) {
	name := f.profile
	if name == "" {
		name = resolveProfileName(nil)
	}
	p, _, err := loadProfile(name)
	if err != nil {
		return "", "", fmt.Errorf("to look up agent %s I need your Authio profile (run `authio login`), or pass --client-id and --project: %w", f.agent, err)
	}
	if f.apiURL != "" && f.apiURL != defaultMgmtAPI {
		p.APIURL = f.apiURL
	}
	res, err := apiGet(p, "/v1/session/clearance/agents/"+f.agent)
	if err != nil {
		return "", "", err
	}
	if res.status == 404 {
		return "", "", fmt.Errorf("agent %s not found in project %s", f.agent, p.ProjectID)
	}
	if res.status >= 400 {
		return "", "", apiError(res, "look up agent "+f.agent)
	}
	var row struct {
		DCRClientID string `json:"dcr_client_id"`
		Status      string `json:"status"`
		Name        string `json:"name"`
	}
	if err := json.Unmarshal(res.body, &row); err != nil || row.DCRClientID == "" {
		return "", "", fmt.Errorf("agent %s: response carried no dcr_client_id", f.agent)
	}
	if row.Status != "active" && row.Status != "" {
		fmt.Fprintf(os.Stderr, "  note: agent %q is %s — login works, but calls will be refused until it is active\n", row.Name, row.Status)
	}
	return row.DCRClientID, p.ProjectID, nil
}

func clearanceLogin(args []string) error {
	f, err := parseClearanceFlags(args)
	if err != nil {
		return err
	}
	clientID, projectID := f.clientID, f.project
	if clientID == "" || projectID == "" {
		c, p, err := lookupAgent(f)
		if err != nil {
			return err
		}
		if clientID == "" {
			clientID = c
		}
		if projectID == "" {
			projectID = p
		}
	}
	oc := &clearance.OAuthClient{AuthCoreURL: f.authCoreURL, ProjectID: projectID, ClientID: clientID, Resource: f.clearanceURL}

	ln, redirectURI, err := clearance.LoopbackListener(f.port)
	if err != nil {
		return fmt.Errorf("open loopback listener: %w", err)
	}
	defer ln.Close()
	verifier, err := newVerifier()
	if err != nil {
		return err
	}
	state, err := newLoginState()
	if err != nil {
		return err
	}
	authURL := oc.AuthorizeURL(redirectURI, state, clearance.ChallengeS256(verifier), clearance.ScopeTools)

	fmt.Println()
	fmt.Printf("  Signing in as agent %s (client %s)\n", f.agent, clientID)
	fmt.Println("  Open this URL if your browser does not:")
	fmt.Println()
	fmt.Println("    " + authURL)
	fmt.Println()
	fmt.Printf("  The redirect must be registered on the Connect client: %s\n", redirectURI)
	fmt.Println("  (tip: pass --port to keep it stable across logins)")
	fmt.Println()
	if !f.noBrowser {
		_ = openBrowser(authURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	code, err := clearance.AwaitCallback(ctx, ln, state)
	if err != nil {
		return err
	}
	tr, err := oc.Exchange(ctx, code, redirectURI, verifier)
	if err != nil {
		return fmt.Errorf("token exchange: %w", err)
	}
	store, err := clearance.DefaultTokenStore()
	if err != nil {
		return err
	}
	exp := time.Now().Add(50 * time.Minute)
	if tr.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	cred := clearance.AgentCredential{
		AgentID: f.agent, ProjectID: projectID, ClientID: clientID,
		AuthCoreURL: f.authCoreURL, ClearanceURL: f.clearanceURL,
		Scope: tr.Scope, AccessToken: tr.AccessToken, ExpiresAt: exp, RefreshToken: tr.RefreshToken,
	}
	if err := store.Save(cred); err != nil {
		return fmt.Errorf("save credential: %w", err)
	}
	fmt.Println("  ✓ Signed in.")
	fmt.Printf("  Saved %s/%s.json\n", store.Dir, f.agent)
	if tr.RefreshToken == "" {
		fmt.Println("  note: no refresh token was issued — you will need to log in again when the access token expires")
	}
	fmt.Println()
	fmt.Println("  Next: authio clearance init --agent " + f.agent)
	return nil
}

func newVerifier() (string, error)   { return clearance.NewCodeVerifier() }
func newLoginState() (string, error) { return clearance.NewState() }

// ---------------------------------------------------------------- serve / explain

func hostedFor(f clearanceFlags) (*clearance.Hosted, error) {
	store, err := clearance.DefaultTokenStore()
	if err != nil {
		return nil, err
	}
	cred, err := store.Load(f.agent)
	if err != nil {
		return nil, err
	}
	base := cred.ClearanceURL
	if base == "" {
		base = f.clearanceURL
	}
	oc := &clearance.OAuthClient{AuthCoreURL: cred.AuthCoreURL, ProjectID: cred.ProjectID, ClientID: cred.ClientID, Resource: base}
	return &clearance.Hosted{BaseURL: base, AgentID: f.agent, Tokens: &clearance.TokenSource{Store: store, Cred: cred, OAuth: oc}}, nil
}

func clearanceServe(args []string) error {
	f, err := parseClearanceFlags(args)
	if err != nil {
		return err
	}
	h, err := hostedFor(f)
	if err != nil {
		return errors.New(clearance.Humanize(err, f.agent))
	}
	cfg, err := clearance.LoadSidecarConfig(f.config)
	if err != nil {
		return err
	}
	root, err := clearance.Root()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &clearance.Server{Hosted: h, Root: root, Providers: cfg.Providers, Log: os.Stderr}
	fmt.Fprintf(os.Stderr, "authio clearance: serving agent %s (hosted %s, %d local provider(s), exec confined to %s)\n", f.agent, h.BaseURL, len(cfg.Providers), root)
	return srv.Serve(ctx, os.Stdin, os.Stdout)
}

func clearanceExplain(args []string) error {
	f, err := parseClearanceFlags(args)
	if err != nil {
		return err
	}
	h, err := hostedFor(f)
	if err != nil {
		return errors.New(clearance.Humanize(err, f.agent))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := h.Policy(ctx)
	if err != nil {
		return errors.New(clearance.Humanize(err, f.agent))
	}
	var pretty map[string]any
	if json.Unmarshal(raw, &pretty) == nil {
		b, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Println(string(raw))
	return nil
}

func clearanceLogout(args []string) error {
	f, err := parseClearanceFlags(args)
	if err != nil {
		return err
	}
	store, err := clearance.DefaultTokenStore()
	if err != nil {
		return err
	}
	if err := store.Delete(f.agent); err != nil {
		return err
	}
	fmt.Printf("  Removed local credential for agent %s.\n", f.agent)
	return nil
}

// ---------------------------------------------------------------- init

func clearanceInit(args []string) error {
	f, err := parseClearanceFlags(args)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("  Claude Code (one command):")
	fmt.Println()
	fmt.Printf("    claude mcp add authio-clearance -- authio clearance serve --agent %s\n", f.agent)
	fmt.Println()
	fmt.Println("  Cursor (.cursor/mcp.json) / any stdio MCP client:")
	fmt.Println()
	cfg := map[string]any{"mcpServers": map[string]any{"authio-clearance": map[string]any{
		"command": "authio", "args": []string{"clearance", "serve", "--agent", f.agent},
	}}}
	b, _ := json.MarshalIndent(cfg, "    ", "  ")
	fmt.Println("    " + string(b))
	fmt.Println()
	fmt.Println("  Run from the directory you want exec.run confined to. Local MCP servers to")
	fmt.Println("  wrap go under clearance.providers in authio.yaml (see `authio clearance help`).")
	fmt.Println()
	if _, err := credentials.DefaultStore(); err == nil {
		if st, err := clearance.DefaultTokenStore(); err == nil {
			if _, err := st.Load(f.agent); err != nil {
				fmt.Printf("  Not signed in yet: authio clearance login --agent %s\n\n", f.agent)
			}
		}
	}
	return nil
}
