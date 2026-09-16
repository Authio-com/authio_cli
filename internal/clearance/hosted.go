package clearance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Hosted is the client for one agent's hosted Clearance surface:
// the MCP data-plane (proxied tools), /evaluate (local-tool verdicts) and
// /policy (--explain).
type Hosted struct {
	BaseURL string
	AgentID string
	Tokens  *TokenSource
	HTTP    *http.Client

	mu        sync.Mutex
	sessionID string
	nextID    int64
}

func (h *Hosted) http() *http.Client {
	if h.HTTP != nil {
		return h.HTTP
	}
	return &http.Client{Timeout: 90 * time.Second}
}

func (h *Hosted) agentURL(suffix string) string {
	return strings.TrimRight(h.BaseURL, "/") + "/v1/agents/" + h.AgentID + suffix
}

// APIError is a structured error from Clearance's REST routes.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Message)
	}
	return fmt.Sprintf("%s (%d)", e.Code, e.Status)
}

// Humanize turns the common failures into actionable sentences.
func Humanize(err error, agentID string) string {
	var ae *APIError
	switch {
	case errors.Is(err, ErrNotLoggedIn), errors.Is(err, ErrReloginRequired):
		return fmt.Sprintf("Not signed in for this agent. Run:\n\n    authio clearance login --agent %s\n", agentID)
	case errors.As(err, &ae):
		switch ae.Code {
		case "agent_paused":
			return "This agent is paused in the Authio dashboard (Clearance → Agents). Resume it to continue."
		case "agent_revoked":
			return "This agent has been revoked in the Authio dashboard. Create a new agent or restore this one."
		case "agent_not_found":
			return fmt.Sprintf("Agent %s does not match the signed-in client. Check the agent id, or run `authio clearance login --agent %s`.", agentID, agentID)
		case "insufficient_scope":
			return fmt.Sprintf("The saved token lacks the tools:call scope. Run `authio clearance login --agent %s` to re-consent.", agentID)
		case "principal_required":
			return "This agent runs as a user, but the token is machine-to-machine. Log in interactively with `authio clearance login`."
		case "invalid_token", "missing_token":
			return fmt.Sprintf("Token rejected. Run `authio clearance login --agent %s`.", agentID)
		}
	}
	return err.Error()
}

func (h *Hosted) do(ctx context.Context, method, url string, body any, extra map[string]string) (int, []byte, http.Header, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	try := func(tok string) (int, []byte, http.Header, error) {
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "authio-cli/clearance")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		resp, err := h.http().Do(req)
		if err != nil {
			return 0, nil, nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		return resp.StatusCode, b, resp.Header, err
	}
	tok, err := h.Tokens.Token(ctx)
	if err != nil {
		return 0, nil, nil, err
	}
	status, b, hdr, err := try(tok)
	if err == nil && status == http.StatusUnauthorized && h.Tokens.Cred.RefreshToken != "" {
		// One forced refresh, then give up with a re-login hint.
		h.Tokens.Cred.ExpiresAt = time.Time{}
		if body != nil {
			bb, _ := json.Marshal(body)
			rdr = bytes.NewReader(bb)
		}
		tok, err = h.Tokens.Token(ctx)
		if err != nil {
			return 0, nil, nil, err
		}
		status, b, hdr, err = try(tok)
	}
	return status, b, hdr, err
}

func apiErr(status int, body []byte) error {
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Code == "" {
		e.Code = http.StatusText(status)
	}
	return &APIError{Status: status, Code: e.Code, Message: e.Message}
}

// Verdict is Clearance's evaluate envelope (the parts the sidecar uses).
type Verdict struct {
	VerdictID  string     `json:"verdict_id"`
	Verdict    string     `json:"verdict"`
	ReasonCode string     `json:"reason_code"`
	PolicyID   string     `json:"policy_id,omitempty"`
	Rule       string     `json:"rule,omitempty"`
	ApprovalID string     `json:"approval_id,omitempty"`
	ExpiresAt  *time.Time `json:"approval_expires_at,omitempty"`
}

// Evaluate judges a local tool call.
func (h *Hosted) Evaluate(ctx context.Context, provider, tool string, args map[string]any, intent string) (*Verdict, error) {
	payload := map[string]any{"provider": provider, "tool": tool, "args": args}
	h.mu.Lock()
	if h.sessionID != "" {
		payload["session_id"] = h.sessionID
	}
	h.mu.Unlock()
	if intent != "" {
		payload["intent"] = intent
	}
	status, b, _, err := h.do(ctx, http.MethodPost, h.agentURL("/evaluate"), payload, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		// A stale hosted session id: drop it and judge without one.
		var e struct{ Code string }
		_ = json.Unmarshal(b, &e)
		if e.Code == "session_not_found" {
			h.mu.Lock()
			h.sessionID = ""
			h.mu.Unlock()
			delete(payload, "session_id")
			status, b, _, err = h.do(ctx, http.MethodPost, h.agentURL("/evaluate"), payload, nil)
			if err != nil {
				return nil, err
			}
		}
	}
	if status != http.StatusOK {
		return nil, apiErr(status, b)
	}
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("decode verdict: %w", err)
	}
	return &v, nil
}

// Policy fetches the agent's resolved rule chain (raw JSON, printed as-is).
func (h *Hosted) Policy(ctx context.Context) (json.RawMessage, error) {
	status, b, _, err := h.do(ctx, http.MethodGet, h.agentURL("/policy"), nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiErr(status, b)
	}
	return json.RawMessage(b), nil
}

// ---------------------------------------------------------------- MCP proxy

// rpc sends one JSON-RPC request to the hosted data-plane, managing the
// Mcp-Session-Id: initialize on first use, re-initialize on 404.
func (h *Hosted) rpc(ctx context.Context, method string, params any) (json.RawMessage, *rpcError, error) {
	if method != "initialize" {
		if err := h.ensureSession(ctx); err != nil {
			return nil, nil, err
		}
	}
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	sid := h.sessionID
	h.mu.Unlock()
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	hdr := map[string]string{}
	if sid != "" && method != "initialize" {
		hdr["Mcp-Session-Id"] = sid
	}
	status, b, rh, err := h.do(ctx, http.MethodPost, h.agentURL("/mcp"), req, hdr)
	if err != nil {
		return nil, nil, err
	}
	if status == http.StatusNotFound && method != "initialize" {
		// Session expired/revoked server-side: re-initialize once and retry.
		h.mu.Lock()
		h.sessionID = ""
		h.mu.Unlock()
		if err := h.ensureSession(ctx); err != nil {
			return nil, nil, err
		}
		h.mu.Lock()
		hdr["Mcp-Session-Id"] = h.sessionID
		h.mu.Unlock()
		status, b, rh, err = h.do(ctx, http.MethodPost, h.agentURL("/mcp"), req, hdr)
		if err != nil {
			return nil, nil, err
		}
	}
	if status != http.StatusOK {
		return nil, nil, apiErr(status, b)
	}
	if method == "initialize" {
		if sid := rh.Get("Mcp-Session-Id"); sid != "" {
			h.mu.Lock()
			h.sessionID = sid
			h.mu.Unlock()
		}
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, nil, fmt.Errorf("decode hosted response: %w", err)
	}
	return resp.Result, resp.Error, nil
}

// Initialize opens the hosted session, forwarding the local client's
// declared intent when present.
func (h *Hosted) Initialize(ctx context.Context, intent string) error {
	params := map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "authio-cli", "version": "clearance"},
	}
	if intent != "" {
		params["_meta"] = map[string]any{"intent": intent}
	}
	_, rerr, err := h.rpc(ctx, "initialize", params)
	if err != nil {
		return err
	}
	if rerr != nil {
		return fmt.Errorf("hosted initialize: %s", rerr.Message)
	}
	return nil
}

func (h *Hosted) ensureSession(ctx context.Context) error {
	h.mu.Lock()
	have := h.sessionID != ""
	h.mu.Unlock()
	if have {
		return nil
	}
	return h.Initialize(ctx, h.pendingIntent())
}

var intentMu sync.Mutex
var declaredIntent string

// SetIntent records the intent the local client declared so a hosted
// (re)initialize can carry it.
func SetIntent(s string) {
	intentMu.Lock()
	declaredIntent = s
	intentMu.Unlock()
}

func (h *Hosted) pendingIntent() string {
	intentMu.Lock()
	defer intentMu.Unlock()
	return declaredIntent
}

// SessionID returns the hosted session id (for evaluate binding / whoami).
func (h *Hosted) SessionID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessionID
}

// ListTools returns the hosted tool surface.
func (h *Hosted) ListTools(ctx context.Context) ([]Tool, error) {
	res, rerr, err := h.rpc(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	if rerr != nil {
		return nil, fmt.Errorf("hosted tools/list: %s", rerr.Message)
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return nil, err
	}
	return out.Tools, nil
}

// CallTool forwards a tools/call verbatim and returns the raw result.
func (h *Hosted) CallTool(ctx context.Context, name string, args json.RawMessage, meta map[string]any) (json.RawMessage, *rpcError, error) {
	params := map[string]any{"name": name}
	if len(args) > 0 {
		params["arguments"] = args
	}
	if len(meta) > 0 {
		params["_meta"] = meta
	}
	return h.rpc(ctx, "tools/call", params)
}
