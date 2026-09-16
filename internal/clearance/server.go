package clearance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Server is the local MCP stdio server. Its tool surface is the union of
// the hosted agent's tools (proxied verbatim), `exec.run`, and the tools of
// every wrapped stdio provider (namespaced `<provider>.<tool>`). Every local
// call is judged by Hosted.Evaluate before it runs.
type Server struct {
	Hosted    *Hosted
	Root      string // launch directory; exec cwd is confined to it
	Providers []StdioProvider
	Log       io.Writer // diagnostics (stderr); never the token

	mu       sync.Mutex
	children map[string]*stdioChild
	intent   string
}

const execToolName = "exec.run"

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		fmt.Fprintf(s.Log, "authio clearance: "+format+"\n", a...)
	}
}

// Serve reads JSON-RPC from in and writes responses to out until EOF.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.children = map[string]*stdioChild{}
	defer s.closeChildren()
	w := &lineWriter{w: out}
	sc := newLineScanner(in)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = w.write(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: rpcParseError, Message: "parse error"}})
			continue
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			_ = w.write(rpcResponse{JSONRPC: "2.0", ID: nullID(req.ID), Error: &rpcError{Code: rpcInvalidRequest, Message: "jsonrpc must be \"2.0\" and method is required"}})
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			s.handleNotification(&req)
			continue
		}
		result, rerr := s.dispatch(ctx, &req)
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		if rerr != nil {
			resp.Error = rerr
		} else {
			resp.Result = result
		}
		if err := w.write(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func nullID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func (s *Server) handleNotification(req *rpcRequest) {
	// notifications/initialized, notifications/cancelled: nothing to do.
}

func (s *Server) dispatch(ctx context.Context, req *rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			Meta map[string]any `json:"_meta"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if v, _ := p.Meta["intent"].(string); v != "" {
			s.mu.Lock()
			s.intent = v
			s.mu.Unlock()
			SetIntent(v)
		}
		// Open the hosted session now so local verdicts bind to it (and the
		// declared intent lands on the session row). Failure is not fatal
		// to the client's initialize: evaluate/tools/list retry lazily.
		if err := s.Hosted.ensureSession(ctx); err != nil {
			s.logf("hosted session not opened yet: %s", Humanize(err, s.Hosted.AgentID))
		}
		return map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "authio-clearance", "title": "Authio Clearance (local sidecar)", "version": "0.5.0"},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools, err := s.listTools(ctx)
		if err != nil {
			return nil, &rpcError{Code: rpcInternal, Message: Humanize(err, s.Hosted.AgentID)}
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		return s.callTool(ctx, req.Params)
	default:
		return nil, &rpcError{Code: rpcMethodNotFound, Message: "method not found: " + req.Method}
	}
}

// ---------------------------------------------------------------- surface

func (s *Server) listTools(ctx context.Context) ([]Tool, error) {
	hosted, err := s.Hosted.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	tools := append([]Tool{}, hosted...)
	tools = append(tools, Tool{
		Name:  execToolName,
		Title: "Run a local command",
		Description: "Run a command on this machine (no shell; argv exactly as given). Every call is judged by Authio Clearance first " +
			"(policy target exec:<command args>). cwd is confined to the directory the sidecar was started in.",
		InputSchema: map[string]any{
			"type":     "object",
			"required": []string{"command"},
			"properties": map[string]any{
				"command":    map[string]any{"type": "string", "description": "Executable name or path (argv[0])."},
				"args":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"cwd":        map[string]any{"type": "string", "description": "Relative to the sidecar's working tree."},
				"timeout_ms": map[string]any{"type": "integer", "minimum": 1, "maximum": int(execMaxTimeout / time.Millisecond)},
			},
			"additionalProperties": false,
		},
	})
	for _, p := range s.Providers {
		child, err := s.child(ctx, p.Name)
		if err != nil {
			s.logf("provider %s unavailable: %v", p.Name, err)
			continue
		}
		for _, t := range child.tools {
			nt := t
			nt.Name = p.Name + "." + t.Name
			if nt.Description == "" {
				nt.Description = "Tool " + t.Name + " from local MCP server " + p.Name
			}
			nt.Description += " (judged by Authio Clearance as mcp/" + p.Name + "/" + t.Name + ")"
			tools = append(tools, nt)
		}
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, nil
}

func (s *Server) child(ctx context.Context, name string) (*stdioChild, error) {
	s.mu.Lock()
	c := s.children[name]
	s.mu.Unlock()
	if c != nil {
		select {
		case <-c.done:
			// exited; respawn below
		default:
			return c, nil
		}
	}
	var p *StdioProvider
	for i := range s.Providers {
		if s.Providers[i].Name == name {
			p = &s.Providers[i]
		}
	}
	if p == nil {
		return nil, fmt.Errorf("unknown provider %s", name)
	}
	c, err := startStdioChild(ctx, s.Root, *p)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.children[name] = c
	s.mu.Unlock()
	return c, nil
}

func (s *Server) closeChildren() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.children {
		c.close()
	}
}

// ---------------------------------------------------------------- calls

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Meta      map[string]any  `json:"_meta"`
}

func (s *Server) callTool(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
	var p callParams
	if err := json.Unmarshal(raw, &p); err != nil || p.Name == "" {
		return nil, &rpcError{Code: rpcInvalidParams, Message: "name is required"}
	}
	s.mu.Lock()
	intent := s.intent
	s.mu.Unlock()
	if v, _ := p.Meta["intent"].(string); v != "" {
		intent = v
	}

	switch {
	case p.Name == execToolName:
		return s.callExec(ctx, p.Arguments, intent)
	case s.providerFor(p.Name) != "":
		return s.callProvider(ctx, p, intent)
	default:
		res, rerr, err := s.Hosted.CallTool(ctx, p.Name, p.Arguments, p.Meta)
		if err != nil {
			return textResult(Humanize(err, s.Hosted.AgentID), true), nil
		}
		if rerr != nil {
			return nil, rerr
		}
		return res, nil
	}
}

// providerFor maps "<provider>.<tool>" to the provider name, or "".
func (s *Server) providerFor(tool string) string {
	for _, p := range s.Providers {
		if strings.HasPrefix(tool, p.Name+".") && len(tool) > len(p.Name)+1 {
			return p.Name
		}
	}
	return ""
}

// verdictResult renders a non-cleared verdict as an isError tool result the
// agent can read, with machine-usable _meta.
func verdictResult(v *Verdict, target string) *ToolResult {
	meta := map[string]any{"verdict": v.Verdict, "reason_code": v.ReasonCode, "verdict_id": v.VerdictID, "target": target}
	if v.PolicyID != "" {
		meta["policy_id"] = v.PolicyID
	}
	if v.Rule != "" {
		meta["rule"] = v.Rule
	}
	switch v.Verdict {
	case "needs_clearance":
		meta["approval_id"] = v.ApprovalID
		if v.ExpiresAt != nil {
			meta["expires_at"] = v.ExpiresAt.UTC().Format(time.RFC3339)
		}
		msg := fmt.Sprintf("needs clearance: a human must approve %s (approval %s", target, v.ApprovalID)
		if v.ExpiresAt != nil {
			msg += ", pending until " + v.ExpiresAt.UTC().Format(time.RFC3339)
		}
		msg += "). Call clearance.await_approval with this approval_id, then retry with _meta.approval_id."
		r := textResult(msg, true)
		r.Meta = meta
		return r
	default:
		r := textResult(fmt.Sprintf("denied: %s (%s)", target, v.ReasonCode), true)
		r.Meta = meta
		return r
	}
}

func (s *Server) callExec(ctx context.Context, raw json.RawMessage, intent string) (any, *rpcError) {
	var a ExecArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, &rpcError{Code: rpcInvalidParams, Message: "exec.run: invalid arguments"}
	}
	if strings.TrimSpace(a.Command) == "" {
		return textResult("exec.run: command is required", true), nil
	}
	argv0 := a.Command
	if i := strings.LastIndexAny(argv0, `/\`); i >= 0 {
		argv0 = argv0[i+1:]
	}
	args := map[string]any{"command": a.CommandLine(), "argv": append([]string{a.Command}, a.Args...), "cwd": a.Cwd}
	v, err := s.Hosted.Evaluate(ctx, "exec", argv0, args, intent)
	if err != nil {
		return textResult("clearance unavailable, refusing to run: "+Humanize(err, s.Hosted.AgentID), true), nil
	}
	if v.Verdict != "cleared" {
		return verdictResult(v, "exec:"+a.CommandLine()), nil
	}
	res, err := RunExec(ctx, s.Root, a)
	if err != nil {
		return textResult(err.Error(), true), nil
	}
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["verdict_id"] = v.VerdictID
	return res, nil
}

func (s *Server) callProvider(ctx context.Context, p callParams, intent string) (any, *rpcError) {
	prov := s.providerFor(p.Name)
	tool := strings.TrimPrefix(p.Name, prov+".")
	var args map[string]any
	if len(p.Arguments) > 0 {
		_ = json.Unmarshal(p.Arguments, &args)
	}
	v, err := s.Hosted.Evaluate(ctx, "mcp", prov+"/"+tool, args, intent)
	if err != nil {
		return textResult("clearance unavailable, refusing to run: "+Humanize(err, s.Hosted.AgentID), true), nil
	}
	if v.Verdict != "cleared" {
		return verdictResult(v, "mcp/"+prov+"/"+tool), nil
	}
	child, err := s.child(ctx, prov)
	if err != nil {
		return textResult("provider "+prov+" unavailable: "+err.Error(), true), nil
	}
	params := map[string]any{"name": tool}
	if len(p.Arguments) > 0 {
		params["arguments"] = p.Arguments
	}
	res, rerr, err := child.call(ctx, "tools/call", params)
	if err != nil {
		return textResult("provider "+prov+": "+err.Error(), true), nil
	}
	if rerr != nil {
		return nil, rerr
	}
	// Stamp the verdict id onto the child's result without disturbing it.
	var m map[string]any
	if json.Unmarshal(res, &m) == nil && m != nil {
		meta, _ := m["_meta"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		meta["verdict_id"] = v.VerdictID
		m["_meta"] = meta
		return m, nil
	}
	return res, nil
}

// ---------------------------------------------------------------- helpers for the command layer

// ErrAgentRequired is returned when --agent is missing.
var ErrAgentRequired = errors.New("--agent <agent_id> is required")

// Root returns the sidecar's working tree: the current directory.
func Root() (string, error) {
	return os.Getwd()
}
