package clearance

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain doubles as a fake stdio MCP child when re-executed with
// AUTHIO_FAKE_MCP=1: it answers initialize, tools/list (one tool
// "echo") and tools/call (echoes its arguments).
func TestMain(m *testing.M) {
	if os.Getenv("AUTHIO_FAKE_MCP") == "1" {
		runFakeMCP()
		return
	}
	os.Exit(m.Run())
}

func runFakeMCP() {
	sc := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for sc.Scan() {
		var req rpcRequest
		if json.Unmarshal(sc.Bytes(), &req) != nil || len(req.ID) == 0 {
			continue
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "fake"}}
		case "tools/list":
			result = map[string]any{"tools": []Tool{{Name: "echo", Description: "echo args", InputSchema: map[string]any{"type": "object"}}, {Name: "boom", InputSchema: map[string]any{"type": "object"}}}}
		case "tools/call":
			var p callParams
			_ = json.Unmarshal(req.Params, &p)
			if p.Name == "boom" {
				b, _ := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32000, Message: "boom"}})
				fmt.Fprintf(out, "%s\n", b)
				out.Flush()
				continue
			}
			result = map[string]any{"content": []ToolContent{{Type: "text", Text: "echo:" + string(p.Arguments)}}, "leaked_env": os.Getenv("AUTHIO_SECRET_MARKER"), "extra_env": os.Getenv("FAKE_EXTRA")}
		default:
			result = map[string]any{}
		}
		b, _ := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
		fmt.Fprintf(out, "%s\n", b)
		out.Flush()
	}
}

// fakeClearance stands in for clearance.authio.com: MCP data-plane with two
// hosted tools, /evaluate with a scripted verdict per tool token, /policy.
type fakeClearance struct {
	srv       *httptest.Server
	mu        sync.Mutex
	verdicts  map[string]Verdict // key: provider + " " + tool
	evaluated []map[string]any
	calls     []string
	initCount int
	sessions  map[string]bool
}

func newFakeClearance(t *testing.T) *fakeClearance {
	f := &fakeClearance{verdicts: map[string]Verdict{}, sessions: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer acc_ok" {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="x"`)
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "invalid_token"})
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/evaluate"):
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.mu.Lock()
			f.evaluated = append(f.evaluated, req)
			v, ok := f.verdicts[req["provider"].(string)+" "+req["tool"].(string)]
			f.mu.Unlock()
			if !ok {
				v = Verdict{VerdictID: "vrd_default", Verdict: "denied", ReasonCode: "no_matching_rule"}
			}
			_ = json.NewEncoder(w).Encode(v)
		case strings.HasSuffix(r.URL.Path, "/policy"):
			_ = json.NewEncoder(w).Encode(map[string]any{"default": "deny", "profile_chain": []string{"prf_1"}})
		case strings.HasSuffix(r.URL.Path, "/mcp"):
			var req rpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			sid := r.Header.Get("Mcp-Session-Id")
			f.mu.Lock()
			defer f.mu.Unlock()
			if req.Method == "initialize" {
				f.initCount++
				id := fmt.Sprintf("cls_%d", f.initCount)
				f.sessions[id] = true
				w.Header().Set("Mcp-Session-Id", id)
				_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"protocolVersion": "2025-06-18"}})
				return
			}
			if !f.sessions[sid] {
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": "session_not_found"})
				return
			}
			switch req.Method {
			case "tools/list":
				_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": []Tool{
					{Name: "valet.hubspot.request", InputSchema: map[string]any{"type": "object"}},
					{Name: "clearance.await_approval", InputSchema: map[string]any{"type": "object"}},
				}}})
			case "tools/call":
				var p callParams
				_ = json.Unmarshal(req.Params, &p)
				f.calls = append(f.calls, p.Name)
				_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"content": []ToolContent{{Type: "text", Text: "hosted:" + p.Name}}}})
			default:
				_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: rpcMethodNotFound, Message: "nope"}})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeClearance) setVerdict(provider, tool string, v Verdict) {
	f.mu.Lock()
	f.verdicts[provider+" "+tool] = v
	f.mu.Unlock()
}

// harness runs Server.Serve over pipes and drives it with JSON-RPC.
type harness struct {
	t    *testing.T
	in   io.WriteCloser
	out  *bufio.Scanner
	next int
	done chan error
}

func startServer(t *testing.T, s *Server) *harness {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	h := &harness{t: t, in: inW, out: newLineScanner(outR), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { h.done <- s.Serve(ctx, inR, outW); _ = outW.Close() }()
	t.Cleanup(func() { _ = inW.Close(); cancel(); <-h.done })
	return h
}

func (h *harness) call(method string, params any) rpcResponse {
	h.next++
	req := map[string]any{"jsonrpc": "2.0", "id": h.next, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	if _, err := fmt.Fprintf(h.in, "%s\n", b); err != nil {
		h.t.Fatal(err)
	}
	if !h.out.Scan() {
		h.t.Fatalf("no response to %s: %v", method, h.out.Err())
	}
	var resp rpcResponse
	if err := json.Unmarshal(h.out.Bytes(), &resp); err != nil {
		h.t.Fatalf("bad response: %s", h.out.Text())
	}
	return resp
}

func (h *harness) toolCall(name string, args any, meta map[string]any) *ToolResult {
	p := map[string]any{"name": name, "arguments": args}
	if meta != nil {
		p["_meta"] = meta
	}
	resp := h.call("tools/call", p)
	if resp.Error != nil {
		h.t.Fatalf("tools/call %s: rpc error %+v", name, resp.Error)
	}
	b, _ := json.Marshal(resp.Result)
	var r ToolResult
	_ = json.Unmarshal(b, &r)
	return &r
}

func newTestServer(t *testing.T, fc *fakeClearance, providers []StdioProvider) *Server {
	root := t.TempDir()
	cred := &AgentCredential{AgentID: "agt_1", ProjectID: "proj_1", ClientID: "dcr_1", AccessToken: "acc_ok", ExpiresAt: time.Now().Add(time.Hour), RefreshToken: "art"}
	hosted := &Hosted{BaseURL: fc.srv.URL, AgentID: "agt_1", Tokens: &TokenSource{Cred: cred, OAuth: &OAuthClient{AuthCoreURL: "http://unused.invalid", ProjectID: "proj_1", ClientID: "dcr_1"}}}
	return &Server{Hosted: hosted, Root: root, Providers: providers, Log: io.Discard}
}

func fakeProvider(name string, env map[string]string) StdioProvider {
	exe, _ := os.Executable()
	e := map[string]string{"AUTHIO_FAKE_MCP": "1"}
	for k, v := range env {
		e[k] = v
	}
	return StdioProvider{Name: name, Command: exe, Args: []string{"-test.run=TestMain"}, Env: e}
}

func TestServer_FramingAndLifecycle(t *testing.T) {
	fc := newFakeClearance(t)
	h := startServer(t, newTestServer(t, fc, nil))

	// parse error → -32700 with null id
	fmt.Fprintln(h.in, "{not json")
	h.out.Scan()
	if !strings.Contains(h.out.Text(), `"code":-32700`) {
		t.Fatalf("parse error not reported: %s", h.out.Text())
	}
	// invalid request
	fmt.Fprintln(h.in, `{"jsonrpc":"1.0","id":9,"method":"x"}`)
	h.out.Scan()
	if !strings.Contains(h.out.Text(), `"code":-32600`) {
		t.Fatalf("invalid request not reported: %s", h.out.Text())
	}
	// notification produces no response; next request still answered
	fmt.Fprintln(h.in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	resp := h.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "_meta": map[string]any{"intent": "tidy repo"}})
	if resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}
	if !strings.Contains(string(mustJSON(resp.Result)), "authio-clearance") {
		t.Fatalf("serverInfo missing: %s", mustJSON(resp.Result))
	}
	if r := h.call("ping", nil); r.Error != nil {
		t.Fatal("ping")
	}
	if r := h.call("bogus/method", nil); r.Error == nil || r.Error.Code != rpcMethodNotFound {
		t.Fatalf("unknown method: %+v", r.Error)
	}
}

func TestServer_ToolsListMergesHostedExecAndProviders(t *testing.T) {
	t.Setenv("AUTHIO_SECRET_MARKER", "leak")
	fc := newFakeClearance(t)
	h := startServer(t, newTestServer(t, fc, []StdioProvider{fakeProvider("fake", map[string]string{"FAKE_EXTRA": "yes"})}))
	resp := h.call("tools/list", map[string]any{})
	if resp.Error != nil {
		t.Fatalf("tools/list: %+v", resp.Error)
	}
	var out struct{ Tools []Tool }
	_ = json.Unmarshal(mustJSON(resp.Result), &out)
	names := map[string]bool{}
	for _, tl := range out.Tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"valet.hubspot.request", "clearance.await_approval", execToolName, "fake.echo", "fake.boom"} {
		if !names[want] {
			t.Fatalf("tools/list missing %s: %v", want, names)
		}
	}
	if fc.initCount != 1 {
		t.Fatalf("hosted initialize count = %d", fc.initCount)
	}
}

func TestServer_ExecGatedByCentralVerdict(t *testing.T) {
	fc := newFakeClearance(t)
	h := startServer(t, newTestServer(t, fc, nil))
	h.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "_meta": map[string]any{"intent": "run tests"}})

	// default: no verdict scripted → denied
	r := h.toolCall(execToolName, ExecArgs{Command: "printf", Args: []string{"hi"}}, nil)
	if !r.IsError || !strings.HasPrefix(r.Content[0].Text, "denied:") || r.Meta["verdict"] != "denied" {
		t.Fatalf("denied not rendered: %+v", r)
	}
	// needs clearance → approval id surfaced, nothing runs
	exp := time.Now().Add(5 * time.Minute)
	fc.setVerdict("exec", "printf", Verdict{VerdictID: "vrd_2", Verdict: "needs_clearance", ReasonCode: "ask_rule", ApprovalID: "apr_9", ExpiresAt: &exp})
	r = h.toolCall(execToolName, ExecArgs{Command: "printf", Args: []string{"hi"}}, nil)
	if !r.IsError || r.Meta["approval_id"] != "apr_9" || !strings.Contains(r.Content[0].Text, "clearance.await_approval") {
		t.Fatalf("needs_clearance not rendered: %+v", r)
	}
	// cleared → runs, verdict id stamped, argv verbatim
	fc.setVerdict("exec", "printf", Verdict{VerdictID: "vrd_3", Verdict: "cleared", ReasonCode: "allow_rule"})
	r = h.toolCall(execToolName, ExecArgs{Command: "printf", Args: []string{"%s", "a b"}}, nil)
	if r.IsError || r.Meta["verdict_id"] != "vrd_3" {
		t.Fatalf("cleared exec failed: %+v", r)
	}
	if got := r.StructuredContent.(map[string]any)["stdout"]; got != "a b" {
		t.Fatalf("stdout = %v", got)
	}
	// what was sent to Clearance: provider exec, tool argv0, command line + intent + session
	fc.mu.Lock()
	last := fc.evaluated[len(fc.evaluated)-1]
	fc.mu.Unlock()
	if last["provider"] != "exec" || last["tool"] != "printf" || last["args"].(map[string]any)["command"] != "printf %s a b" || last["intent"] != "run tests" || last["session_id"] != "cls_1" {
		t.Fatalf("evaluate payload: %v", last)
	}
	// a path in command is reduced to argv0 for the tool token but kept in args
	fc.setVerdict("exec", "printf", Verdict{VerdictID: "vrd_4", Verdict: "cleared"})
	r = h.toolCall(execToolName, ExecArgs{Command: "/usr/bin/printf", Args: []string{"x"}}, nil)
	fc.mu.Lock()
	last = fc.evaluated[len(fc.evaluated)-1]
	fc.mu.Unlock()
	if last["tool"] != "printf" || last["args"].(map[string]any)["command"] != "/usr/bin/printf x" {
		t.Fatalf("argv0 reduction: %v", last)
	}
	// cwd escape is refused even when cleared
	r = h.toolCall(execToolName, ExecArgs{Command: "/usr/bin/printf", Args: []string{"x"}, Cwd: "../../"}, nil)
	if !r.IsError || !strings.Contains(r.Content[0].Text, "escapes") {
		t.Fatalf("cwd escape: %+v", r)
	}
}

func TestServer_ProviderWrappedAndGated(t *testing.T) {
	t.Setenv("AUTHIO_SECRET_MARKER", "leak")
	fc := newFakeClearance(t)
	h := startServer(t, newTestServer(t, fc, []StdioProvider{fakeProvider("fake", map[string]string{"FAKE_EXTRA": "yes"})}))
	h.call("initialize", map[string]any{"protocolVersion": "2025-06-18"})

	// denied by default
	r := h.toolCall("fake.echo", map[string]any{"a": 1}, nil)
	if !r.IsError || r.Meta["target"] != "mcp/fake/echo" {
		t.Fatalf("provider call not denied: %+v", r)
	}
	// cleared → forwarded to the child; verdict id stamped; env scrubbed but explicit env passed
	fc.setVerdict("mcp", "fake/echo", Verdict{VerdictID: "vrd_p", Verdict: "cleared"})
	resp := h.call("tools/call", map[string]any{"name": "fake.echo", "arguments": map[string]any{"a": 1}})
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	var m map[string]any
	_ = json.Unmarshal(mustJSON(resp.Result), &m)
	if m["leaked_env"] != "" || m["extra_env"] != "yes" {
		t.Fatalf("child env: leaked=%v extra=%v", m["leaked_env"], m["extra_env"])
	}
	if m["_meta"].(map[string]any)["verdict_id"] != "vrd_p" {
		t.Fatalf("verdict id not stamped: %v", m["_meta"])
	}
	if !strings.Contains(fmt.Sprint(m["content"]), `echo:{"a":1}`) {
		t.Fatalf("child result not returned: %v", m["content"])
	}
	// child JSON-RPC error passes through as an error
	fc.setVerdict("mcp", "fake/boom", Verdict{VerdictID: "vrd_b", Verdict: "cleared"})
	resp = h.call("tools/call", map[string]any{"name": "fake.boom"})
	if resp.Error == nil || resp.Error.Message != "boom" {
		t.Fatalf("child error not passed through: %+v", resp)
	}
	// evaluate saw provider mcp, tool fake/echo, args
	fc.mu.Lock()
	first := fc.evaluated[0]
	fc.mu.Unlock()
	if first["provider"] != "mcp" || first["tool"] != "fake/echo" || first["args"].(map[string]any)["a"] != float64(1) {
		t.Fatalf("evaluate payload: %v", first)
	}
}

func TestServer_HostedProxyAndSessionRecovery(t *testing.T) {
	fc := newFakeClearance(t)
	h := startServer(t, newTestServer(t, fc, nil))
	r := h.toolCall("valet.hubspot.request", map[string]any{"method": "GET", "path": "/x"}, map[string]any{"approval_id": "apr_1"})
	if r.IsError || r.Content[0].Text != "hosted:valet.hubspot.request" {
		t.Fatalf("hosted call: %+v", r)
	}
	// hosted evaluate is never called for hosted tools
	if len(fc.evaluated) != 0 {
		t.Fatalf("hosted tool was locally evaluated: %v", fc.evaluated)
	}
	// server-side session loss → transparent re-initialize
	fc.mu.Lock()
	fc.sessions = map[string]bool{}
	fc.mu.Unlock()
	r = h.toolCall("clearance.await_approval", map[string]any{"approval_id": "apr_1"}, nil)
	if r.IsError || fc.initCount != 2 {
		t.Fatalf("session recovery: err=%v inits=%d", r.IsError, fc.initCount)
	}
}

func TestServer_TokenRejectedIsHumane(t *testing.T) {
	fc := newFakeClearance(t)
	s := newTestServer(t, fc, nil)
	s.Hosted.Tokens.Cred.AccessToken = "acc_bad"
	s.Hosted.Tokens.Cred.RefreshToken = ""
	s.Hosted.Tokens.Cred.ExpiresAt = time.Now().Add(time.Hour)
	h := startServer(t, s)
	resp := h.call("tools/list", map[string]any{})
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "authio clearance login --agent agt_1") {
		t.Fatalf("expected re-login hint, got %+v", resp.Error)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// Sanity: the fake child really is a separate process (guards against the
// harness accidentally running in-process).
func TestFakeChildIsSubprocess(t *testing.T) {
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=TestMain")
	cmd.Env = []string{"AUTHIO_FAKE_MCP=1", "PATH=" + os.Getenv("PATH")}
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	out, err := cmd.Output()
	if err != nil || !strings.Contains(string(out), "2025-06-18") {
		t.Fatalf("fake child: %v %s", err, out)
	}
}
