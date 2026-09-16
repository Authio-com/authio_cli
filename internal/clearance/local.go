package clearance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Local tools: `exec.run` and stdio MCP servers declared in authio.yaml.
// Neither carries policy — every call is judged by Hosted.Evaluate first.

const (
	execMaxOutput  = 1 << 20
	execMaxTimeout = 120 * time.Second
	execDefTimeout = 30 * time.Second
)

// ExecArgs is the exec.run input.
type ExecArgs struct {
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Cwd       string   `json:"cwd,omitempty"`
	TimeoutMS int      `json:"timeout_ms,omitempty"`
}

// CommandLine is the policy string: argv joined by single spaces, so
// `exec:git push*` matches ["git","push","origin"].
func (a ExecArgs) CommandLine() string {
	parts := append([]string{a.Command}, a.Args...)
	return strings.Join(parts, " ")
}

// resolveCwd confines cwd to root (the directory the sidecar was launched
// in). Symlinks are resolved so a link out of the tree is refused too.
func resolveCwd(root, cwd string) (string, error) {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if cwd == "" {
		return rootReal, nil
	}
	p := cwd
	if !filepath.IsAbs(p) {
		p = filepath.Join(rootReal, p)
	}
	p = filepath.Clean(p)
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("cwd %q: %w", cwd, err)
	}
	rel, err := filepath.Rel(rootReal, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("cwd %q escapes the working tree %s", cwd, root)
	}
	return real, nil
}

// childEnv is the minimal environment handed to children: PATH and HOME
// (so tools resolve and find their config) plus explicit extras. The
// sidecar's own environment — including any tokens — is never inherited.
func childEnv(extra map[string]string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if l := os.Getenv("LANG"); l != "" {
		env = append(env, "LANG="+l)
	}
	if t := os.Getenv("TMPDIR"); t != "" {
		env = append(env, "TMPDIR="+t)
	}
	for k, v := range extra {
		if k == "" || strings.ContainsAny(k, "= \t\n") {
			continue
		}
		env = append(env, k+"="+v)
	}
	return env
}

// RunExec executes an already-cleared command: argv exactly as given, no
// shell, capped output and time.
func RunExec(ctx context.Context, root string, a ExecArgs) (*ToolResult, error) {
	if strings.TrimSpace(a.Command) == "" {
		return textResult("command is required", true), nil
	}
	cwd, err := resolveCwd(root, a.Cwd)
	if err != nil {
		return textResult(err.Error(), true), nil
	}
	timeout := execDefTimeout
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	if timeout > execMaxTimeout {
		timeout = execMaxTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, a.Command, a.Args...)
	cmd.Dir = cwd
	cmd.Env = childEnv(nil)
	cmd.Stdin = nil
	var stdout, stderr limitedBuf
	stdout.max, stderr.max = execMaxOutput, execMaxOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	runErr := cmd.Run()
	code := 0
	timedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
	if runErr != nil {
		var ee *exec.ExitError
		switch {
		case errors.As(runErr, &ee):
			code = ee.ExitCode()
		case timedOut:
			code = -1
		default:
			return textResult("exec failed: "+runErr.Error(), true), nil
		}
	}
	out := map[string]any{
		"command":     a.CommandLine(),
		"exit_code":   code,
		"stdout":      stdout.String(),
		"stderr":      stderr.String(),
		"truncated":   stdout.truncated || stderr.truncated,
		"timed_out":   timedOut,
		"duration_ms": time.Since(start).Milliseconds(),
	}
	res := jsonResult(out)
	res.IsError = code != 0
	return res, nil
}

// limitedBuf caps captured output. It deliberately does NOT embed
// bytes.Buffer: os/exec copies child output with io.Copy, which prefers a
// writer's ReadFrom — an embedded Buffer would expose bytes.Buffer.ReadFrom
// and bypass this Write (and the cap) entirely.
type limitedBuf struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *limitedBuf) Write(p []byte) (int, error) {
	room := b.max - b.buf.Len()
	if room <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		b.truncated = true
		_, _ = b.buf.Write(p[:room])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuf) String() string { return b.buf.String() }

// ---------------------------------------------------------------- stdio MCP children

// StdioProvider is a `clearance.providers.<name>` entry of type stdio.
type StdioProvider struct {
	Name    string
	Command string
	Args    []string
	Env     map[string]string
}

// stdioChild is a live connection to one stdio MCP server.
type stdioChild struct {
	name   string
	cmd    *exec.Cmd
	w      *lineWriter
	mu     sync.Mutex
	nextID int64
	pend   map[int64]chan rpcResponse
	tools  []Tool
	done   chan struct{}
}

func startStdioChild(ctx context.Context, root string, p StdioProvider) (*stdioChild, error) {
	if strings.TrimSpace(p.Command) == "" {
		return nil, fmt.Errorf("provider %s: command is required", p.Name)
	}
	cmd := exec.CommandContext(ctx, p.Command, p.Args...)
	cmd.Dir = root
	cmd.Env = childEnv(p.Env)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("provider %s: start %s: %w", p.Name, p.Command, err)
	}
	c := &stdioChild{name: p.Name, cmd: cmd, w: &lineWriter{w: stdin}, pend: map[int64]chan rpcResponse{}, done: make(chan struct{})}
	go c.readLoop(stdout)
	init := map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "authio-clearance", "version": "sidecar"},
	}
	if _, rerr, err := c.call(ctx, "initialize", init); err != nil || rerr != nil {
		_ = cmd.Process.Kill()
		if err == nil {
			err = errors.New(rerr.Message)
		}
		return nil, fmt.Errorf("provider %s: initialize: %w", p.Name, err)
	}
	_ = c.w.write(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	res, rerr, err := c.call(ctx, "tools/list", map[string]any{})
	if err != nil || rerr != nil {
		_ = cmd.Process.Kill()
		if err == nil {
			err = errors.New(rerr.Message)
		}
		return nil, fmt.Errorf("provider %s: tools/list: %w", p.Name, err)
	}
	var tl struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(res, &tl); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("provider %s: decode tools: %w", p.Name, err)
	}
	c.tools = tl.Tools
	return c, nil
}

func (c *stdioChild) readLoop(r io.Reader) {
	defer close(c.done)
	sc := newLineScanner(r)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var resp rpcResponse
		if err := json.Unmarshal(line, &resp); err != nil || len(resp.ID) == 0 {
			continue // notifications / requests from the child are ignored
		}
		var id int64
		if err := json.Unmarshal(resp.ID, &id); err != nil {
			continue
		}
		c.mu.Lock()
		ch := c.pend[id]
		delete(c.pend, id)
		c.mu.Unlock()
		if ch != nil {
			ch <- resp
		}
	}
}

func (c *stdioChild) call(ctx context.Context, method string, params any) (json.RawMessage, *rpcError, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan rpcResponse, 1)
	c.pend[id] = ch
	c.mu.Unlock()
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	if err := c.w.write(req); err != nil {
		return nil, nil, err
	}
	select {
	case resp := <-ch:
		if resp.Error != nil {
			return nil, resp.Error, nil
		}
		b, _ := json.Marshal(resp.Result)
		return b, nil, nil
	case <-c.done:
		return nil, nil, fmt.Errorf("provider %s exited", c.name)
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pend, id)
		c.mu.Unlock()
		return nil, nil, ctx.Err()
	}
}

func (c *stdioChild) close() {
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
}
