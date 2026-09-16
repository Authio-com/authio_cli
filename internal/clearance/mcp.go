// Package clearance implements `authio clearance`: a local MCP stdio server
// that fronts the hosted Clearance data-plane and wraps local tools (shell
// commands, stdio MCP servers) so every call — hosted or local — is judged
// by the same central policy and lands in the same audit trail.
package clearance

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// JSON-RPC 2.0 framing shared by the stdio server and the stdio child
// clients. MCP over stdio is newline-delimited JSON, one message per line.

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternal       = -32603
)

// Tool is an MCP tool descriptor.
type Tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolResult is the tools/call result shape. Verdict metadata rides in
// Meta so a client can act on approval ids programmatically.
type ToolResult struct {
	Content           []ToolContent  `json:"content"`
	StructuredContent any            `json:"structuredContent,omitempty"`
	IsError           bool           `json:"isError,omitempty"`
	Meta              map[string]any `json:"_meta,omitempty"`
}

func textResult(text string, isErr bool) *ToolResult {
	return &ToolResult{Content: []ToolContent{{Type: "text", Text: text}}, IsError: isErr}
}

func jsonResult(v any) *ToolResult {
	b, _ := json.Marshal(v)
	return &ToolResult{Content: []ToolContent{{Type: "text", Text: string(b)}}, StructuredContent: v}
}

// lineWriter serialises JSON-RPC messages onto a stream, one per line,
// safely from multiple goroutines.
type lineWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lineWriter) write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = fmt.Fprintf(l.w, "%s\n", b)
	return err
}

// maxLine bounds one stdio frame; MCP messages are small, tool outputs
// are capped separately.
const maxLine = 8 << 20

func newLineScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	return sc
}
