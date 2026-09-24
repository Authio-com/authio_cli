package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tcast/authio_cli/internal/credentials"
)

// MCP serves a newline-delimited JSON-RPC MCP server on stdio.
// Tools call the project-scoped secret-key API only.
func MCP(args []string) error {
	p, _, err := loadProfile(resolveProfileName(args))
	if err != nil {
		return err
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		resp, reply := handleMCP(p, []byte(line))
		if !reply {
			continue
		}
		if err := writeMCP(os.Stdout, resp); err != nil {
			return err
		}
	}
	if err := in.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

type mcpRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func handleMCP(p *credentials.Profile, raw []byte) (any, bool) {
	var req mcpRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return mcpError(json.RawMessage("null"), -32700, "parse error"), true
	}
	if req.Method == "notifications/initialized" || strings.HasPrefix(req.Method, "notifications/") {
		return nil, false
	}
	switch req.Method {
	case "initialize":
		return mcpResult(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "authio", "version": "0.1.0"},
		}), true
	case "tools/list":
		return mcpResult(req.ID, map[string]any{"tools": mcpTools()}), true
	case "tools/call":
		return mcpResult(req.ID, callMCPTool(p, req.Params)), true
	case "ping":
		return mcpResult(req.ID, map[string]any{}), true
	default:
		if len(req.ID) == 0 {
			return nil, false
		}
		return mcpError(req.ID, -32601, "method not found"), true
	}
}

func mcpTools() []map[string]any {
	obj := func(props map[string]any, required []string) map[string]any {
		schema := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			schema["required"] = required
		}
		return schema
	}
	str := map[string]any{"type": "string"}
	return []map[string]any{
		{"name": "whoami", "description": "Show the project this secret key is pinned to.", "inputSchema": obj(map[string]any{}, nil)},
		{"name": "domains_list", "description": "List custom domains for this project.", "inputSchema": obj(map[string]any{}, nil)},
		{"name": "domains_create", "description": "Create a custom domain and register its certificate when the plan allows.", "inputSchema": obj(map[string]any{"domain": str, "organization_id": str}, []string{"domain"})},
		{"name": "domains_verify", "description": "Check DNS or the Cloudflare certificate for one domain.", "inputSchema": obj(map[string]any{"id": str}, []string{"id"})},
		{"name": "domains_branding", "description": "Update logo, color, name, or tagline on one custom domain.", "inputSchema": obj(map[string]any{"id": str, "display_name": str, "primary_color": str, "logo_url": str, "tagline": str}, []string{"id"})},
		{"name": "redirects_list", "description": "List redirect URIs for this project.", "inputSchema": obj(map[string]any{}, nil)},
		{"name": "redirects_create", "description": "Add a redirect URI. kind defaults to oauth_callback.", "inputSchema": obj(map[string]any{"uri": str, "kind": str}, []string{"uri"})},
	}
}

func callMCPTool(p *credentials.Profile, params json.RawMessage) map[string]any {
	var call struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &call)
	}
	if call.Arguments == nil {
		call.Arguments = map[string]any{}
	}
	if p == nil {
		return mcpText(true, "no credentials")
	}
	switch call.Name {
	case "whoami":
		res, err := apiGet(p, "/v1/projects/me")
		return mcpAPI(res, err, 200)
	case "domains_list":
		res, err := apiGet(p, "/v1/custom-domains")
		return mcpAPI(res, err, 200)
	case "domains_create":
		domain, _ := call.Arguments["domain"].(string)
		if strings.TrimSpace(domain) == "" {
			return mcpText(true, "domain is required")
		}
		body := map[string]any{"domain": domain}
		if org, ok := call.Arguments["organization_id"].(string); ok && org != "" {
			body["organization_id"] = org
		}
		res, err := apiPost(p, "/v1/custom-domains", body)
		return mcpAPI(res, err, 201)
	case "domains_verify":
		id, _ := call.Arguments["id"].(string)
		if id == "" || strings.Contains(id, "/") {
			return mcpText(true, "id is required")
		}
		res, err := apiPost(p, "/v1/custom-domains/"+id+"/verify", map[string]any{})
		return mcpAPI(res, err, 200)
	case "domains_branding":
		id, _ := call.Arguments["id"].(string)
		if id == "" || strings.Contains(id, "/") {
			return mcpText(true, "id is required")
		}
		branding := map[string]any{}
		for _, key := range []string{"display_name", "primary_color", "logo_url", "tagline"} {
			if v, ok := call.Arguments[key].(string); ok && v != "" {
				branding[key] = v
			}
		}
		if len(branding) == 0 {
			return mcpText(true, "pass at least one branding field")
		}
		res, err := apiPatch(p, "/v1/custom-domains/"+id+"/branding", map[string]any{"branding": branding})
		return mcpAPI(res, err, 200)
	case "redirects_list":
		res, err := apiGet(p, "/v1/redirect-uris")
		return mcpAPI(res, err, 200)
	case "redirects_create":
		uri, _ := call.Arguments["uri"].(string)
		if strings.TrimSpace(uri) == "" {
			return mcpText(true, "uri is required")
		}
		kind, _ := call.Arguments["kind"].(string)
		if kind == "" {
			kind = "oauth_callback"
		}
		res, err := apiPost(p, "/v1/redirect-uris", map[string]any{"uri": uri, "kind": kind})
		return mcpAPI(res, err, 201)
	default:
		return mcpText(true, "unknown tool")
	}
}

func mcpAPI(res *apiResult, err error, okStatus int) map[string]any {
	if err != nil {
		return mcpText(true, err.Error())
	}
	if res.status != okStatus && !(okStatus == 201 && res.status == 200) {
		return mcpText(true, fmt.Sprintf("HTTP %d: %s", res.status, strings.TrimSpace(string(res.body))))
	}
	return mcpText(false, string(res.body))
}

func mcpText(isError bool, text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func mcpResult(id json.RawMessage, result any) map[string]any {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result}
}

func mcpError(id json.RawMessage, code int, message string) map[string]any {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error":   map[string]any{"code": code, "message": message},
	}
}

func writeMCP(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}
