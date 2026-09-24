package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPInitializeAndList(t *testing.T) {
	initResp, reply := handleMCP(nil, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if !reply {
		t.Fatal("initialize should reply")
	}
	raw, err := json.Marshal(initResp)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "2024-11-05") || !strings.Contains(text, `"name":"authio"`) {
		t.Fatalf("unexpected initialize: %s", text)
	}

	listResp, reply := handleMCP(nil, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if !reply {
		t.Fatal("tools/list should reply")
	}
	listRaw, _ := json.Marshal(listResp)
	listText := string(listRaw)
	for _, name := range []string{"whoami", "domains_create", "domains_verify", "redirects_create", "domains_branding"} {
		if !strings.Contains(listText, name) {
			t.Fatalf("tools/list missing %s: %s", name, listText)
		}
	}

	_, reply = handleMCP(nil, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if reply {
		t.Fatal("notifications must not get a response")
	}
}
