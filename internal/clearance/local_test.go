package clearance

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveCwd_ConfinedToRoot(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
			t.Fatal(err)
		}
	}
	rootReal, _ := filepath.EvalSymlinks(root)
	cases := []struct {
		cwd  string
		ok   bool
		want string
	}{
		{"", true, rootReal},
		{"pkg", true, filepath.Join(rootReal, "pkg")},
		{"./pkg/../pkg", true, filepath.Join(rootReal, "pkg")},
		{"..", false, ""},
		{"../" + filepath.Base(outside), false, ""},
		{outside, false, ""},
		{"pkg/../..", false, ""},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			cwd  string
			ok   bool
			want string
		}{"escape", false, ""})
	}
	for _, c := range cases {
		got, err := resolveCwd(root, c.cwd)
		if (err == nil) != c.ok {
			t.Fatalf("cwd %q: ok=%v err=%v", c.cwd, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Fatalf("cwd %q: got %q want %q", c.cwd, got, c.want)
		}
	}
}

func TestRunExec_NoShellCappedAndConfined(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix tools")
	}
	root := t.TempDir()
	ctx := context.Background()

	// argv is passed verbatim — a shell metacharacter is data, not syntax.
	res, err := RunExec(ctx, root, ExecArgs{Command: "printf", Args: []string{"%s", "a;b && c"}})
	if err != nil || res.IsError {
		t.Fatalf("printf failed: %v %+v", err, res)
	}
	out := res.StructuredContent.(map[string]any)
	if out["stdout"] != "a;b && c" || out["exit_code"] != 0 {
		t.Fatalf("unexpected output: %v", out)
	}

	// exit code propagates as isError
	res, _ = RunExec(ctx, root, ExecArgs{Command: "sh", Args: []string{"-c", "exit 3"}})
	if !res.IsError || res.StructuredContent.(map[string]any)["exit_code"] != 3 {
		t.Fatalf("exit code not propagated: %+v", res.StructuredContent)
	}

	// output cap
	res, _ = RunExec(ctx, root, ExecArgs{Command: "sh", Args: []string{"-c", "head -c 2000000 /dev/zero | tr '\\0' x"}})
	o := res.StructuredContent.(map[string]any)
	if len(o["stdout"].(string)) != execMaxOutput || o["truncated"] != true {
		t.Fatalf("output not capped: len=%d truncated=%v", len(o["stdout"].(string)), o["truncated"])
	}

	// timeout
	res, _ = RunExec(ctx, root, ExecArgs{Command: "sleep", Args: []string{"5"}, TimeoutMS: 200})
	if !res.IsError || res.StructuredContent.(map[string]any)["timed_out"] != true {
		t.Fatalf("timeout not reported: %+v", res.StructuredContent)
	}

	// cwd escape refused before anything runs
	res, _ = RunExec(ctx, root, ExecArgs{Command: "pwd", Cwd: ".."})
	if !res.IsError || !strings.Contains(res.Content[0].Text, "escapes") {
		t.Fatalf("cwd escape not refused: %+v", res)
	}

	// environment is scrubbed: a secret in the sidecar env must not reach children
	t.Setenv("AUTHIO_SECRET_MARKER", "leak")
	res, _ = RunExec(ctx, root, ExecArgs{Command: "sh", Args: []string{"-c", "printenv AUTHIO_SECRET_MARKER || echo absent"}})
	if got := res.StructuredContent.(map[string]any)["stdout"]; !strings.Contains(got.(string), "absent") {
		t.Fatalf("env leaked to child: %q", got)
	}
}

func TestExecArgs_CommandLine(t *testing.T) {
	if got := (ExecArgs{Command: "git", Args: []string{"push", "origin", "main"}}).CommandLine(); got != "git push origin main" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadSidecarConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "authio.yaml")
	os.WriteFile(p, []byte(`
version: 1
redirect_uris:
  - uri: https://app.example.com/cb
clearance:
  providers:
    filesystem:
      type: stdio
      command: npx
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
      env: { LOG_LEVEL: warn }
    exec: builtin
`), 0o600)
	cfg, err := LoadSidecarConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers) != 1 || cfg.Providers[0].Name != "filesystem" || cfg.Providers[0].Command != "npx" || cfg.Providers[0].Env["LOG_LEVEL"] != "warn" {
		t.Fatalf("unexpected providers: %+v", cfg.Providers)
	}
	if cfg2, err := LoadSidecarConfig(filepath.Join(dir, "missing.yaml")); err != nil || len(cfg2.Providers) != 0 {
		t.Fatalf("missing file should be empty config: %v %+v", err, cfg2)
	}
	os.WriteFile(p, []byte("clearance:\n  providers:\n    Bad Name:\n      type: stdio\n      command: x\n"), 0o600)
	if _, err := LoadSidecarConfig(p); err == nil {
		t.Fatal("bad provider name accepted")
	}
	os.WriteFile(p, []byte("clearance:\n  providers:\n    remote:\n      type: http\n      url: https://x\n"), 0o600)
	if _, err := LoadSidecarConfig(p); err == nil {
		t.Fatal("http provider type accepted by sidecar")
	}
}
