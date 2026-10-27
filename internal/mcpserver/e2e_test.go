package mcpserver

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adee42/mcp-server-control/internal/server"
	"github.com/adee42/mcp-server-control/internal/tlsutil"
)

const (
	adminKey   = "sck_admin0000000000000000000000000000000000000"
	limitedKey = "sck_limited00000000000000000000000000000000000"
)

// startBackend runs a real sc-server handler over TLS and writes a servers file for it.
func startBackend(t *testing.T) (serversPath, fingerprint string, root string) {
	t.Helper()
	root = t.TempDir()
	cfg, err := server.ParseConfig([]byte(fmt.Sprintf(`
keys:
  - name: admin
    hash: %s
    scopes: [info, exec, jobs, files, cron]
    paths: { write: [%q] }
  - name: limited
    hash: %s
    scopes: [info, exec]
    commands: { allow: ["^echo "] }
`, server.HashKey(adminKey), root, server.HashKey(limitedKey))))
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(cfg, nil, nil)
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })

	fingerprint = tlsutil.Fingerprint(ts.Certificate().Raw)
	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())
	f := &ServersFile{Servers: []*Server{
		{Name: "admin", Host: u.Hostname(), Port: port, APIKey: adminKey, TLSFingerprint: fingerprint},
		{Name: "limited", Host: u.Hostname(), Port: port, APIKey: limitedKey, TLSFingerprint: fingerprint},
		{Name: "wrongpin", Host: u.Hostname(), Port: port, APIKey: adminKey, TLSFingerprint: "SHA256:" + strings.Repeat("00:", 31) + "00"},
	}}
	serversPath = filepath.Join(t.TempDir(), "servers.yaml")
	if err := f.Save(serversPath); err != nil {
		t.Fatal(err)
	}
	return serversPath, fingerprint, root
}

func connect(t *testing.T, serversPath string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := NewServer(FileSource(serversPath)).Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func TestEndToEnd(t *testing.T) {
	serversPath, _, root := startBackend(t)
	cs := connect(t, serversPath)

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 18 {
		t.Errorf("got %d tools", len(tools.Tools))
	}
	for _, tool := range tools.Tools {
		if tool.Name == "run_command" {
			schema := fmt.Sprint(tool.InputSchema)
			if !strings.Contains(schema, "server") || !strings.Contains(schema, "command") {
				t.Errorf("run_command schema lacks fields: %s", schema)
			}
		}
	}

	if out, isErr := call(t, cs, "list_servers", nil); isErr || !strings.Contains(out, `"limited"`) {
		t.Errorf("list_servers: %s", out)
	}
	if out, isErr := call(t, cs, "server_info", map[string]any{"server": "admin"}); isErr || !strings.Contains(out, `"key_name": "admin"`) {
		t.Errorf("server_info: %s", out)
	}
	if out, isErr := call(t, cs, "run_command", map[string]any{"server": "limited", "command": "echo hello mcp"}); isErr || !strings.Contains(out, "hello mcp") || !strings.Contains(out, "exit_code: 0") {
		t.Errorf("run_command: %s", out)
	}
	if out, isErr := call(t, cs, "run_command", map[string]any{"server": "limited", "command": "whoami"}); !isErr || !strings.Contains(out, "allowlist") {
		t.Errorf("disallowed command: %v %s", isErr, out)
	}
	if out, isErr := call(t, cs, "server_info", map[string]any{"server": "wrongpin"}); !isErr || !strings.Contains(out, "fingerprint mismatch") {
		t.Errorf("wrong pin: %v %s", isErr, out)
	}
	if out, isErr := call(t, cs, "server_info", map[string]any{"server": "nope"}); !isErr || !strings.Contains(out, "unknown server") {
		t.Errorf("unknown server: %v %s", isErr, out)
	}

	target := filepath.Join(root, "dir", "hello.txt")
	if out, isErr := call(t, cs, "write_file", map[string]any{"server": "admin", "path": target, "content": "hi there\n", "mkdir_all": true}); isErr {
		t.Errorf("write_file: %s", out)
	}
	if out, isErr := call(t, cs, "read_file", map[string]any{"server": "admin", "path": target}); isErr || !strings.Contains(out, "hi there") {
		t.Errorf("read_file: %s", out)
	}
	local := filepath.Join(t.TempDir(), "copy.txt")
	if out, isErr := call(t, cs, "download_file", map[string]any{"server": "admin", "path": target, "local_path": local}); isErr {
		t.Errorf("download_file: %s", out)
	}
	if b, _ := os.ReadFile(local); string(b) != "hi there\n" {
		t.Errorf("downloaded %q", b)
	}
	if out, isErr := call(t, cs, "list_dir", map[string]any{"server": "admin", "path": filepath.Dir(target)}); isErr || !strings.Contains(out, "hello.txt") {
		t.Errorf("list_dir: %s", out)
	}

	out, isErr := call(t, cs, "start_job", map[string]any{"server": "admin", "command": "echo from-job"})
	if isErr {
		t.Fatalf("start_job: %s", out)
	}
	id := out[strings.Index(out, `"id": "`)+7:]
	id = id[:strings.Index(id, `"`)]
	if out, isErr := call(t, cs, "job_status", map[string]any{"server": "admin", "job_id": id, "wait_seconds": 10}); isErr || !strings.Contains(out, "from-job") || !strings.Contains(out, "exited") {
		t.Errorf("job_status: %s", out)
	}
	if out, isErr := call(t, cs, "list_services", map[string]any{"server": "admin"}); !isErr || !strings.Contains(out, "lacks scope") {
		t.Errorf("services without scope: %s", out)
	}
}
