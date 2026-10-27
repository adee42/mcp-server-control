package server

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adee42/mcp-server-control/internal/api"
)

func readAudit(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var entries []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad audit line %q: %v", sc.Text(), err)
		}
		entries = append(entries, e)
	}
	return entries
}

func TestAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "audit.log")
	a, err := OpenAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	s, _ := newTestServer(t, testConfig(t, ""))
	s.SetAuditLog(a)

	do(t, s, "", "GET", "/v1/health", nil)
	do(t, s, adminKey, "POST", "/v1/exec", api.ExecRequest{Command: "echo audited", Env: map[string]string{"SECRET_TOKEN": "hunter2"}})
	do(t, s, limitedKey, "POST", "/v1/exec", api.ExecRequest{Command: "cat /etc/shadow"})
	do(t, s, "sck_bogus", "GET", "/v1/info", nil)
	do(t, s, adminKey, "GET", "/v1/nope", nil)
	do(t, s, adminKey, "PUT", "/v1/cron/nightly", api.CronJob{Schedule: "@daily", Command: "true"})

	e := readAudit(t, path)
	if len(e) != 5 {
		t.Fatalf("got %d entries (health must not be logged): %v", len(e), e)
	}
	check := func(i int, want map[string]any) {
		t.Helper()
		for k, v := range want {
			if e[i][k] != v {
				t.Errorf("entry %d: %s = %v, want %v (entry: %v)", i, k, e[i][k], v, e[i])
			}
		}
	}
	check(0, map[string]any{"msg": "request", "op": "exec", "key": "admin", "command": "echo audited", "exit_code": 0.0, "status": 200.0})
	if names, _ := e[0]["env_names"].([]any); len(names) != 1 || names[0] != "SECRET_TOKEN" {
		t.Errorf("env_names = %v", e[0]["env_names"])
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "hunter2") {
		t.Error("environment values must not be logged")
	}
	check(1, map[string]any{"op": "exec", "key": "limited", "command": "cat /etc/shadow", "status": 403.0, "level": "WARN"})
	if e[1]["error"] == nil {
		t.Error("refused request has no error")
	}
	check(2, map[string]any{"op": "info", "key": "", "status": 401.0, "error": "invalid API key"})
	check(3, map[string]any{"op": "unknown", "status": 404.0})
	check(4, map[string]any{"op": "cron.set", "cron_name": "nightly", "schedule": "@daily", "command": "true", "user": "root"})

	// Reopen after the file was moved away (logrotate) writes to a fresh file.
	if runtime.GOOS == "windows" {
		return // Windows cannot rename a file that is open
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := a.Reopen(path); err != nil {
		t.Fatal(err)
	}
	do(t, s, adminKey, "GET", "/v1/info", nil)
	if e := readAudit(t, path); len(e) != 1 || e[0]["op"] != "info" {
		t.Errorf("after reopen: %v", e)
	}
}
