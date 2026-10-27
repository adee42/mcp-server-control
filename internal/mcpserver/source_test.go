package mcpserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParseAddress(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		bad  bool
	}{
		{in: "web1.example.com", host: "web1.example.com", port: 8443},
		{in: "10.0.0.5:9443", host: "10.0.0.5", port: 9443},
		{in: "https://web1:8443/", host: "web1", port: 8443},
		{in: "::1", host: "::1", port: 8443},
		{in: "[fd00::5]:8444", host: "fd00::5", port: 8444},
		{in: "[fd00::5]", host: "fd00::5", port: 8443},
		{in: "web1:http", bad: true},
		{in: "web1:70000", bad: true},
		{in: "web 1", bad: true},
	}
	for _, c := range cases {
		host, port, err := parseAddress(c.in)
		if c.bad != (err != nil) || (!c.bad && (host != c.host || port != c.port)) {
			t.Errorf("parseAddress(%q) = %q, %d, %v", c.in, host, port, err)
		}
	}
}

func TestLoadEnvServers(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("ab:", 31) + "ab"
	env := map[string]string{
		"SC_SERVER_1_NAME": "web1", "SC_SERVER_1_ADDRESS": "10.0.0.5", "SC_SERVER_1_KEY": "sck_one", "SC_SERVER_1_FINGERPRINT": fp,
		// Slot 2 left empty in the UI: the host passes the unexpanded templates.
		"SC_SERVER_2_NAME": "${user_config.server2_name}", "SC_SERVER_2_ADDRESS": "${user_config.server2_address}",
		"SC_SERVER_2_KEY": "${user_config.server2_api_key}", "SC_SERVER_2_FINGERPRINT": "${user_config.server2_fingerprint}",
		// Slot 3 without a name falls back to the host.
		"SC_SERVER_3_ADDRESS": " db.internal:9000 ", "SC_SERVER_3_KEY": "sck_three",
		// Broken slots are reported, not fatal.
		"SC_SERVER_4_NAME": "nokey", "SC_SERVER_4_ADDRESS": "10.0.0.7",
		"SC_SERVER_5_NAME": "web1", "SC_SERVER_5_ADDRESS": "10.0.0.8", "SC_SERVER_5_KEY": "sck_dup",
		"SC_SERVER_6_NAME": "badpin", "SC_SERVER_6_ADDRESS": "10.0.0.9", "SC_SERVER_6_KEY": "sck_x", "SC_SERVER_6_FINGERPRINT": "nope",
		"SC_SERVER_7_NAME": "has space", "SC_SERVER_7_ADDRESS": "10.0.0.10", "SC_SERVER_7_KEY": "sck_x",
		"SC_SERVER_8_KEY": "sck_noaddr",
		// Slots beyond the UI's five still work when set by hand.
		"SC_SERVER_12_NAME": "extra", "SC_SERVER_12_ADDRESS": "extra.example.com", "SC_SERVER_12_KEY": "sck_extra",
	}
	f := LoadEnvServers(func(k string) string { return env[k] })

	var got []string
	for _, s := range f.Servers {
		got = append(got, fmt.Sprintf("%s=%s:%d", s.Name, s.Host, s.Port))
	}
	want := []string{"web1=10.0.0.5:8443", "db.internal=db.internal:9000", "extra=extra.example.com:8443"}
	if !slices.Equal(got, want) {
		t.Errorf("servers = %v, want %v", got, want)
	}
	if f.Servers[0].TLSFingerprint != strings.ToUpper(fp) || f.Servers[0].APIKey != "sck_one" {
		t.Errorf("server 1 = %+v", f.Servers[0])
	}
	problems := strings.Join(f.Problems, "\n")
	for _, want := range []string{
		"server 4 (nokey): API key is empty",
		`server 5 (web1): name "web1" is already used by server 1`,
		"server 6 (badpin): fingerprint",
		"server 7 (has space): name may only",
		"server 8: address is empty",
	} {
		if !strings.Contains(problems, want) {
			t.Errorf("problems lack %q:\n%s", want, problems)
		}
	}
	if len(f.Problems) != 5 {
		t.Errorf("got %d problems:\n%s", len(f.Problems), problems)
	}
	if _, err := f.Find("nokey"); err == nil || !strings.Contains(err.Error(), "API key is empty") {
		t.Errorf("Find of a skipped server should explain why: %v", err)
	}
}

// Every env var the manifest passes must refer to an existing setting, and every slot it
// exposes must be one sc-mcp reads.
func TestMCPBManifestServerSettings(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "mcpb", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Server struct {
			MCPConfig struct {
				Args              []string          `json:"args"`
				Env               map[string]string `json:"env"`
				PlatformOverrides map[string]struct {
					Args []string `json:"args"`
				} `json:"platform_overrides"`
			} `json:"mcp_config"`
		} `json:"server"`
		UserConfig map[string]struct {
			Type      string `json:"type"`
			Required  bool   `json:"required"`
			Sensitive bool   `json:"sensitive"`
		} `json:"user_config"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	cfg := m.Server.MCPConfig
	if !slices.Contains(cfg.Args, "-from-env") || !slices.Contains(cfg.PlatformOverrides["win32"].Args, "-from-env") {
		t.Errorf("serve must get -from-env on every platform: %v / %v", cfg.Args, cfg.PlatformOverrides["win32"].Args)
	}
	envRe := regexp.MustCompile(`^SC_SERVER_(\d+)_(NAME|ADDRESS|KEY|FINGERPRINT)$`)
	tmplRe := regexp.MustCompile(`^\$\{user_config\.([a-z0-9_]+)\}$`)
	used := map[string]bool{}
	for name, val := range cfg.Env {
		if name == "SC_SERVERS_FILE" {
			if s := m.UserConfig["servers_file"]; val != "${user_config.servers_file}" || s.Type != "file" || s.Sensitive {
				t.Errorf("SC_SERVERS_FILE = %q must come from a non-secret file setting servers_file (got %+v)", val, s)
			}
			used["servers_file"] = true
			continue
		}
		mm := envRe.FindStringSubmatch(name)
		if mm == nil {
			t.Errorf("unexpected env var %s", name)
			continue
		}
		if n, _ := strconv.Atoi(mm[1]); n < 1 || n > EnvSlots {
			t.Errorf("%s is outside the %d slots sc-mcp reads", name, EnvSlots)
		}
		tm := tmplRe.FindStringSubmatch(val)
		if tm == nil {
			t.Errorf("%s = %q is not a user_config template", name, val)
			continue
		}
		setting, ok := m.UserConfig[tm[1]]
		if !ok {
			t.Errorf("%s refers to missing setting %s", name, tm[1])
		}
		if (mm[2] == "KEY") != setting.Sensitive {
			t.Errorf("%s: only API keys should be sensitive (sensitive=%v)", tm[1], setting.Sensitive)
		}
		used[tm[1]] = true
	}
	for name := range m.UserConfig {
		if !used[name] {
			t.Errorf("setting %s is not passed to the server", name)
		}
	}
}

func TestLoadEnvServersWithFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "servers.yaml")
	os.WriteFile(good, []byte(`servers:
  - name: db1
    host: 10.0.1.1
    api_key: sck_db1
  - name: web1
    host: 10.0.1.2
    api_key: sck_clash
  - name: db2
    host: 10.0.1.3
    port: 9443
    api_key_env: DB2_KEY
`), 0o600)
	broken := filepath.Join(dir, "broken.yaml")
	os.WriteFile(broken, []byte("servers:\n  - name: x\n   host: bad-indent\n"), 0o600)

	env := map[string]string{
		"SC_SERVER_1_NAME": "web1", "SC_SERVER_1_ADDRESS": "10.0.0.5", "SC_SERVER_1_KEY": "sck_one",
	}
	load := func(file string) *ServersFile {
		env["SC_SERVERS_FILE"] = file
		return LoadEnvServers(func(k string) string { return env[k] })
	}
	names := func(f *ServersFile) []string {
		var n []string
		for _, s := range f.Servers {
			n = append(n, s.Name)
		}
		return n
	}

	f := load(good)
	if got := names(f); !slices.Equal(got, []string{"web1", "db1", "db2"}) {
		t.Errorf("servers = %v", got)
	}
	if s, _ := f.Find("db2"); s == nil || s.Port != 9443 || s.APIKeyEnv != "DB2_KEY" {
		t.Errorf("db2 = %+v", s)
	}
	if s, _ := f.Find("web1"); s == nil || s.APIKey != "sck_one" {
		t.Errorf("the slot must win over the file for web1: %+v", s)
	}
	if len(f.Problems) != 1 || !strings.Contains(f.Problems[0], `name "web1" is already used by server 1`) {
		t.Errorf("problems = %v", f.Problems)
	}

	// Edits to the file show up on the next load without restarting.
	os.WriteFile(good, []byte("servers:\n  - name: db9\n    host: 10.0.1.9\n    api_key: sck_9\n"), 0o600)
	if got := names(load(good)); !slices.Equal(got, []string{"web1", "db9"}) {
		t.Errorf("after edit: %v", got)
	}

	// A missing or broken file is reported, and the slots keep working.
	for _, file := range []string{filepath.Join(dir, "nope.yaml"), broken} {
		f := load(file)
		if got := names(f); !slices.Equal(got, []string{"web1"}) || len(f.Problems) != 1 || !strings.Contains(f.Problems[0], "servers file "+file) {
			t.Errorf("%s: servers %v, problems %v", file, got, f.Problems)
		}
	}

	// Left empty in the settings: the unexpanded template means no file.
	if f := load("${user_config.servers_file}"); len(f.Problems) != 0 || len(f.Servers) != 1 {
		t.Errorf("unset file: %v %v", names(f), f.Problems)
	}
}
