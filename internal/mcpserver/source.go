package mcpserver

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/adee42/mcp-server-control/internal/tlsutil"
)

// Source is where the MCP server gets its server list from. Load runs on every tool call,
// so changes apply without a restart.
type Source struct {
	Load func() (*ServersFile, error)
	// AddHint tells the user how to add servers; shown when none are configured.
	AddHint string
}

// FileSource reads a servers.yaml file (the Claude Code plugin and the sc-mcp CLI).
func FileSource(path string) Source {
	return Source{
		Load:    func() (*ServersFile, error) { return LoadServers(path) },
		AddHint: "Add one with: sc-mcp add -name NAME -host HOST -key KEY -fingerprint FP (config: " + path + ")",
	}
}

// EnvSlots is how many SC_SERVER_<n>_* slots EnvSource reads. The MCPB manifest exposes
// the first 5 in the Claude Desktop settings; extra slots can be set by hand.
const EnvSlots = 20

// EnvSource reads servers from the environment, which is how Claude Desktop passes the
// extension settings: SC_SERVER_<n>_NAME, _ADDRESS, _KEY and _FINGERPRINT for n = 1..EnvSlots,
// plus SC_SERVERS_FILE, a servers.yaml for setups with more servers than slots.
func EnvSource() Source {
	return Source{
		Load:    func() (*ServersFile, error) { return LoadEnvServers(os.Getenv), nil },
		AddHint: "Enter servers in Claude Desktop under Settings → Extensions → Server Control → Configure, or choose a servers.yaml there as Servers file.",
	}
}

// LoadEnvServers builds the server list from the SC_SERVER_<n>_* slots, then appends the
// servers in SC_SERVERS_FILE (re-read on every call, so edits apply without a restart).
// Empty slots are ignored; incomplete or invalid entries, a missing or unreadable file and
// duplicate names are reported in Problems instead of failing the rest.
func LoadEnvServers(getenv func(string) string) *ServersFile {
	f := &ServersFile{}
	seen := map[string]string{} // server name -> where it was defined
	for n := 1; n <= EnvSlots; n++ {
		get := func(field string) string { return envValue(getenv, fmt.Sprintf("SC_SERVER_%d_%s", n, field)) }
		name, addr, key, fp := get("NAME"), get("ADDRESS"), get("KEY"), get("FINGERPRINT")
		if name == "" && addr == "" && key == "" && fp == "" {
			continue
		}
		problem := func(msg string) {
			label := fmt.Sprintf("server %d", n)
			if name != "" {
				label += fmt.Sprintf(" (%s)", name)
			}
			f.Problems = append(f.Problems, label+": "+msg)
		}
		if addr == "" {
			problem("address is empty")
			continue
		}
		host, port, err := parseAddress(addr)
		if err != nil {
			problem(err.Error())
			continue
		}
		if name == "" {
			name = host
		}
		if !serverNameRe.MatchString(name) {
			problem("name may only contain letters, digits, . _ -")
			continue
		}
		if prev, dup := seen[name]; dup {
			problem(fmt.Sprintf("name %q is already used by %s", name, prev))
			continue
		}
		if key == "" {
			problem("API key is empty")
			continue
		}
		if fp != "" {
			if fp, err = tlsutil.NormalizeFingerprint(fp); err != nil {
				problem(err.Error())
				continue
			}
		}
		seen[name] = fmt.Sprintf("server %d", n)
		f.Servers = append(f.Servers, &Server{Name: name, Host: host, Port: port, APIKey: key, TLSFingerprint: fp})
	}
	if path := envValue(getenv, "SC_SERVERS_FILE"); path != "" {
		addFileServers(f, path, seen)
	}
	return f
}

// addFileServers appends the servers of a servers.yaml to f, skipping names already taken.
func addFileServers(f *ServersFile, path string, seen map[string]string) {
	problem := func(msg string) { f.Problems = append(f.Problems, "servers file "+path+": "+msg) }
	if _, err := os.Stat(path); err != nil {
		// LoadServers treats a missing file as empty; a configured one should exist.
		problem(err.Error())
		return
	}
	file, err := LoadServers(path)
	if err != nil {
		problem(err.Error())
		return
	}
	for _, s := range file.Servers {
		if prev, dup := seen[s.Name]; dup {
			problem(fmt.Sprintf("name %q is already used by %s", s.Name, prev))
			continue
		}
		seen[s.Name] = "the servers file"
		f.Servers = append(f.Servers, s)
	}
}

// envValue returns a trimmed environment value. Hosts pass optional settings the user left
// empty as the literal "${user_config.…}" template, which counts as empty.
func envValue(getenv func(string) string, name string) string {
	v := strings.TrimSpace(getenv(name))
	if strings.HasPrefix(v, "${") {
		return ""
	}
	return v
}

// parseAddress accepts host, host:port, [v6]:port, a bare IPv6 address, or any of these
// with an https:// prefix. The port defaults to 8443.
func parseAddress(s string) (string, int, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://"), "/")
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), 8443, nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		host, portStr = strings.Trim(s, "[]"), "8443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in address %q", s)
	}
	if host == "" || strings.ContainsAny(host, " /") {
		return "", 0, fmt.Errorf("invalid address %q (use host or host:port)", s)
	}
	return host, port, nil
}
