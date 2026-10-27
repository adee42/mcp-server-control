// Package mcpserver implements the sc-mcp side: the local list of servers and the MCP
// tools that act on them.
package mcpserver

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/adee42/mcp-server-control/internal/client"
	"github.com/adee42/mcp-server-control/internal/tlsutil"
)

// Server is one entry of servers.yaml.
type Server struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port,omitempty"`
	APIKey      string `yaml:"api_key,omitempty"`
	// APIKeyEnv names an environment variable holding the key, as an alternative to APIKey.
	APIKeyEnv      string `yaml:"api_key_env,omitempty"`
	TLSFingerprint string `yaml:"tls_fingerprint,omitempty"`
	// InsecureSkipVerify disables certificate checks. Only for testing.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`
}

type ServersFile struct {
	Servers []*Server `yaml:"servers"`
	// Problems describes entries that were skipped because they are incomplete or invalid.
	Problems []string `yaml:"-"`
}

// ConfigPath returns $SERVER_CONTROL_CONFIG or <user config dir>/server-control/servers.yaml.
// An unexpanded "${...}" value counts as unset: MCPB hosts leave optional settings the user
// left empty as the literal template.
func ConfigPath() (string, error) {
	if p := os.Getenv("SERVER_CONTROL_CONFIG"); p != "" && !strings.HasPrefix(p, "${") {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "server-control", "servers.yaml"), nil
}

var serverNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// LoadServers reads the servers file; a missing file is an empty list.
func LoadServers(path string) (*ServersFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &ServersFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f ServersFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && len(bytes.TrimSpace(data)) > 0 {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]bool{}
	for i, s := range f.Servers {
		if s == nil || !serverNameRe.MatchString(s.Name) {
			return nil, fmt.Errorf("%s: servers[%d] needs a name of letters, digits, . _ -", path, i)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("%s: duplicate server name %q", path, s.Name)
		}
		seen[s.Name] = true
		if s.Host == "" {
			return nil, fmt.Errorf("%s: server %q has no host", path, s.Name)
		}
		if s.Port == 0 {
			s.Port = 8443
		}
	}
	return &f, nil
}

// Save writes the file with mode 0600, since it contains API keys.
func (f *ServersFile) Save(path string) error {
	data, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (f *ServersFile) Find(name string) (*Server, error) {
	i := slices.IndexFunc(f.Servers, func(s *Server) bool { return s.Name == name })
	if i < 0 {
		names := make([]string, len(f.Servers))
		for i, s := range f.Servers {
			names[i] = s.Name
		}
		err := fmt.Errorf("unknown server %q (configured: %v)", name, names)
		if len(f.Problems) > 0 {
			err = fmt.Errorf("%w; skipped entries: %s", err, strings.Join(f.Problems, "; "))
		}
		return nil, err
	}
	return f.Servers[i], nil
}

// Key returns the API key from the file or the named environment variable.
func (s *Server) Key() (string, error) {
	if s.APIKey != "" {
		return s.APIKey, nil
	}
	if s.APIKeyEnv != "" {
		if v := os.Getenv(s.APIKeyEnv); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("server %q: environment variable %s is not set", s.Name, s.APIKeyEnv)
	}
	return "", fmt.Errorf("server %q has no api_key or api_key_env", s.Name)
}

func (s *Server) Client() (*client.Client, error) {
	key, err := s.Key()
	if err != nil {
		return nil, err
	}
	if s.TLSFingerprint != "" {
		if _, err := tlsutil.NormalizeFingerprint(s.TLSFingerprint); err != nil {
			return nil, fmt.Errorf("server %q: %w", s.Name, err)
		}
	}
	return client.New(client.Options{
		Host:        s.Host,
		Port:        s.Port,
		Key:         key,
		Fingerprint: s.TLSFingerprint,
		Insecure:    s.InsecureSkipVerify,
	})
}
