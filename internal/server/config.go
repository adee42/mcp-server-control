package server

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/adee42/mcp-server-control/internal/api"
)

// DefaultConfigPath is where sc-server looks for its config unless told otherwise.
const DefaultConfigPath = "/etc/server-control/config.yaml"

// DefaultAuditLog is where operations are logged unless audit_log says otherwise.
const DefaultAuditLog = "/var/log/server-control/audit.log"

type Config struct {
	Listen  string    `yaml:"listen"`
	TLS     TLSConfig `yaml:"tls"`
	Limits  Limits    `yaml:"limits"`
	CronDir string    `yaml:"cron_dir"`
	// AuditLog is the JSON-lines file every operation is appended to; "off" disables it.
	AuditLog string `yaml:"audit_log"`
	Keys     []*Key `yaml:"keys"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type Limits struct {
	DefaultTimeout Duration `yaml:"default_timeout"`
	MaxTimeout     Duration `yaml:"max_timeout"`
	MaxOutput      ByteSize `yaml:"max_output"`
	MaxFile        ByteSize `yaml:"max_file"`
	JobRetention   Duration `yaml:"job_retention"`
	MaxJobs        int      `yaml:"max_jobs"`
}

type Key struct {
	Name      string        `yaml:"name"`
	Hash      string        `yaml:"hash"`
	Scopes    []string      `yaml:"scopes"`
	Commands  CommandRules  `yaml:"commands,omitempty"`
	Paths     PathRules     `yaml:"paths,omitempty"`
	Services  ServiceRules  `yaml:"services,omitempty"`
	IPAllow   []string      `yaml:"ip_allow,omitempty"`
	Expires   *time.Time    `yaml:"expires,omitempty"`
	RateLimit RateLimitRule `yaml:"rate_limit,omitempty"`
	Disabled  bool          `yaml:"disabled,omitempty"`

	// Compiled forms, filled by Config.validate.
	allow    []*regexp.Regexp
	deny     []*regexp.Regexp
	prefixes []netip.Prefix
}

type CommandRules struct {
	Allow []string `yaml:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty"`
}

type PathRules struct {
	Read  []string `yaml:"read,omitempty"`
	Write []string `yaml:"write,omitempty"`
}

type ServiceRules struct {
	Allow []string `yaml:"allow,omitempty"`
}

type RateLimitRule struct {
	PerMinute int `yaml:"per_minute,omitempty"`
	Burst     int `yaml:"burst,omitempty"`
}

// Duration is a time.Duration that reads and writes as "60s", "1h" etc.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// ByteSize reads plain integers or values with a KiB/MiB/GiB (or K/M/G) suffix.
type ByteSize int64

var byteSizeRe = regexp.MustCompile(`^(\d+)\s*([KMG]I?B?|B)?$`)

func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	m := byteSizeRe.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(n.Value)))
	if m == nil {
		return fmt.Errorf("line %d: invalid size %q", n.Line, n.Value)
	}
	var v int64
	fmt.Sscan(m[1], &v)
	switch strings.TrimSuffix(strings.TrimSuffix(m[2], "B"), "I") {
	case "K":
		v <<= 10
	case "M":
		v <<= 20
	case "G":
		v <<= 30
	}
	*b = ByteSize(v)
	return nil
}

func (b ByteSize) MarshalYAML() (any, error) {
	switch {
	case b != 0 && b%(1<<30) == 0:
		return fmt.Sprintf("%dGiB", b>>30), nil
	case b != 0 && b%(1<<20) == 0:
		return fmt.Sprintf("%dMiB", b>>20), nil
	case b != 0 && b%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", b>>10), nil
	}
	return int64(b), nil
}

// LoadConfig reads, defaults and validates a config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.TLS.Cert == "" {
		c.TLS.Cert = "/etc/server-control/tls/cert.pem"
	}
	if c.TLS.Key == "" {
		c.TLS.Key = "/etc/server-control/tls/key.pem"
	}
	if c.CronDir == "" {
		c.CronDir = "/etc/cron.d"
	}
	if c.AuditLog == "" {
		c.AuditLog = DefaultAuditLog
	}
	l := &c.Limits
	if l.DefaultTimeout == 0 {
		l.DefaultTimeout = Duration(60 * time.Second)
	}
	if l.MaxTimeout == 0 {
		l.MaxTimeout = Duration(time.Hour)
	}
	if l.MaxOutput == 0 {
		l.MaxOutput = 1 << 20
	}
	if l.MaxFile == 0 {
		l.MaxFile = 50 << 20
	}
	if l.JobRetention == 0 {
		l.JobRetention = Duration(24 * time.Hour)
	}
	if l.MaxJobs == 0 {
		l.MaxJobs = 100
	}
}

var keyNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (c *Config) validate() error {
	if c.AuditLog != "off" && !isAbs(c.AuditLog) {
		return fmt.Errorf("audit_log must be an absolute path or \"off\", got %q", c.AuditLog)
	}
	seenName := map[string]bool{}
	seenHash := map[string]bool{}
	for i, k := range c.Keys {
		if k == nil {
			return fmt.Errorf("keys[%d]: empty entry", i)
		}
		where := fmt.Sprintf("key %q", k.Name)
		if !keyNameRe.MatchString(k.Name) {
			return fmt.Errorf("keys[%d]: invalid name %q (use letters, digits, . _ -)", i, k.Name)
		}
		if seenName[k.Name] {
			return fmt.Errorf("%s: duplicate name", where)
		}
		seenName[k.Name] = true
		if !strings.HasPrefix(k.Hash, hashPrefix) || len(k.Hash) != len(hashPrefix)+64 {
			return fmt.Errorf("%s: hash must be %q followed by 64 hex chars (use `sc-server key add`)", where, hashPrefix)
		}
		if seenHash[k.Hash] {
			return fmt.Errorf("%s: duplicate hash", where)
		}
		seenHash[k.Hash] = true
		for _, s := range k.Scopes {
			if !slices.Contains(api.AllScopes, s) {
				return fmt.Errorf("%s: unknown scope %q (valid: %s)", where, s, strings.Join(api.AllScopes, ", "))
			}
		}
		k.allow, k.deny, k.prefixes = nil, nil, nil
		for _, p := range k.Commands.Allow {
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("%s: commands.allow %q: %w", where, p, err)
			}
			k.allow = append(k.allow, re)
		}
		for _, p := range k.Commands.Deny {
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("%s: commands.deny %q: %w", where, p, err)
			}
			k.deny = append(k.deny, re)
		}
		for _, p := range append(slices.Clone(k.Paths.Read), k.Paths.Write...) {
			if !isAbs(p) {
				return fmt.Errorf("%s: path %q must be absolute", where, p)
			}
		}
		for _, g := range k.Services.Allow {
			if _, err := filepath.Match(g, ""); err != nil {
				return fmt.Errorf("%s: services.allow %q: %w", where, g, err)
			}
		}
		for _, s := range k.IPAllow {
			p, err := parsePrefix(s)
			if err != nil {
				return fmt.Errorf("%s: ip_allow %q: %w", where, s, err)
			}
			k.prefixes = append(k.prefixes, p)
		}
		if k.RateLimit.PerMinute < 0 || k.RateLimit.Burst < 0 {
			return fmt.Errorf("%s: rate_limit values must be >= 0", where)
		}
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// isAbs treats only slash-rooted paths as absolute, since the server targets Linux.
func isAbs(p string) bool { return strings.HasPrefix(p, "/") || filepath.IsAbs(p) }

func (k *Key) HasScope(s string) bool { return slices.Contains(k.Scopes, s) }

// AuditLogPath returns the audit log file, or "" when auditing is off.
func (c *Config) AuditLogPath() string {
	if c.AuditLog == "off" {
		return ""
	}
	return c.AuditLog
}
