// Command sc-server is the remote agent of server-control: an HTTPS API that runs
// commands, jobs, file transfers, service actions and cron jobs for authorized API keys.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/adee42/mcp-server-control/internal/api"
	"github.com/adee42/mcp-server-control/internal/server"
	"github.com/adee42/mcp-server-control/internal/tlsutil"
)

const usage = `sc-server - server-control remote agent

Usage:
  sc-server serve       [-config PATH]
  sc-server key add     -name NAME -scopes LIST [policy flags]   create a key (printed once)
  sc-server key rotate  -name NAME                               replace a key's secret, keep its policy
  sc-server key list
  sc-server key revoke  -name NAME
  sc-server cert gen    [-hosts h1,h2] [-force]                  create a self-signed certificate
  sc-server fingerprint                                          print the certificate fingerprint

Every command accepts -config (default %s, or $SC_SERVER_CONFIG).
Scopes: %s, or "all".
Send SIGHUP to a running server to reload keys and limits.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, server.DefaultConfigPath, strings.Join(api.AllScopes, ", "))
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "serve":
		err = cmdServe(args)
	case "key":
		if len(args) == 0 {
			err = errors.New("usage: sc-server key add|rotate|list|revoke")
			break
		}
		switch args[0] {
		case "add":
			err = cmdKeyAdd(args[1:])
		case "rotate":
			err = cmdKeyRotate(args[1:])
		case "list":
			err = cmdKeyList(args[1:])
		case "revoke":
			err = cmdKeyRevoke(args[1:])
		default:
			err = fmt.Errorf("unknown key command %q", args[0])
		}
	case "cert":
		if len(args) == 0 || args[0] != "gen" {
			err = errors.New("usage: sc-server cert gen [-hosts h1,h2] [-force]")
			break
		}
		err = cmdCertGen(args[1:])
	case "fingerprint":
		err = cmdFingerprint(args)
	case "version", "-version", "--version":
		fmt.Println(server.Version)
	case "help", "-h", "-help", "--help":
		fmt.Printf(usage, server.DefaultConfigPath, strings.Join(api.AllScopes, ", "))
	default:
		err = fmt.Errorf("unknown command %q (run sc-server help)", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	def := server.DefaultConfigPath
	if env := os.Getenv("SC_SERVER_CONFIG"); env != "" {
		def = env
	}
	return fs, fs.String("config", def, "config file")
}

// loadConfig reads the config; a missing file yields the defaults so `cert gen` and
// `key add` work on a fresh install.
func loadConfig(path string) (*server.Config, error) {
	cfg, err := server.LoadConfig(path)
	if errors.Is(err, fs.ErrNotExist) {
		return server.ParseConfig(nil)
	}
	return cfg, err
}

func cmdServe(args []string) error {
	fs, cfgPath := newFlags("serve")
	fs.Parse(args)
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if len(cfg.Keys) == 0 {
		log.Warn("no API keys configured; every request except /v1/health will be rejected", "config", *cfgPath)
	}
	if _, err := os.Stat(cfg.TLS.Cert); errors.Is(err, os.ErrNotExist) {
		if err := tlsutil.GenerateSelfSigned(cfg.TLS.Cert, cfg.TLS.Key, tlsutil.DefaultHosts()); err != nil {
			return fmt.Errorf("generate certificate: %w", err)
		}
		log.Info("generated self-signed certificate", "cert", cfg.TLS.Cert)
	}
	fp, err := tlsutil.FileFingerprint(cfg.TLS.Cert)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	audit, err := server.OpenAuditLog(cfg.AuditLogPath())
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer audit.Close()

	srv := server.New(cfg, log, nil)
	srv.SetAuditLog(audit)
	defer srv.Close()
	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigs {
			if sig == syscall.SIGHUP {
				next, err := server.LoadConfig(*cfgPath)
				if err != nil {
					log.Error("reload failed; keeping current config", "error", err)
					continue
				}
				// Reopening also picks up a file moved away by logrotate.
				if err := audit.Reopen(next.AuditLogPath()); err != nil {
					log.Error("reopen audit log failed; still writing to the old file", "error", err)
				}
				srv.Reload(next)
				srv.Event("config_reloaded", slog.Int("keys", len(next.Keys)))
				continue
			}
			srv.Event("server_stop", slog.String("signal", sig.String()))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			hs.Shutdown(ctx)
			cancel()
			return
		}
	}()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	srv.Event("server_start", slog.String("addr", cfg.Listen), slog.String("version", server.Version),
		slog.Int("keys", len(cfg.Keys)), slog.String("fingerprint", fp), slog.String("audit_log", cfg.AuditLog))
	if err := hs.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// listFlag collects a repeatable flag; comma-separated values are split too.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func splitComma(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func cmdKeyAdd(args []string) error {
	fs, cfgPath := newFlags("key add")
	name := fs.String("name", "", "key name (required)")
	scopes := fs.String("scopes", "", "comma-separated scopes, or \"all\" (required)")
	var allow, deny, read, write, services, ips listFlag
	fs.Var(&allow, "allow", "command allow regex (repeatable); set → commands run without a shell")
	fs.Var(&deny, "deny", "command deny regex (repeatable)")
	fs.Var(&read, "read-path", "readable path root (repeatable)")
	fs.Var(&write, "write-path", "writable (and readable) path root (repeatable)")
	fs.Var(&services, "service", "service unit glob (repeatable, e.g. nginx, app-*, *)")
	fs.Var(&ips, "ip", "allowed source IP or CIDR (repeatable/comma-separated)")
	expires := fs.String("expires", "", "expiry as RFC 3339 time, date (2027-01-31) or duration (90d, 12h)")
	perMinute := fs.Int("rate", 0, "requests per minute (0 = unlimited)")
	burst := fs.Int("burst", 0, "rate limit burst (default min(rate, 10))")
	fs.Parse(args)
	if *name == "" || *scopes == "" {
		return errors.New("-name and -scopes are required")
	}
	k := &server.Key{
		Name:      *name,
		Commands:  server.CommandRules{Allow: allow, Deny: deny},
		Paths:     server.PathRules{Read: read, Write: write},
		Services:  server.ServiceRules{Allow: splitComma(services)},
		IPAllow:   splitComma(ips),
		RateLimit: server.RateLimitRule{PerMinute: *perMinute, Burst: *burst},
	}
	if *scopes == "all" {
		k.Scopes = slices.Clone(api.AllScopes)
	} else {
		k.Scopes = splitComma([]string{*scopes})
	}
	if *expires != "" {
		t, err := parseExpiry(*expires)
		if err != nil {
			return err
		}
		k.Expires = &t
	}
	raw, err := server.GenerateKey()
	if err != nil {
		return err
	}
	k.Hash = server.HashKey(raw)
	node, err := server.KeyNode(k)
	if err != nil {
		return err
	}
	err = server.EditKeys(*cfgPath, func(keys *yaml.Node) error {
		if server.KeyIndex(keys, *name) >= 0 {
			return fmt.Errorf("a key named %q already exists (use key rotate or key revoke)", *name)
		}
		keys.Content = append(keys.Content, node)
		return nil
	})
	if err != nil {
		return err
	}
	printNewKey(*name, raw, *cfgPath)
	warnPolicy(k)
	return nil
}

func cmdKeyRotate(args []string) error {
	fs, cfgPath := newFlags("key rotate")
	name := fs.String("name", "", "key name (required)")
	fs.Parse(args)
	raw, err := server.GenerateKey()
	if err != nil {
		return err
	}
	err = server.EditKeys(*cfgPath, func(keys *yaml.Node) error {
		i := server.KeyIndex(keys, *name)
		if i < 0 {
			return fmt.Errorf("no key named %q", *name)
		}
		server.SetKeyField(keys.Content[i], "hash", server.HashKey(raw))
		return nil
	})
	if err != nil {
		return err
	}
	printNewKey(*name, raw, *cfgPath)
	return nil
}

func printNewKey(name, raw, cfgPath string) {
	fmt.Printf("API key %q saved to %s.\n\n  %s\n\n", name, cfgPath, raw)
	fmt.Println("This is the only time the key is shown. Store it in sc-mcp with:")
	fmt.Printf("  sc-mcp add -name <server-name> -host <host> -key %s -fingerprint <fingerprint>\n", raw)
	fmt.Println("A running sc-server picks up the change after `systemctl reload sc-server` (SIGHUP).")
}

func warnPolicy(k *server.Key) {
	has := func(s string) bool { return slices.Contains(k.Scopes, s) }
	if (has(api.ScopeExec) || has(api.ScopeJobs) || has(api.ScopeCron)) && len(k.Commands.Allow) == 0 {
		fmt.Println("note: no -allow rules, so this key can run any shell command as the server's user.")
	}
	if has(api.ScopeFiles) && len(k.Paths.Read)+len(k.Paths.Write) == 0 {
		fmt.Println("note: files scope without -read-path/-write-path denies all file access.")
	}
	if (has(api.ScopeServices) || has(api.ScopeServicesManage)) && len(k.Services.Allow) == 0 {
		fmt.Println("note: services scope without -service globs denies all units.")
	}
}

func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return time.Now().UTC().AddDate(0, 0, n).Truncate(time.Second), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return time.Now().UTC().Add(d).Truncate(time.Second), nil
	}
	return time.Time{}, fmt.Errorf("cannot parse expiry %q", s)
}

func cmdKeyList(args []string) error {
	fs, cfgPath := newFlags("key list")
	fs.Parse(args)
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSCOPES\tCOMMANDS\tIP ALLOW\tRATE/MIN\tEXPIRES")
	for _, k := range cfg.Keys {
		cmds := "any (shell)"
		if len(k.Commands.Allow) > 0 {
			cmds = fmt.Sprintf("%d allow rules", len(k.Commands.Allow))
		}
		if len(k.Commands.Deny) > 0 {
			cmds += fmt.Sprintf(", %d deny", len(k.Commands.Deny))
		}
		ips, rate, exp := "any", "-", "never"
		if len(k.IPAllow) > 0 {
			ips = strings.Join(k.IPAllow, ",")
		}
		if k.RateLimit.PerMinute > 0 {
			rate = strconv.Itoa(k.RateLimit.PerMinute)
		}
		if k.Expires != nil {
			exp = k.Expires.Format(time.RFC3339)
			if time.Now().After(*k.Expires) {
				exp += " (expired)"
			}
		}
		if k.Disabled {
			exp += " (disabled)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", k.Name, strings.Join(k.Scopes, ","), cmds, ips, rate, exp)
	}
	return tw.Flush()
}

func cmdKeyRevoke(args []string) error {
	fs, cfgPath := newFlags("key revoke")
	name := fs.String("name", "", "key name (required)")
	fs.Parse(args)
	err := server.EditKeys(*cfgPath, func(keys *yaml.Node) error {
		i := server.KeyIndex(keys, *name)
		if i < 0 {
			return fmt.Errorf("no key named %q", *name)
		}
		keys.Content = slices.Delete(keys.Content, i, i+1)
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Key %q removed. Reload the server (systemctl reload sc-server) to apply.\n", *name)
	return nil
}

func cmdCertGen(args []string) error {
	fs, cfgPath := newFlags("cert gen")
	hosts := fs.String("hosts", "", "comma-separated DNS names/IPs (default: hostname, localhost and local IPs)")
	force := fs.Bool("force", false, "overwrite an existing certificate")
	fs.Parse(args)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.TLS.Cert); err == nil && !*force {
		return fmt.Errorf("%s exists (use -force to replace it; clients pinning the old fingerprint must be updated)", cfg.TLS.Cert)
	}
	h := tlsutil.DefaultHosts()
	if *hosts != "" {
		h = splitComma([]string{*hosts})
	}
	if err := tlsutil.GenerateSelfSigned(cfg.TLS.Cert, cfg.TLS.Key, h); err != nil {
		return err
	}
	fp, err := tlsutil.FileFingerprint(cfg.TLS.Cert)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s and %s for %s\nFingerprint: %s\n", cfg.TLS.Cert, cfg.TLS.Key, strings.Join(h, ", "), fp)
	return nil
}

func cmdFingerprint(args []string) error {
	fs, cfgPath := newFlags("fingerprint")
	fs.Parse(args)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	fp, err := tlsutil.FileFingerprint(cfg.TLS.Cert)
	if err != nil {
		return err
	}
	fmt.Println(fp)
	return nil
}
