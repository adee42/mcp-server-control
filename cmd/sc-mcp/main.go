// Command sc-mcp is the local side of server-control. Run without arguments it is an MCP
// server on stdio (started by the Claude plugin); its subcommands manage the server list.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adee42/mcp-server-control/internal/mcpserver"
	"github.com/adee42/mcp-server-control/internal/tlsutil"
)

const usage = `sc-mcp - server-control MCP server and server list manager

Usage:
  sc-mcp [serve] [-from-env]          run the MCP server on stdio (what the Claude plugin does);
                                      -from-env takes servers from the Claude Desktop extension settings
  sc-mcp add -name N -host H [-port 8443] (-key K | -key-env VAR) [-fingerprint FP] [-description D]
  sc-mcp remove -name N
  sc-mcp list
  sc-mcp test [-name N]                check connectivity and key for one or all servers
  sc-mcp path                          print the servers file location

Servers file: %s
(override with $SERVER_CONTROL_CONFIG)
`

func main() {
	path, err := mcpserver.ConfigPath()
	if err != nil {
		log.Fatal(err)
	}
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var args []string
	if len(os.Args) > 2 {
		args = os.Args[2:]
	}
	switch cmd {
	case "serve":
		err = serve(path, args)
	case "add":
		err = cmdAdd(path, args)
	case "remove", "rm":
		err = cmdRemove(path, args)
	case "list", "ls":
		err = cmdList(path)
	case "test":
		err = cmdTest(path, args)
	case "path":
		fmt.Println(path)
	case "version", "-version", "--version":
		fmt.Println(mcpserver.Version)
	case "help", "-h", "-help", "--help":
		fmt.Printf(usage, path)
	default:
		err = fmt.Errorf("unknown command %q (run sc-mcp help)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(path string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fromEnv := fs.Bool("from-env", false, "read servers from SC_SERVER_<n>_NAME/ADDRESS/KEY/FINGERPRINT (Claude Desktop extension settings) instead of the servers file")
	fs.Parse(args)
	// stdout carries the MCP protocol; diagnostics go to stderr.
	log.SetOutput(os.Stderr)
	src := mcpserver.FileSource(path)
	if *fromEnv {
		src = mcpserver.EnvSource()
	}
	return mcpserver.NewServer(src).Run(context.Background(), &mcp.StdioTransport{})
}

func cmdAdd(path string, args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	var s mcpserver.Server
	fs.StringVar(&s.Name, "name", "", "server name used by Claude (required)")
	fs.StringVar(&s.Host, "host", "", "hostname or IP (required)")
	fs.IntVar(&s.Port, "port", 8443, "port")
	fs.StringVar(&s.APIKey, "key", "", "API key from `sc-server key add`")
	fs.StringVar(&s.APIKeyEnv, "key-env", "", "read the API key from this environment variable instead")
	fs.StringVar(&s.TLSFingerprint, "fingerprint", "", "pin the server certificate (from `sc-server fingerprint`)")
	fs.StringVar(&s.Description, "description", "", "what this server is, shown to Claude")
	fs.BoolVar(&s.InsecureSkipVerify, "insecure", false, "skip TLS verification (testing only)")
	replace := fs.Bool("replace", false, "replace an existing entry with the same name")
	fs.Parse(args)
	if s.Name == "" || s.Host == "" {
		return errors.New("-name and -host are required")
	}
	if (s.APIKey == "") == (s.APIKeyEnv == "") {
		return errors.New("give exactly one of -key or -key-env")
	}
	if s.TLSFingerprint != "" {
		fp, err := tlsutil.NormalizeFingerprint(s.TLSFingerprint)
		if err != nil {
			return err
		}
		s.TLSFingerprint = fp
	} else if !s.InsecureSkipVerify {
		fmt.Fprintln(os.Stderr, "note: no -fingerprint, so the server certificate must be trusted by a system CA.")
	}
	f, err := mcpserver.LoadServers(path)
	if err != nil {
		return err
	}
	if i := slices.IndexFunc(f.Servers, func(x *mcpserver.Server) bool { return x.Name == s.Name }); i >= 0 {
		if !*replace {
			return fmt.Errorf("server %q already exists (use -replace)", s.Name)
		}
		f.Servers[i] = &s
	} else {
		f.Servers = append(f.Servers, &s)
	}
	if err := f.Save(path); err != nil {
		return err
	}
	fmt.Printf("Saved server %q to %s\n", s.Name, path)
	return testOne(&s)
}

func cmdRemove(path string, args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	name := fs.String("name", "", "server name (required)")
	fs.Parse(args)
	f, err := mcpserver.LoadServers(path)
	if err != nil {
		return err
	}
	n := len(f.Servers)
	f.Servers = slices.DeleteFunc(f.Servers, func(s *mcpserver.Server) bool { return s.Name == *name })
	if len(f.Servers) == n {
		return fmt.Errorf("no server named %q", *name)
	}
	if err := f.Save(path); err != nil {
		return err
	}
	fmt.Printf("Removed server %q\n", *name)
	return nil
}

func cmdList(path string) error {
	f, err := mcpserver.LoadServers(path)
	if err != nil {
		return err
	}
	if len(f.Servers) == 0 {
		fmt.Println("No servers configured in", path)
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tKEY\tTLS\tDESCRIPTION")
	for _, s := range f.Servers {
		key := "inline"
		if s.APIKeyEnv != "" {
			key = "$" + s.APIKeyEnv
		}
		tlsMode := "system CA"
		switch {
		case s.TLSFingerprint != "":
			tlsMode = "pinned"
		case s.InsecureSkipVerify:
			tlsMode = "INSECURE"
		}
		fmt.Fprintf(tw, "%s\t%s:%d\t%s\t%s\t%s\n", s.Name, s.Host, s.Port, key, tlsMode, s.Description)
	}
	return tw.Flush()
}

func cmdTest(path string, args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	name := fs.String("name", "", "server name (default: all)")
	fs.Parse(args)
	f, err := mcpserver.LoadServers(path)
	if err != nil {
		return err
	}
	failed := 0
	for _, s := range f.Servers {
		if *name != "" && s.Name != *name {
			continue
		}
		if testOne(s) != nil {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d server(s) failed", failed)
	}
	return nil
}

func testOne(s *mcpserver.Server) error {
	fail := func(err error) error {
		fmt.Printf("%-16s FAIL  %v\n", s.Name, err)
		return err
	}
	c, err := s.Client()
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h, err := c.Health(ctx)
	if err != nil {
		return fail(err)
	}
	info, err := c.Info(ctx)
	if err != nil {
		return fail(fmt.Errorf("reachable (sc-server %s) but: %w", h.Version, err))
	}
	fmt.Printf("%-16s OK    %s (%s %s), sc-server %s, key %q scopes %v\n",
		s.Name, info.Hostname, info.OS, info.Distro, h.Version, info.KeyName, info.KeyScopes)
	return nil
}
