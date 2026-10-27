// Command thirdparty prints the license texts of all third-party code compiled into the
// sc-server and sc-mcp binaries: every linked Go module (for every platform the binaries
// are built for) and the Go standard library. Binary releases must ship these notices.
//
//	go run ./tools/thirdparty -o THIRD_PARTY_LICENSES.txt
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// targets are the binaries and platforms that get published (see build.ps1 and the Makefile).
var targets = []struct{ pkg, goos, goarch string }{
	{"./cmd/sc-server", "linux", "amd64"},
	{"./cmd/sc-server", "linux", "arm64"},
	{"./cmd/sc-mcp", "windows", "amd64"},
	{"./cmd/sc-mcp", "darwin", "amd64"},
	{"./cmd/sc-mcp", "darwin", "arm64"},
	{"./cmd/sc-mcp", "linux", "amd64"},
	{"./cmd/sc-mcp", "linux", "arm64"},
}

var licenseFile = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice)([.-].*)?$`)

type module struct{ path, version, dir string }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "thirdparty:", err)
		os.Exit(1)
	}
}

func run() error {
	out := flag.String("o", "", "write to this file instead of stdout")
	flag.Parse()
	mods := map[string]module{}
	for _, t := range targets {
		cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}", t.pkg)
		cmd.Env = append(os.Environ(), "GOOS="+t.goos, "GOARCH="+t.goarch, "CGO_ENABLED=0")
		cmd.Stderr = os.Stderr
		list, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("go list %s for %s/%s: %w", t.pkg, t.goos, t.goarch, err)
		}
		sc := bufio.NewScanner(bytes.NewReader(list))
		for sc.Scan() {
			if f := strings.Split(sc.Text(), "\t"); len(f) == 3 {
				mods[f[0]] = module{f[0], f[1], f[2]}
			}
		}
	}
	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return err
	}
	version, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		return err
	}

	dst := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		dst = f
	}
	w := bufio.NewWriter(dst)
	fmt.Fprintln(w, "Third-party software included in the server-control binaries")
	fmt.Fprintln(w, "(sc-server, sc-mcp and the server-control.mcpb bundle).")
	fmt.Fprintln(w, "server-control itself is MIT licensed; see LICENSE.")

	if err := section(w, "Go standard library and runtime", strings.TrimSpace(string(version)), strings.TrimSpace(string(goroot))); err != nil {
		return err
	}
	paths := make([]string, 0, len(mods))
	for p := range mods {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		m := mods[p]
		if err := section(w, m.path, m.version, m.dir); err != nil {
			return err
		}
	}
	return w.Flush()
}

// section writes every license and notice file found at the top of dir.
func section(w *bufio.Writer, name, version, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && licenseFile.MatchString(e.Name()) {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("%s: no license file in %s", name, dir)
	}
	fmt.Fprintf(w, "\n%s\n%s %s\n", strings.Repeat("=", 78), name, version)
	for _, f := range files {
		text, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s %s\n\n%s\n", strings.Repeat("-", 10), f, strings.TrimRight(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n"))
	}
	return nil
}
