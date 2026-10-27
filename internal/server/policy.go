package server

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/shlex"
)

// shellMeta are characters that would let a command escape an allowlist if a shell saw them.
const shellMeta = ";|&$`<>()\n\r"

// commandPlan is how a command will be executed after policy checks.
type commandPlan struct {
	argv  []string
	shell bool // argv is ["/bin/sh", "-c", command]
}

// planCommand applies the key's command rules.
//
// Keys with an allowlist run commands without a shell: the command is split into words,
// shell metacharacters are rejected and the space-joined words must match an allow pattern.
// Keys without an allowlist get a shell. Deny patterns apply in both modes, but only an
// allowlist is a real security boundary: a shell can always obfuscate a denied command.
func (k *Key) planCommand(command string) (commandPlan, error) {
	if strings.TrimSpace(command) == "" {
		return commandPlan{}, errStatus(http.StatusBadRequest, "command is empty")
	}
	if strings.ContainsRune(command, 0) {
		return commandPlan{}, errStatus(http.StatusBadRequest, "command contains a NUL byte")
	}
	for _, re := range k.deny {
		if re.MatchString(command) {
			return commandPlan{}, denied("command matches deny rule %q", re)
		}
	}
	if len(k.allow) == 0 {
		return commandPlan{argv: shellArgv(command), shell: true}, nil
	}
	if i := strings.IndexAny(command, shellMeta); i >= 0 {
		return commandPlan{}, denied("shell metacharacter %q not allowed for this key (commands run without a shell)", command[i])
	}
	argv, err := shlex.Split(command)
	if err != nil {
		return commandPlan{}, errStatus(http.StatusBadRequest, "cannot parse command: "+err.Error())
	}
	if len(argv) == 0 {
		return commandPlan{}, errStatus(http.StatusBadRequest, "command is empty")
	}
	normalized := strings.Join(argv, " ")
	for _, re := range k.deny {
		if re.MatchString(normalized) {
			return commandPlan{}, denied("command matches deny rule %q", re)
		}
	}
	for _, re := range k.allow {
		if re.MatchString(normalized) {
			return commandPlan{argv: argv}, nil
		}
	}
	return commandPlan{}, denied("command not in this key's allowlist")
}

func denied(format string, args ...any) error {
	return errStatus(http.StatusForbidden, "denied by key policy: "+fmt.Sprintf(format, args...))
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// checkEnv rejects malformed names, and any overrides for allowlisted keys:
// variables such as LD_PRELOAD or PATH would defeat the allowlist.
func (k *Key) checkEnv(env map[string]string) error {
	if len(env) == 0 {
		return nil
	}
	if len(k.allow) > 0 {
		return denied("environment overrides are not allowed for keys with a command allowlist")
	}
	for name := range env {
		if !envNameRe.MatchString(name) {
			return errStatus(http.StatusBadRequest, fmt.Sprintf("invalid environment variable name %q", name))
		}
	}
	return nil
}

// checkPath resolves p (following symlinks) and verifies the result lies under one of the
// key's read roots, or write roots when write is set. It returns the resolved path.
func (k *Key) checkPath(p string, write bool) (string, error) {
	if !isAbs(p) {
		return "", errStatus(http.StatusBadRequest, "path must be absolute")
	}
	p = filepath.Clean(p)
	roots := k.Paths.Write
	if !write {
		roots = append(append([]string{}, k.Paths.Read...), k.Paths.Write...)
	}
	if len(roots) == 0 {
		kind := "read"
		if write {
			kind = "write"
		}
		return "", denied("no %s paths configured for this key", kind)
	}
	resolved, err := resolvePath(p, write)
	if err != nil {
		return "", err
	}
	for _, root := range roots {
		r := filepath.Clean(filepath.FromSlash(root))
		if rr, err := filepath.EvalSymlinks(r); err == nil {
			r = rr
		}
		if within(r, resolved) {
			return resolved, nil
		}
	}
	return "", denied("path %s is outside this key's allowed paths", p)
}

// resolvePath follows symlinks. For writes the target may not exist yet, so only its
// parent directory must resolve.
func resolvePath(p string, write bool) (string, error) {
	r, err := filepath.EvalSymlinks(p)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if !write {
		return "", errStatus(http.StatusNotFound, "no such file or directory: "+p)
	}
	// Walk up to the deepest existing ancestor (writes may create directories).
	dir, rest := filepath.Dir(p), filepath.Base(p)
	for {
		r, err := filepath.EvalSymlinks(dir)
		if err == nil {
			return filepath.Join(r, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errStatus(http.StatusNotFound, "no existing parent directory for "+p)
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

var unitRe = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,255}$`)

// checkService validates a unit name against the key's glob allowlist and returns the
// full unit name (".service" is appended when no unit type is given).
func (k *Key) checkService(name string) (string, error) {
	if !unitRe.MatchString(name) || strings.HasPrefix(name, "-") {
		return "", errStatus(http.StatusBadRequest, fmt.Sprintf("invalid unit name %q", name))
	}
	unit := name
	if !strings.Contains(unit, ".") {
		unit += ".service"
	}
	if k.serviceAllowed(unit) {
		return unit, nil
	}
	return "", denied("service %s not in this key's service allowlist", unit)
}

func (k *Key) serviceAllowed(unit string) bool {
	short := strings.TrimSuffix(unit, ".service")
	for _, g := range k.Services.Allow {
		if ok, _ := path.Match(g, unit); ok {
			return true
		}
		if ok, _ := path.Match(g, short); ok {
			return true
		}
	}
	return false
}
