package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/adee42/mcp-server-control/internal/api"
)

// ServiceManager controls system services. The default implementation drives systemctl.
type ServiceManager interface {
	List(ctx context.Context, pattern string) ([]api.Service, error)
	Status(ctx context.Context, unit string, journalLines int) (api.ServiceStatus, error)
	Action(ctx context.Context, unit, action string) (api.ServiceActionResult, error)
}

// Runner runs a program and returns its stdout. A non-zero exit returns the output
// alongside an error that includes stderr.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return stdout.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), nil
}

func defaultServiceManager() ServiceManager { return &Systemd{Run: execRunner} }

// Systemd implements ServiceManager with systemctl and journalctl.
type Systemd struct{ Run Runner }

func (m *Systemd) List(ctx context.Context, pattern string) ([]api.Service, error) {
	args := []string{"list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"}
	if pattern != "" {
		args = append(args, "--", pattern)
	}
	out, err := m.Run(ctx, "systemctl", args...)
	if err != nil {
		return nil, err
	}
	return parseListUnits(out), nil
}

func parseListUnits(out []byte) []api.Service {
	var list []api.Service
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		// Failed units are prefixed with a marker such as "●" even in --plain mode on some versions.
		line := strings.TrimLeft(strings.TrimSpace(sc.Text()), "●* ")
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		list = append(list, api.Service{
			Unit: f[0], Load: f[1], Active: f[2], Sub: f[3],
			Description: strings.Join(f[4:], " "),
		})
	}
	return list
}

var statusProps = []string{
	"Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "Result",
	"MainPID", "ExecMainStatus", "ActiveEnterTimestamp", "NRestarts", "MemoryCurrent", "FragmentPath",
}

func (m *Systemd) Status(ctx context.Context, unit string, journalLines int) (api.ServiceStatus, error) {
	out, err := m.Run(ctx, "systemctl", "show", "--no-pager", "--property="+strings.Join(statusProps, ","), "--", unit)
	if err != nil {
		return api.ServiceStatus{}, err
	}
	st := api.ServiceStatus{Unit: unit, Properties: map[string]string{}}
	for line := range strings.Lines(string(out)) {
		if k, v, ok := strings.Cut(strings.TrimRight(line, "\r\n"), "="); ok {
			st.Properties[k] = v
		}
	}
	if journalLines > 0 {
		// The journal is a convenience; missing journalctl or permissions are not fatal.
		j, err := m.Run(ctx, "journalctl", "-u", unit, "-n", strconv.Itoa(journalLines), "--no-pager", "-o", "short-iso")
		if err == nil {
			st.RecentJournal = string(j)
		}
	}
	return st, nil
}

func (m *Systemd) Action(ctx context.Context, unit, action string) (api.ServiceActionResult, error) {
	res := api.ServiceActionResult{Unit: unit, Action: action}
	out, err := m.Run(ctx, "systemctl", action, "--", unit)
	res.Output = strings.TrimSpace(string(out))
	if err != nil {
		return res, errStatus(http.StatusBadGateway, err.Error())
	}
	// is-active exits non-zero for inactive units but still prints the state.
	state, _ := m.Run(ctx, "systemctl", "is-active", "--", unit)
	res.Active = strings.TrimSpace(string(state))
	return res, nil
}

var servicePatternRe = regexp.MustCompile(`^[A-Za-z0-9@._:*?\[\]-]{1,255}$`)

func (s *Server) handleServiceList(r *http.Request, k *Key) (any, error) {
	pattern := r.URL.Query().Get("pattern")
	if pattern != "" {
		note(r, slog.String("pattern", pattern))
	}
	if pattern != "" && !servicePatternRe.MatchString(pattern) {
		return nil, errStatus(http.StatusBadRequest, "invalid pattern")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	all, err := s.services.List(ctx, pattern)
	if err != nil {
		return nil, err
	}
	// Only show units this key may see.
	visible := slices.DeleteFunc(all, func(svc api.Service) bool { return !k.serviceAllowed(svc.Unit) })
	if visible == nil {
		visible = []api.Service{}
	}
	return visible, nil
}

func (s *Server) handleServiceStatus(r *http.Request, k *Key) (any, error) {
	note(r, slog.String("unit", r.PathValue("unit")))
	unit, err := k.checkService(r.PathValue("unit"))
	if err != nil {
		return nil, err
	}
	lines := 30
	if v := r.URL.Query().Get("journal_lines"); v != "" {
		if lines, err = strconv.Atoi(v); err != nil || lines < 0 {
			return nil, errStatus(http.StatusBadRequest, "journal_lines must be a non-negative integer")
		}
		lines = min(lines, 1000)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	return s.services.Status(ctx, unit, lines)
}

func (s *Server) handleServiceAction(r *http.Request, k *Key) (any, error) {
	action := r.PathValue("action")
	note(r, slog.String("unit", r.PathValue("unit")), slog.String("action", action))
	if !slices.Contains(api.ServiceActions, action) {
		return nil, errStatus(http.StatusBadRequest, fmt.Sprintf("unknown action %q (valid: %s)", action, strings.Join(api.ServiceActions, ", ")))
	}
	unit, err := k.checkService(r.PathValue("unit"))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.services.Action(ctx, unit, action)
	if err == nil {
		note(r, slog.String("active", res.Active))
	}
	return res, err
}
