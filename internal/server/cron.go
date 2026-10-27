package server

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/adee42/mcp-server-control/internal/api"
)

// CronManager keeps one /etc/cron.d file per job, named server-control-<name>.
// It never reads or touches cron files it did not create.
type CronManager struct {
	dir func() string
}

const (
	cronFilePrefix = "server-control-"
	cronHeader     = "# Managed by server-control. Do not edit by hand.\n"
	cronEnv        = "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
)

var (
	cronNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}$`)
	cronUserRe  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	cronFieldRe = regexp.MustCompile(`^[0-9A-Za-z*/,-]+$`)
	cronMacros  = []string{"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
)

func validateSchedule(s string) error {
	f := strings.Fields(s)
	if len(f) == 1 && slices.Contains(cronMacros, f[0]) {
		return nil
	}
	if len(f) != 5 {
		return fmt.Errorf("schedule must have 5 fields or be one of %s", strings.Join(cronMacros, ", "))
	}
	for _, x := range f {
		if !cronFieldRe.MatchString(x) {
			return fmt.Errorf("invalid schedule field %q", x)
		}
	}
	return nil
}

// formatCron renders a job file. "%" is escaped because cron turns it into a newline.
func formatCron(j api.CronJob) string {
	var b strings.Builder
	b.WriteString(cronHeader)
	fmt.Fprintf(&b, "# name: %s\n", j.Name)
	if j.Comment != "" {
		fmt.Fprintf(&b, "# comment: %s\n", j.Comment)
	}
	b.WriteString(cronEnv)
	fmt.Fprintf(&b, "%s %s %s\n", strings.Join(strings.Fields(j.Schedule), " "), j.User,
		strings.ReplaceAll(j.Command, "%", `\%`))
	return b.String()
}

func parseCron(name, content string) (api.CronJob, error) {
	j := api.CronJob{Name: name}
	for line := range strings.Lines(content) {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "# comment: "):
			j.Comment = strings.TrimPrefix(line, "# comment: ")
		case strings.HasPrefix(line, "#"), strings.Contains(strings.SplitN(line, " ", 2)[0], "="):
		default:
			n := 5
			if strings.HasPrefix(line, "@") {
				n = 1
			}
			f, rest := splitFields(line, n+1)
			if len(f) != n+1 || rest == "" {
				return j, fmt.Errorf("cannot parse cron line %q", line)
			}
			j.Schedule = strings.Join(f[:n], " ")
			j.User = f[n]
			j.Command = strings.ReplaceAll(rest, `\%`, "%")
		}
	}
	if j.Schedule == "" {
		return j, errors.New("no job line found")
	}
	return j, nil
}

// splitFields returns the first n whitespace-separated fields and the untouched remainder.
func splitFields(s string, n int) ([]string, string) {
	var f []string
	for len(f) < n {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			break
		}
		end := strings.IndexAny(s, " \t")
		if end < 0 {
			end = len(s)
		}
		f = append(f, s[:end])
		s = s[end:]
	}
	return f, strings.TrimLeft(s, " \t")
}

func (c *CronManager) path(name string) string {
	return filepath.Join(c.dir(), cronFilePrefix+name)
}

func (c *CronManager) List() ([]api.CronJob, error) {
	entries, err := os.ReadDir(c.dir())
	if err != nil {
		return nil, fsError(err)
	}
	list := []api.CronJob{}
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.Name(), cronFilePrefix)
		if !ok || !cronNameRe.MatchString(name) || e.IsDir() {
			continue
		}
		data, err := os.ReadFile(c.path(name))
		if err != nil {
			return nil, fsError(err)
		}
		j, err := parseCron(name, string(data))
		if err != nil {
			j.Comment = "unparseable: " + err.Error()
		}
		list = append(list, j)
	}
	return list, nil
}

func (c *CronManager) Put(j api.CronJob) error {
	// cron ignores files that are group or world writable.
	return writeFileAtomic(c.path(j.Name), []byte(formatCron(j)), 0o644, nil)
}

func (c *CronManager) Delete(name string) error {
	err := os.Remove(c.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return errStatus(http.StatusNotFound, "no such cron job: "+name)
	}
	return fsError(err)
}

func cronName(r *http.Request) (string, error) {
	name := r.PathValue("name")
	note(r, slog.String("cron_name", name))
	if !cronNameRe.MatchString(name) {
		return "", errStatus(http.StatusBadRequest, "cron job name must match [a-z0-9][a-z0-9-]{0,49}")
	}
	return name, nil
}

func (s *Server) handleCronList(r *http.Request, k *Key) (any, error) {
	return s.cron.List()
}

func (s *Server) handleCronPut(r *http.Request, k *Key) (any, error) {
	name, err := cronName(r)
	if err != nil {
		return nil, err
	}
	var j api.CronJob
	if err := decodeBody(r, smallBody, &j); err != nil {
		return nil, err
	}
	if j.Name != "" && j.Name != name {
		return nil, errStatus(http.StatusBadRequest, "name in body does not match URL")
	}
	j.Name = name
	if j.User == "" {
		j.User = "root"
	}
	if err := validateSchedule(j.Schedule); err != nil {
		return nil, errStatus(http.StatusBadRequest, err.Error())
	}
	if !cronUserRe.MatchString(j.User) {
		return nil, errStatus(http.StatusBadRequest, "invalid user name")
	}
	if strings.ContainsAny(j.Command, "\r\n") || strings.ContainsAny(j.Comment, "\r\n") {
		return nil, errStatus(http.StatusBadRequest, "command and comment must be a single line")
	}
	note(r, slog.String("schedule", j.Schedule), slog.String("user", j.User), slog.String("command", j.Command))
	// The same command policy as exec applies to what cron will run later.
	if _, err := k.planCommand(j.Command); err != nil {
		return nil, err
	}
	if err := s.cron.Put(j); err != nil {
		return nil, fsError(err)
	}
	return j, nil
}

func (s *Server) handleCronDelete(r *http.Request, k *Key) (any, error) {
	name, err := cronName(r)
	if err != nil {
		return nil, err
	}
	if err := s.cron.Delete(name); err != nil {
		return nil, err
	}
	return map[string]string{"deleted": name}, nil
}
