package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/adee42/mcp-server-control/internal/api"
)

// newCmd applies the key's command and environment policy and builds the process.
// The process runs in its own process group so cancellation kills its children too.
func (s *Server) newCmd(ctx context.Context, k *Key, command, cwd string, env map[string]string) (*exec.Cmd, error) {
	plan, err := k.planCommand(command)
	if err != nil {
		return nil, err
	}
	if err := k.checkEnv(env); err != nil {
		return nil, err
	}
	if cwd != "" && !isAbs(cwd) {
		return nil, errStatus(http.StatusBadRequest, "cwd must be absolute")
	}
	cmd := exec.CommandContext(ctx, plan.argv[0], plan.argv[1:]...)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	for name, v := range env {
		cmd.Env = append(cmd.Env, name+"="+v)
	}
	setProcAttrs(cmd)
	cmd.Cancel = func() error { return killTree(cmd) }
	cmd.WaitDelay = 5 * time.Second
	return cmd, nil
}

func (s *Server) handleExec(r *http.Request, k *Key) (any, error) {
	var req api.ExecRequest
	if err := decodeBody(r, smallBody+int64(s.config().Limits.MaxFile), &req); err != nil {
		return nil, err
	}
	noteCommand(r, req.Command, req.Cwd, req.Env)
	if req.Stdin != "" {
		note(r, slog.Int("stdin_bytes", len(req.Stdin)))
	}
	limits := s.config().Limits
	timeout := s.timeout(req.TimeoutSeconds, time.Duration(limits.DefaultTimeout))
	// Derived from the request context, so a client disconnect also kills the command.
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	cmd, err := s.newCmd(ctx, k, req.Command, req.Cwd, req.Env)
	if err != nil {
		return nil, err
	}
	stdout := &capBuffer{max: int(limits.MaxOutput)}
	stderr := &capBuffer{max: int(limits.MaxOutput)}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}
	start := time.Now()
	err = cmd.Run()
	res := api.ExecResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationMS: time.Since(start).Milliseconds(),
		Truncated:  stdout.truncated || stderr.truncated,
		TimedOut:   errors.Is(ctx.Err(), context.DeadlineExceeded),
	}
	res.ExitCode = exitCode(cmd, err, &res.Stderr)
	note(r, slog.Int("exit_code", res.ExitCode), slog.Bool("timed_out", res.TimedOut), slog.Bool("truncated", res.Truncated))
	return res, nil
}

// noteCommand records a command, its working directory and the names (not values) of
// environment overrides in the audit entry.
func noteCommand(r *http.Request, command, cwd string, env map[string]string) {
	note(r, slog.String("command", command))
	if cwd != "" {
		note(r, slog.String("cwd", cwd))
	}
	if len(env) > 0 {
		note(r, slog.Any("env_names", slices.Sorted(maps.Keys(env))))
	}
}

// exitCode maps a Run/Wait result to a shell-like exit code. Start failures (such as a
// missing executable) become 127 with the error appended to stderr.
func exitCode(cmd *exec.Cmd, err error, stderr *string) int {
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	if err != nil {
		if *stderr != "" && !strings.HasSuffix(*stderr, "\n") {
			*stderr += "\n"
		}
		*stderr += err.Error()
		return 127
	}
	return 0
}

// capBuffer keeps the first max bytes written to it and records whether more arrived.
type capBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	room := b.max - b.buf.Len()
	if room < len(p) {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *capBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
