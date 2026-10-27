package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"maps"
	"net/http"
	"os/exec"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/adee42/mcp-server-control/internal/api"
)

// JobManager runs background commands and keeps their recent output in memory.
// Jobs do not survive a server restart.
type JobManager struct {
	s    *Server
	mu   sync.Mutex
	jobs map[string]*job
	stop chan struct{}
	once sync.Once
}

type job struct {
	mu     sync.Mutex
	info   api.Job
	out    *ringBuffer
	cmd    *exec.Cmd
	cancel context.CancelFunc
	killed bool
	done   chan struct{}
}

func newJobManager(s *Server) *JobManager {
	m := &JobManager{s: s, jobs: map[string]*job{}, stop: make(chan struct{})}
	go m.reap()
	return m
}

// reap drops finished jobs older than the configured retention.
func (m *JobManager) reap() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.prune()
		}
	}
}

func (m *JobManager) prune() {
	cutoff := m.s.now().Add(-time.Duration(m.s.config().Limits.JobRetention))
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, j := range m.jobs {
		j.mu.Lock()
		old := j.info.FinishedAt != nil && j.info.FinishedAt.Before(cutoff)
		j.mu.Unlock()
		if old {
			delete(m.jobs, id)
		}
	}
}

func (m *JobManager) shutdown() {
	m.once.Do(func() { close(m.stop) })
	m.mu.Lock()
	jobs := slices.Collect(maps.Values(m.jobs))
	m.mu.Unlock()
	for _, j := range jobs {
		j.cancel()
	}
}

// running counts running jobs; the caller holds m.mu.
func (m *JobManager) running() int {
	n := 0
	for _, j := range m.jobs {
		j.mu.Lock()
		if j.info.Status == api.JobRunning {
			n++
		}
		j.mu.Unlock()
	}
	return n
}

func (s *Server) handleJobStart(r *http.Request, k *Key) (any, error) {
	var req api.JobRequest
	if err := decodeBody(r, smallBody, &req); err != nil {
		return nil, err
	}
	noteCommand(r, req.Command, req.Cwd, req.Env)
	m := s.jobs
	limits := s.config().Limits

	var ctx context.Context
	var cancel context.CancelFunc
	if req.TimeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), s.timeout(req.TimeoutSeconds, 0))
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	cmd, err := s.newCmd(ctx, k, req.Command, req.Cwd, req.Env)
	if err != nil {
		cancel()
		return nil, err
	}
	j := &job{
		info: api.Job{
			ID:        newJobID(),
			Command:   req.Command,
			KeyName:   k.Name,
			Status:    api.JobRunning,
			StartedAt: s.now(),
		},
		out:    newRingBuffer(int(limits.MaxOutput)),
		cmd:    cmd,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	cmd.Stdout, cmd.Stderr = j.out, j.out

	// Check the limit and register under one lock so concurrent starts cannot overshoot it.
	m.mu.Lock()
	if m.running() >= limits.MaxJobs {
		m.mu.Unlock()
		cancel()
		return nil, errStatus(http.StatusTooManyRequests, "too many running jobs on this server")
	}
	if err := cmd.Start(); err != nil {
		m.mu.Unlock()
		cancel()
		return nil, errStatus(http.StatusBadRequest, "cannot start command: "+err.Error())
	}
	m.jobs[j.info.ID] = j
	m.mu.Unlock()
	note(r, slog.String("job_id", j.info.ID))

	go func() {
		defer close(j.done)
		defer cancel()
		err := cmd.Wait()
		now := s.now()
		j.mu.Lock()
		defer j.mu.Unlock()
		j.info.FinishedAt = &now
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		j.info.ExitCode = &code
		switch {
		case j.killed:
			j.info.Status = api.JobKilled
		case ctx.Err() == context.DeadlineExceeded:
			j.info.Status = api.JobTimedOut
		case cmd.ProcessState == nil && err != nil:
			j.info.Status = api.JobFailed
			j.info.Error = err.Error()
		default:
			j.info.Status = api.JobExited
		}
		s.Event("job_finished",
			slog.String("job_id", j.info.ID), slog.String("key", j.info.KeyName), slog.String("command", j.info.Command),
			slog.String("status", j.info.Status), slog.Int("exit_code", code),
			slog.Int64("duration_ms", now.Sub(j.info.StartedAt).Milliseconds()))
	}()
	return j.snapshot(), nil
}

func newJobID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (j *job) snapshot() api.Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.info
}

func (j *job) terminate() { _ = terminateTree(j.cmd) }

func (s *Server) handleJobList(r *http.Request, k *Key) (any, error) {
	s.jobs.mu.Lock()
	list := make([]api.Job, 0, len(s.jobs.jobs))
	for _, j := range s.jobs.jobs {
		list = append(list, j.snapshot())
	}
	s.jobs.mu.Unlock()
	slices.SortFunc(list, func(a, b api.Job) int { return b.StartedAt.Compare(a.StartedAt) })
	return list, nil
}

func (s *Server) lookupJob(r *http.Request) (*job, error) {
	id := r.PathValue("id")
	note(r, slog.String("job_id", id))
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	j, ok := s.jobs.jobs[id]
	if !ok {
		return nil, errStatus(http.StatusNotFound, "no such job: "+id)
	}
	return j, nil
}

// handleJobGet returns status and output from ?offset= (default 0). ?wait=N waits up to
// N seconds (max 60) for the job to finish first, so callers can poll less often.
func (s *Server) handleJobGet(r *http.Request, k *Key) (any, error) {
	j, err := s.lookupJob(r)
	if err != nil {
		return nil, err
	}
	var offset int64
	if v := r.URL.Query().Get("offset"); v != "" {
		if offset, err = strconv.ParseInt(v, 10, 64); err != nil || offset < 0 {
			return nil, errStatus(http.StatusBadRequest, "offset must be a non-negative integer")
		}
	}
	if v := r.URL.Query().Get("wait"); v != "" {
		secs, err := strconv.Atoi(v)
		if err != nil || secs < 0 {
			return nil, errStatus(http.StatusBadRequest, "wait must be a non-negative integer")
		}
		select {
		case <-j.done:
		case <-time.After(time.Duration(min(secs, 60)) * time.Second):
		case <-r.Context().Done():
		}
	}
	out, start, next := j.out.ReadFrom(offset)
	return api.JobOutput{
		Job:        j.snapshot(),
		Offset:     start,
		NextOffset: next,
		Output:     string(out),
		Dropped:    start > offset,
	}, nil
}

// handleJobKill sends SIGTERM, then SIGKILL after 5 seconds if the job is still running.
func (s *Server) handleJobKill(r *http.Request, k *Key) (any, error) {
	j, err := s.lookupJob(r)
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	running := j.info.Status == api.JobRunning
	if running {
		j.killed = true
	}
	j.mu.Unlock()
	if running {
		j.terminate()
		select {
		case <-j.done:
		case <-time.After(5 * time.Second):
			j.cancel() // cancelling the context runs cmd.Cancel, which SIGKILLs the group
			<-j.done
		}
	}
	return j.snapshot(), nil
}

// ringBuffer keeps the most recent max bytes of a stream and counts everything written,
// so readers can address output by absolute offset.
type ringBuffer struct {
	mu    sync.Mutex
	buf   []byte
	max   int
	total int64 // bytes written since the start; buf holds [total-len(buf), total)
}

func newRingBuffer(max int) *ringBuffer { return &ringBuffer{max: max} }

func (b *ringBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total += int64(len(p))
	if len(p) >= b.max {
		b.buf = append(b.buf[:0], p[len(p)-b.max:]...)
		return len(p), nil
	}
	if over := len(b.buf) + len(p) - b.max; over > 0 {
		b.buf = append(b.buf[:0], b.buf[over:]...)
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

// ReadFrom returns output from offset on, the offset it actually starts at (later than
// requested if that output was dropped) and the offset to ask for next.
func (b *ringBuffer) ReadFrom(offset int64) (out []byte, start, next int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	first := b.total - int64(len(b.buf))
	start = min(max(offset, first), b.total)
	return slices.Clone(b.buf[start-first:]), start, b.total
}
