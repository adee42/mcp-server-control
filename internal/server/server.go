// Package server implements the sc-server HTTPS API.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adee42/mcp-server-control/internal/api"
)

// Version is reported by /v1/health; set at build time with -ldflags.
var Version = "dev"

type Server struct {
	cfg      atomic.Pointer[Config]
	log      *slog.Logger
	audit    *slog.Logger
	now      func() time.Time
	jobs     *JobManager
	services ServiceManager
	cron     *CronManager

	limMu    sync.Mutex
	limiters map[string]limiterEntry
}

// New builds a server. services may be nil to use the platform default (systemd on Linux).
func New(cfg *Config, log *slog.Logger, services ServiceManager) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if services == nil {
		services = defaultServiceManager()
	}
	s := &Server{
		log:      log,
		audit:    slog.New(slog.DiscardHandler),
		now:      time.Now,
		services: services,
		limiters: map[string]limiterEntry{},
	}
	s.cfg.Store(cfg)
	s.jobs = newJobManager(s)
	s.cron = &CronManager{dir: func() string { return s.config().CronDir }}
	return s
}

func (s *Server) config() *Config { return s.cfg.Load() }

// Reload swaps in a new config (keys, limits); listen address and TLS changes need a restart.
func (s *Server) Reload(cfg *Config) { s.cfg.Store(cfg) }

// Close kills running jobs.
func (s *Server) Close() { s.jobs.shutdown() }

// Handler returns the HTTP handler for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, api.Health{Status: "ok", Version: Version})
	})
	// op names the operation in the audit log.
	route := func(pattern, op, scope string, h handlerFunc) {
		mux.Handle(pattern, s.authed(op, scope, h))
	}
	route("GET /v1/info", "info", api.ScopeInfo, s.handleInfo)
	route("POST /v1/exec", "exec", api.ScopeExec, s.handleExec)
	route("POST /v1/jobs", "job.start", api.ScopeJobs, s.handleJobStart)
	route("GET /v1/jobs", "job.list", api.ScopeJobs, s.handleJobList)
	route("GET /v1/jobs/{id}", "job.status", api.ScopeJobs, s.handleJobGet)
	route("DELETE /v1/jobs/{id}", "job.kill", api.ScopeJobs, s.handleJobKill)
	route("GET /v1/files", "file.read", api.ScopeFiles, s.handleFileRead)
	route("PUT /v1/files", "file.write", api.ScopeFiles, s.handleFileWrite)
	route("GET /v1/files/list", "file.list", api.ScopeFiles, s.handleFileList)
	route("GET /v1/services", "service.list", api.ScopeServices, s.handleServiceList)
	route("GET /v1/services/{unit}", "service.status", api.ScopeServices, s.handleServiceStatus)
	route("POST /v1/services/{unit}/{action}", "service.action", api.ScopeServicesManage, s.handleServiceAction)
	route("GET /v1/cron", "cron.list", api.ScopeCron, s.handleCronList)
	route("PUT /v1/cron/{name}", "cron.set", api.ScopeCron, s.handleCronPut)
	route("DELETE /v1/cron/{name}", "cron.delete", api.ScopeCron, s.handleCronDelete)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := errStatus(http.StatusNotFound, "no such endpoint: "+r.Method+" "+r.URL.Path)
		logInfo(r).err = err
		writeError(w, err)
	})
	return s.logRequests(mux)
}

// handlerFunc returns a response value (written as JSON with 200) or an error.
type handlerFunc func(r *http.Request, k *Key) (any, error)

func (s *Server) authed(op, scope string, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl := logInfo(r)
		rl.op = op
		k, err := s.authenticate(r)
		if k != nil {
			rl.key = k.Name
		}
		if err == nil && !k.HasScope(scope) {
			err = errStatus(http.StatusForbidden, fmt.Sprintf("key %q lacks scope %q", k.Name, scope))
		}
		var resp any
		if err == nil {
			resp, err = h(r, k)
		}
		if err != nil {
			rl.err = err
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
}

func statusOf(err error) int {
	var ae *httpError
	if errors.As(err, &ae) {
		return ae.status
	}
	return http.StatusInternalServerError
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, statusOf(err), api.Error{Error: err.Error()})
}

// decodeBody reads a JSON request body of at most limit bytes into v.
func decodeBody(r *http.Request, limit int64, v any) error {
	body := http.MaxBytesReader(nil, r.Body, limit)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return errStatus(http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", limit))
		}
		return errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error())
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errStatus(http.StatusBadRequest, "invalid JSON body: trailing data")
	}
	return nil
}

const smallBody = 1 << 20

// timeout converts a requested timeout in seconds into a duration clamped to the server limits.
func (s *Server) timeout(seconds int, def time.Duration) time.Duration {
	max := time.Duration(s.config().Limits.MaxTimeout)
	if seconds <= 0 {
		return min(def, max)
	}
	return min(time.Duration(seconds)*time.Second, max)
}
