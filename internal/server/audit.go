package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLog is an append-only JSON-lines file of every operation the server handles.
// Reopen switches to a (possibly new) path, e.g. after logrotate moved the file away.
// An AuditLog with an empty path discards everything.
type AuditLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func OpenAuditLog(path string) (*AuditLog, error) {
	a := &AuditLog{}
	return a, a.Reopen(path)
}

// Reopen closes the current file and opens path for appending (mode 0600).
func (a *AuditLog) Reopen(path string) error {
	var f *os.File
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		var err error
		if f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err != nil {
			return err
		}
	}
	a.mu.Lock()
	old := a.f
	a.f, a.path = f, path
	a.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

func (a *AuditLog) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return len(p), nil
	}
	return a.f.Write(p)
}

func (a *AuditLog) Close() error { return a.Reopen("") }

// SetAuditLog directs audit entries (one JSON object per line) to w; nil disables them.
func (s *Server) SetAuditLog(w *AuditLog) {
	if w == nil {
		s.audit = slog.New(slog.DiscardHandler)
		return
	}
	s.audit = slog.New(slog.NewJSONHandler(w, nil))
}

// Event writes a non-request entry (server start, reload, ...) to the audit log and the
// regular log.
func (s *Server) Event(msg string, attrs ...slog.Attr) {
	s.audit.LogAttrs(context.Background(), slog.LevelInfo, msg, attrs...)
	s.log.LogAttrs(context.Background(), slog.LevelInfo, msg, attrs...)
}

// requestLog collects what a request did; handlers add details with note().
type requestLog struct {
	op    string
	key   string
	err   error
	attrs []slog.Attr
}

type requestLogKey struct{}

// note adds details (command, path, unit, result ...) to the request's audit entry.
func note(r *http.Request, attrs ...slog.Attr) {
	if rl, ok := r.Context().Value(requestLogKey{}).(*requestLog); ok {
		rl.attrs = append(rl.attrs, attrs...)
	}
}

func logInfo(r *http.Request) *requestLog {
	rl, _ := r.Context().Value(requestLogKey{}).(*requestLog)
	if rl == nil {
		rl = &requestLog{}
	}
	return rl
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// logRequests writes one entry per request, authenticated or not, to the audit log and
// the regular log. Health checks are not logged.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rl := &requestLog{op: "unknown"}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), requestLogKey{}, rl)))

		ip, _ := remoteIP(r)
		attrs := []slog.Attr{
			slog.String("op", rl.op),
			slog.String("key", rl.key),
			slog.String("remote", ip.String()),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		}
		attrs = append(attrs, rl.attrs...)
		level := slog.LevelInfo
		if rl.err != nil {
			attrs = append(attrs, slog.String("error", rl.err.Error()))
			level = slog.LevelWarn
		}
		s.audit.LogAttrs(r.Context(), level, "request", attrs...)
		s.log.LogAttrs(r.Context(), level, "request", attrs...)
	})
}
