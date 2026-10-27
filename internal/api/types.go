// Package api defines the JSON wire types shared by sc-server and sc-mcp.
package api

import "time"

// Scopes a key can be granted.
const (
	ScopeInfo           = "info"
	ScopeExec           = "exec"
	ScopeJobs           = "jobs"
	ScopeFiles          = "files"
	ScopeServices       = "services"
	ScopeServicesManage = "services:manage"
	ScopeCron           = "cron"
)

// AllScopes lists every valid scope.
var AllScopes = []string{ScopeInfo, ScopeExec, ScopeJobs, ScopeFiles, ScopeServices, ScopeServicesManage, ScopeCron}

// Error is the body of every non-2xx response.
type Error struct {
	Error string `json:"error"`
}

type Health struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type Disk struct {
	Mount      string `json:"mount"`
	FSType     string `json:"fstype"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

type Info struct {
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	Distro        string     `json:"distro,omitempty"`
	Kernel        string     `json:"kernel,omitempty"`
	Arch          string     `json:"arch"`
	UptimeSeconds float64    `json:"uptime_seconds,omitempty"`
	Load          [3]float64 `json:"load,omitempty"`
	CPUs          int        `json:"cpus"`
	MemTotalBytes uint64     `json:"mem_total_bytes,omitempty"`
	MemAvailBytes uint64     `json:"mem_available_bytes,omitempty"`
	Disks         []Disk     `json:"disks,omitempty"`
	KeyName       string     `json:"key_name"`
	KeyScopes     []string   `json:"key_scopes"`
}

// ExecRequest runs a command synchronously.
type ExecRequest struct {
	Command string            `json:"command"`
	Cwd     string            `json:"cwd,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Stdin   string            `json:"stdin,omitempty"`
	// TimeoutSeconds of 0 uses the server default; values above the server maximum are clamped.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

type ExecResult struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// JobRequest starts a background job. TimeoutSeconds of 0 means no timeout.
type JobRequest struct {
	Command        string            `json:"command"`
	Cwd            string            `json:"cwd,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

const (
	JobRunning  = "running"
	JobExited   = "exited"
	JobKilled   = "killed"
	JobTimedOut = "timed_out"
	JobFailed   = "failed"
)

type Job struct {
	ID         string     `json:"id"`
	Command    string     `json:"command"`
	KeyName    string     `json:"key_name"`
	Status     string     `json:"status"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// JobOutput is a slice of a job's combined stdout/stderr starting at Offset.
// Offsets count bytes since the job started; output older than the buffer is dropped.
type JobOutput struct {
	Job
	Offset     int64  `json:"offset"`
	NextOffset int64  `json:"next_offset"`
	Output     string `json:"output"`
	Dropped    bool   `json:"dropped,omitempty"`
}

type FileContent struct {
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`
	ModTime    time.Time `json:"mod_time"`
	ContentB64 string    `json:"content_b64"`
}

type FileWrite struct {
	ContentB64 string `json:"content_b64"`
	// Mode is an octal string such as "0644"; empty keeps the existing mode or uses 0644.
	Mode string `json:"mode,omitempty"`
	// MkdirAll creates missing parent directories.
	MkdirAll bool `json:"mkdir_all,omitempty"`
}

type FileWriteResult struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type DirEntry struct {
	Name    string    `json:"name"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
}

type DirListing struct {
	Path    string     `json:"path"`
	Entries []DirEntry `json:"entries"`
}

type Service struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

type ServiceStatus struct {
	Unit          string            `json:"unit"`
	Properties    map[string]string `json:"properties"`
	RecentJournal string            `json:"recent_journal,omitempty"`
}

// Service actions accepted by POST /v1/services/{unit}/{action}.
var ServiceActions = []string{"start", "stop", "restart", "reload", "enable", "disable"}

type ServiceActionResult struct {
	Unit   string `json:"unit"`
	Action string `json:"action"`
	Active string `json:"active"`
	Output string `json:"output,omitempty"`
}

type CronJob struct {
	Name     string `json:"name"`
	Schedule string `json:"schedule"`
	User     string `json:"user"`
	Command  string `json:"command"`
	Comment  string `json:"comment,omitempty"`
}
