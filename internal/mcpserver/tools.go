package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adee42/mcp-server-control/internal/api"
	"github.com/adee42/mcp-server-control/internal/client"
)

// Version is reported to MCP clients; set at build time with -ldflags.
var Version = "dev"

// maxInlineText is the largest file read_file returns inline; larger files need download_file.
const maxInlineText = 256 << 10

const instructions = `Tools for remote Linux servers managed by server-control. Every tool except list_servers takes a "server" name from list_servers.
Each server's API key has its own scopes and policy: a "denied by key policy" error is final, so do not try to work around it with other commands.
Call server_info first on an unfamiliar server to see its OS, resources and what your key may do.
Use start_job + job_status for anything that may run longer than a minute (upgrades, builds, backups).
Prefer service_* tools over running systemctl through run_command, and set_cron over editing crontabs by hand.
Ask the user before destructive actions (deleting data, stopping production services, rebooting).`

// NewServer builds the MCP server. The source is read on every tool call, so changes to
// the server list take effect without restarting.
func NewServer(src Source) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "server-control", Version: Version},
		&mcp.ServerOptions{Instructions: instructions})
	t := &tools{src: src}
	t.register(s)
	return s
}

type tools struct{ src Source }

func (t *tools) client(name string) (*client.Client, error) {
	f, err := t.src.Load()
	if err != nil {
		return nil, err
	}
	srv, err := f.Find(name)
	if err != nil {
		return nil, err
	}
	return srv.Client()
}

// text wraps a plain text result.
func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// jsonResult renders v as indented JSON text.
func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // keep > and & in commands readable
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, nil, err
	}
	return text(b.String()), nil, nil
}

// withClient adapts a handler that needs a client for the input's server.
func withClient[In interface{ serverName() string }](t *tools, h func(ctx context.Context, c *client.Client, in In) (*mcp.CallToolResult, any, error)) mcp.ToolHandlerFor[In, any] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		c, err := t.client(in.serverName())
		if err != nil {
			return nil, nil, err
		}
		return h(ctx, c, in)
	}
}

type serverArg struct {
	Server string `json:"server" jsonschema:"name of the server, from list_servers"`
}

func (a serverArg) serverName() string { return a.Server }

type runCommandIn struct {
	serverArg
	Command        string            `json:"command" jsonschema:"the command line to run"`
	Cwd            string            `json:"cwd,omitempty" jsonschema:"absolute working directory"`
	Env            map[string]string `json:"env,omitempty" jsonschema:"extra environment variables"`
	Stdin          string            `json:"stdin,omitempty" jsonschema:"text to feed on standard input"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"timeout in seconds; default is the server's (usually 60); use start_job for long tasks"`
}

type startJobIn struct {
	serverArg
	Command        string            `json:"command" jsonschema:"the command line to run in the background"`
	Cwd            string            `json:"cwd,omitempty" jsonschema:"absolute working directory"`
	Env            map[string]string `json:"env,omitempty" jsonschema:"extra environment variables"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"kill the job after this many seconds; 0 means no timeout"`
}

type jobIn struct {
	serverArg
	ID string `json:"job_id" jsonschema:"job id returned by start_job"`
}

type jobStatusIn struct {
	jobIn
	Offset      int64 `json:"offset,omitempty" jsonschema:"return output from this byte offset (pass the previous next_offset to get only new output)"`
	WaitSeconds int   `json:"wait_seconds,omitempty" jsonschema:"wait up to this many seconds (max 60) for the job to finish before answering"`
}

type pathIn struct {
	serverArg
	Path string `json:"path" jsonschema:"absolute path on the server"`
}

type writeFileIn struct {
	pathIn
	Content    string `json:"content,omitempty" jsonschema:"text content to write"`
	ContentB64 string `json:"content_b64,omitempty" jsonschema:"base64 content, for binary data (instead of content)"`
	Mode       string `json:"mode,omitempty" jsonschema:"octal permissions such as 0644; default keeps the existing mode"`
	MkdirAll   bool   `json:"mkdir_all,omitempty" jsonschema:"create missing parent directories"`
}

type transferIn struct {
	pathIn
	LocalPath string `json:"local_path" jsonschema:"path on this (local) machine"`
	Mode      string `json:"mode,omitempty" jsonschema:"upload only: octal permissions such as 0644"`
	MkdirAll  bool   `json:"mkdir_all,omitempty" jsonschema:"upload only: create missing parent directories on the server"`
}

type listServicesIn struct {
	serverArg
	Pattern string `json:"pattern,omitempty" jsonschema:"unit glob such as nginx* (optional)"`
}

type serviceIn struct {
	serverArg
	Unit string `json:"unit" jsonschema:"systemd unit, e.g. nginx or nginx.service"`
}

type serviceStatusIn struct {
	serviceIn
	JournalLines *int `json:"journal_lines,omitempty" jsonschema:"recent journal lines to include (default 30, 0 for none)"`
}

type serviceActionIn struct {
	serviceIn
	Action string `json:"action" jsonschema:"one of start, stop, restart, reload, enable, disable"`
}

type setCronIn struct {
	serverArg
	Name     string `json:"name" jsonschema:"job name: lowercase letters, digits and dashes"`
	Schedule string `json:"schedule" jsonschema:"cron schedule: 5 fields (m h dom mon dow) or @daily, @hourly, @reboot, ..."`
	Command  string `json:"command" jsonschema:"command to run (a percent sign is escaped automatically)"`
	User     string `json:"user,omitempty" jsonschema:"user to run as (default root)"`
	Comment  string `json:"comment,omitempty" jsonschema:"what the job is for"`
}

type cronNameIn struct {
	serverArg
	Name string `json:"name" jsonschema:"cron job name"`
}

func ptr[T any](v T) *T { return &v }

func (t *tools) register(s *mcp.Server) {
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}
	destructive := &mcp.ToolAnnotations{DestructiveHint: ptr(true)}
	safeWrite := &mcp.ToolAnnotations{DestructiveHint: ptr(false)}

	mcp.AddTool(s, &mcp.Tool{Name: "list_servers", Description: "List the configured servers (name, host, port, description).", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			f, err := t.src.Load()
			if err != nil {
				return nil, nil, err
			}
			var problems string
			if len(f.Problems) > 0 {
				problems = "\nSkipped incomplete or invalid entries (ask the user to fix them):\n- " + strings.Join(f.Problems, "\n- ") + "\n"
			}
			if len(f.Servers) == 0 {
				return text("No servers configured. " + t.src.AddHint + problems), nil, nil
			}
			type row struct {
				Name        string `json:"name"`
				Host        string `json:"host"`
				Port        int    `json:"port"`
				Description string `json:"description,omitempty"`
			}
			rows := make([]row, len(f.Servers))
			for i, s := range f.Servers {
				rows[i] = row{s.Name, s.Host, s.Port, s.Description}
			}
			res, _, err := jsonResult(rows)
			if err != nil {
				return nil, nil, err
			}
			if problems != "" {
				res.Content = append(res.Content, &mcp.TextContent{Text: problems})
			}
			return res, nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "server_info", Description: "Host facts (OS, kernel, uptime, load, memory, disks) and the scopes of the API key in use.", Annotations: readOnly},
		withClient(t, func(ctx context.Context, c *client.Client, in serverArg) (*mcp.CallToolResult, any, error) {
			info, err := c.Info(ctx)
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(info)
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "run_command", Description: "Run a command on the server and wait for it to finish. Returns exit code, stdout and stderr. Keys with a command allowlist run commands without a shell (no pipes, redirects or chaining).", Annotations: destructive},
		withClient(t, func(ctx context.Context, c *client.Client, in runCommandIn) (*mcp.CallToolResult, any, error) {
			r, err := c.Exec(ctx, api.ExecRequest{Command: in.Command, Cwd: in.Cwd, Env: in.Env, Stdin: in.Stdin, TimeoutSeconds: in.TimeoutSeconds})
			if err != nil {
				return nil, nil, err
			}
			return text(formatExec(r)), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "start_job", Description: "Start a long-running command in the background. Returns a job id for job_status and kill_job. Output is kept in memory on the server (most recent part only for very chatty jobs).", Annotations: destructive},
		withClient(t, func(ctx context.Context, c *client.Client, in startJobIn) (*mcp.CallToolResult, any, error) {
			j, err := c.StartJob(ctx, api.JobRequest{Command: in.Command, Cwd: in.Cwd, Env: in.Env, TimeoutSeconds: in.TimeoutSeconds})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(j)
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "job_status", Description: "Status and output of a background job. Pass the previous next_offset as offset to get only new output; use wait_seconds to wait for completion.", Annotations: readOnly},
		withClient(t, func(ctx context.Context, c *client.Client, in jobStatusIn) (*mcp.CallToolResult, any, error) {
			o, err := c.Job(ctx, in.ID, in.Offset, in.WaitSeconds)
			if err != nil {
				return nil, nil, err
			}
			return text(formatJob(o)), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "list_jobs", Description: "List background jobs on the server, newest first.", Annotations: readOnly},
		withClient(t, func(ctx context.Context, c *client.Client, in serverArg) (*mcp.CallToolResult, any, error) {
			j, err := c.Jobs(ctx)
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(j)
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "kill_job", Description: "Stop a background job (SIGTERM to its process group, SIGKILL after 5 seconds).", Annotations: destructive},
		withClient(t, func(ctx context.Context, c *client.Client, in jobIn) (*mcp.CallToolResult, any, error) {
			j, err := c.KillJob(ctx, in.ID)
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(j)
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "read_file", Description: "Read a text file on the server. Binary or large files: use download_file.", Annotations: readOnly},
		withClient(t, func(ctx context.Context, c *client.Client, in pathIn) (*mcp.CallToolResult, any, error) {
			f, err := c.ReadFile(ctx, in.Path)
			if err != nil {
				return nil, nil, err
			}
			data, err := base64.StdEncoding.DecodeString(f.ContentB64)
			if err != nil {
				return nil, nil, err
			}
			head := fmt.Sprintf("%s (%d bytes, mode %s, modified %s)", f.Path, f.Size, f.Mode, f.ModTime.Format("2006-01-02 15:04:05 MST"))
			switch {
			case !utf8.Valid(data):
				return text(head + "\nBinary content; use download_file to save it locally."), nil, nil
			case len(data) > maxInlineText:
				return text(fmt.Sprintf("%s\nFile is larger than %d KiB; use download_file, or run_command with head/tail/grep.", head, maxInlineText>>10)), nil, nil
			}
			return text(head + "\n\n" + string(data)), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "write_file", Description: "Create or overwrite a file on the server (atomic replace; keeps owner and mode of an existing file unless mode is given).", Annotations: destructive},
		withClient(t, func(ctx context.Context, c *client.Client, in writeFileIn) (*mcp.CallToolResult, any, error) {
			b64 := in.ContentB64
			if b64 == "" {
				b64 = base64.StdEncoding.EncodeToString([]byte(in.Content))
			} else if in.Content != "" {
				return nil, nil, errors.New("give either content or content_b64, not both")
			}
			r, err := c.WriteFile(ctx, in.Path, api.FileWrite{ContentB64: b64, Mode: in.Mode, MkdirAll: in.MkdirAll})
			if err != nil {
				return nil, nil, err
			}
			return text(fmt.Sprintf("Wrote %d bytes to %s", r.Size, r.Path)), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "list_dir", Description: "List a directory on the server.", Annotations: readOnly},
		withClient(t, func(ctx context.Context, c *client.Client, in pathIn) (*mcp.CallToolResult, any, error) {
			d, err := c.ListDir(ctx, in.Path)
			if err != nil {
				return nil, nil, err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s (%d entries)\n", d.Path, len(d.Entries))
			for _, e := range d.Entries {
				name := e.Name
				if e.IsDir {
					name += "/"
				}
				fmt.Fprintf(&b, "%s %10d %s %s\n", e.Mode, e.Size, e.ModTime.Format("2006-01-02 15:04"), name)
			}
			return text(b.String()), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "download_file", Description: "Copy a file from the server to a path on this local machine.", Annotations: safeWrite},
		withClient(t, func(ctx context.Context, c *client.Client, in transferIn) (*mcp.CallToolResult, any, error) {
			if in.LocalPath == "" {
				return nil, nil, errors.New("local_path is required")
			}
			f, err := c.ReadFile(ctx, in.Path)
			if err != nil {
				return nil, nil, err
			}
			data, err := base64.StdEncoding.DecodeString(f.ContentB64)
			if err != nil {
				return nil, nil, err
			}
			local, _ := filepath.Abs(in.LocalPath)
			if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
				return nil, nil, err
			}
			if err := os.WriteFile(local, data, 0o644); err != nil {
				return nil, nil, err
			}
			return text(fmt.Sprintf("Downloaded %s (%d bytes) to %s", f.Path, len(data), local)), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "upload_file", Description: "Copy a file from this local machine to a path on the server (atomic replace).", Annotations: destructive},
		withClient(t, func(ctx context.Context, c *client.Client, in transferIn) (*mcp.CallToolResult, any, error) {
			data, err := os.ReadFile(in.LocalPath)
			if err != nil {
				return nil, nil, err
			}
			r, err := c.WriteFile(ctx, in.Path, api.FileWrite{ContentB64: base64.StdEncoding.EncodeToString(data), Mode: in.Mode, MkdirAll: in.MkdirAll})
			if err != nil {
				return nil, nil, err
			}
			return text(fmt.Sprintf("Uploaded %s to %s (%d bytes)", in.LocalPath, r.Path, r.Size)), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "list_services", Description: "List systemd services the key may see, with load/active/sub state.", Annotations: readOnly},
		withClient(t, func(ctx context.Context, c *client.Client, in listServicesIn) (*mcp.CallToolResult, any, error) {
			list, err := c.Services(ctx, in.Pattern)
			if err != nil {
				return nil, nil, err
			}
			var b strings.Builder
			for _, s := range list {
				fmt.Fprintf(&b, "%-40s %-8s %-10s %-10s %s\n", s.Unit, s.Load, s.Active, s.Sub, s.Description)
			}
			if b.Len() == 0 {
				return text("No matching services visible to this key."), nil, nil
			}
			return text(b.String()), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "service_status", Description: "Detailed state of a systemd unit plus recent journal lines.", Annotations: readOnly},
		withClient(t, func(ctx context.Context, c *client.Client, in serviceStatusIn) (*mcp.CallToolResult, any, error) {
			lines := 30
			if in.JournalLines != nil {
				lines = *in.JournalLines
			}
			st, err := c.ServiceStatus(ctx, in.Unit, lines)
			if err != nil {
				return nil, nil, err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s\n", st.Unit)
			for _, k := range []string{"Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "Result", "MainPID", "ExecMainStatus", "ActiveEnterTimestamp", "NRestarts", "MemoryCurrent", "FragmentPath"} {
				if v, ok := st.Properties[k]; ok && v != "" {
					fmt.Fprintf(&b, "  %s=%s\n", k, v)
				}
			}
			if st.RecentJournal != "" {
				fmt.Fprintf(&b, "\nRecent journal:\n%s", st.RecentJournal)
			}
			return text(b.String()), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "service_action", Description: "Start, stop, restart, reload, enable or disable a systemd unit. Needs the services:manage scope.", Annotations: destructive},
		withClient(t, func(ctx context.Context, c *client.Client, in serviceActionIn) (*mcp.CallToolResult, any, error) {
			r, err := c.ServiceAction(ctx, in.Unit, in.Action)
			if err != nil {
				return nil, nil, err
			}
			msg := fmt.Sprintf("%s %s: done, now %s", in.Action, r.Unit, r.Active)
			if r.Output != "" {
				msg += "\n" + r.Output
			}
			return text(msg), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "list_cron", Description: "List cron jobs managed by server-control (files /etc/cron.d/server-control-*). Other cron entries are not shown.", Annotations: readOnly},
		withClient(t, func(ctx context.Context, c *client.Client, in serverArg) (*mcp.CallToolResult, any, error) {
			j, err := c.Cron(ctx)
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(j)
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "set_cron", Description: "Create or replace a named cron job. The command is checked against the key's command policy.", Annotations: destructive},
		withClient(t, func(ctx context.Context, c *client.Client, in setCronIn) (*mcp.CallToolResult, any, error) {
			j, err := c.PutCron(ctx, api.CronJob{Name: in.Name, Schedule: in.Schedule, Command: in.Command, User: in.User, Comment: in.Comment})
			if err != nil {
				return nil, nil, err
			}
			return text(fmt.Sprintf("Cron job %q saved: %s as %s: %s", j.Name, j.Schedule, j.User, j.Command)), nil, nil
		}))

	mcp.AddTool(s, &mcp.Tool{Name: "delete_cron", Description: "Delete a cron job created by set_cron.", Annotations: destructive},
		withClient(t, func(ctx context.Context, c *client.Client, in cronNameIn) (*mcp.CallToolResult, any, error) {
			if err := c.DeleteCron(ctx, in.Name); err != nil {
				return nil, nil, err
			}
			return text("Deleted cron job " + in.Name), nil, nil
		}))
}

func formatExec(r api.ExecResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit_code: %d (%d ms)", r.ExitCode, r.DurationMS)
	if r.TimedOut {
		b.WriteString(" TIMED OUT")
	}
	if r.Truncated {
		b.WriteString(" (output truncated)")
	}
	b.WriteString("\n")
	if r.Stdout != "" {
		fmt.Fprintf(&b, "--- stdout ---\n%s", r.Stdout)
		if !strings.HasSuffix(r.Stdout, "\n") {
			b.WriteString("\n")
		}
	}
	if r.Stderr != "" {
		fmt.Fprintf(&b, "--- stderr ---\n%s", r.Stderr)
	}
	return b.String()
}

func formatJob(o api.JobOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "job %s: %s", o.ID, o.Status)
	if o.ExitCode != nil {
		fmt.Fprintf(&b, ", exit_code %d", *o.ExitCode)
	}
	if o.Error != "" {
		fmt.Fprintf(&b, ", error: %s", o.Error)
	}
	fmt.Fprintf(&b, "\ncommand: %s\nstarted: %s", o.Command, o.StartedAt.Format("2006-01-02 15:04:05 MST"))
	if o.FinishedAt != nil {
		fmt.Fprintf(&b, ", finished: %s", o.FinishedAt.Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Fprintf(&b, "\noutput bytes %d-%d (next_offset=%d)", o.Offset, o.NextOffset, o.NextOffset)
	if o.Dropped {
		b.WriteString(" — earlier output was dropped from the server's buffer")
	}
	if o.Output != "" {
		fmt.Fprintf(&b, "\n--- output ---\n%s", o.Output)
	}
	return b.String()
}
