---
name: server-control
description: How to operate remote Linux servers with the server-control MCP tools (run_command, start_job, service_action, set_cron, read_file, ...) and how to add servers. Use when the user asks to check, change, deploy to, restart services on, or schedule jobs on one of their servers.
---

# Working with server-control

The `server-control` MCP tools talk to `sc-server` agents on the user's Linux servers.
Each server has its own API key, and each key has a policy that the server enforces.

## Before acting
- Call `list_servers` to get the exact server names, then call `server_info` once per server. It shows the OS, the resources and `key_scopes`, which tell you what this key may do.
- If a tool fails with **"denied by key policy"** or **"lacks scope"**, stop and tell the user. Don't try a different command to get around it: the policy is deliberate.
- Keys with a command allowlist run commands **without a shell**, so pipes, `&&`, `;`, redirects and `$(...)` are rejected. Run one plain command at a time.

## Choosing a tool
| Task | Tool |
|---|---|
| Quick command (< 1 min) | `run_command` (set `timeout_seconds` when needed) |
| Upgrades, builds, backups, anything long | `start_job`, then `job_status` with `wait_seconds` (up to 60) and `offset` = previous `next_offset` |
| Service state / logs | `list_services`, `service_status` (includes recent journal lines) |
| Start/stop/restart/reload/enable/disable | `service_action` |
| Scheduled tasks | `list_cron`, `set_cron`, `delete_cron` (only jobs server-control created) |
| Config files | `read_file` and `write_file` (atomic; keeps owner and mode) |
| Binary or large files | `download_file`, `upload_file` (local path ↔ server path) |

## Safety
- Confirm with the user before destructive or disruptive actions: deleting data, stopping or restarting production services, reboots, package removals, overwriting configs.
- Before `write_file` on an existing config, read it first. After the change, validate it (for example `nginx -t`) before reloading the service.
- Prefer `reload` over `restart` when the service supports it.

## Adding or changing servers
The plugin doesn't hold API keys in the conversation. Servers are managed with the `sc-mcp` CLI, which writes `servers.yaml` (`sc-mcp path` prints its location):

```
sc-mcp add -name web1 -host 10.0.0.5 -key sck_... -fingerprint SHA256:AB:CD:...
sc-mcp test
```

Keys are created on the server with `sudo sc-server key add -name <name> -scopes ...`, and `sudo sc-server fingerprint` prints the certificate pin. Point the user to these commands instead of asking them to paste keys into the chat.
