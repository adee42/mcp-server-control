# server-control

Let Claude operate your Linux servers through MCP, with each server enforcing a separate policy for every API key.

```
Claude Code ──stdio/MCP──▶ sc-mcp (local plugin) ──HTTPS + bearer key──▶ sc-server (on each Linux host)
                            servers.yaml                                  config.yaml: keys + policies
```

- **`sc-server`** is a single static Go binary that runs as a systemd service on each host. It provides command execution, background jobs, file transfer, systemd service control and cron jobs. Every request is checked against the policy of the key that sent it.
- **`sc-mcp`** is the MCP server bundled in the Claude plugin. It reads your list of servers (name, host, port, API key, TLS pin) and exposes 18 tools to Claude.

## Quick start

### 1. Download or build

Prebuilt binaries are attached to each [GitHub Release](https://github.com/adee42/mcp-server-control/releases/latest): `sc-server-linux-amd64`, `sc-server-linux-arm64` and `server-control.mcpb`, plus `SHA256SUMS` and `THIRD_PARTY_LICENSES.txt`. Check what you downloaded with:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

To build yourself instead (the Claude Code plugin always needs this step, because its `sc-mcp` binary is not in the repository):

```powershell
.\build.ps1          # Windows: plugin/bin/sc-mcp.exe + bin/sc-server-linux-{amd64,arm64}
```
```sh
make                 # macOS/Linux: plugin/bin/sc-mcp + bin/sc-server-linux-*
```

### 2. Install the server on a Linux host

Copy `sc-server-linux-amd64` (from the release or `bin/`) and the `deploy/` folder to the host, then run:

```sh
sudo ./deploy/install.sh ./sc-server-linux-amd64 admin
```

The script installs `/usr/local/bin/sc-server` and creates `/etc/server-control/config.yaml` (mode 0600). It also generates a self-signed certificate and enables the `sc-server` systemd service. If you pass a key name (`admin` above), it also creates a full-access key. The script prints the **API key**, which is shown only this once, and the **certificate fingerprint**.

### 3. Register the server locally

```sh
sc-mcp add -name web1 -host web1.example.com -key sck_... -fingerprint SHA256:AB:CD:... -description "Production web server"
sc-mcp test
```

The servers file is `%AppData%\server-control\servers.yaml` on Windows and `~/.config/server-control/servers.yaml` on Linux (`~/Library/Application Support/...` on macOS). Run `sc-mcp path` to print it, or set `SERVER_CONTROL_CONFIG` to use another file. It is re-read on every tool call. To keep a key out of the file, use `-key-env VAR`.

### 4. Install the plugin in Claude Code

```
/plugin marketplace add D:\path\to\mcp-server-control
/plugin install server-control@server-control
```

#### Or: Claude Desktop (MCP Bundle)

Download `server-control.mcpb` from the latest release, or build it:

```powershell
.\build.ps1 -Mcpb    # or: make mcpb   (needs Node.js; writes bin/server-control.mcpb)
```

Open `server-control.mcpb` in Claude Desktop, or drag it onto **Settings → Extensions**. One bundle covers Windows (x64; ARM runs it under emulation), macOS (Intel and Apple silicon) and Linux (x64 and arm64). The bundle is not signed.

Servers are entered in the extension's settings screen, which has five slots. Each slot has these fields:

| Field | Example | |
|---|---|---|
| Name | `web1` | Optional; defaults to the host |
| Address | `web1.example.com` or `10.0.0.5:9443` | Port defaults to 8443 |
| API key | `sck_...` | From `sudo sc-server key add`; stored as a secret by Claude Desktop |
| TLS fingerprint | `SHA256:AB:CD:...` | From `sudo sc-server fingerprint`. Leave it empty only for CA-signed certificates. |

Leave unused slots empty. For more servers than five, choose a `servers.yaml` (same format as for the Claude Code plugin, for example one written by `sc-mcp add`) in the optional **Servers file** setting. Its servers are added to the ones in the slots. You can also leave all slots empty and use only the file. The file is re-read on every request, so adding a server to it needs no restart. Slot changes, on the other hand, only apply once each running Claude session restarts the extension.

A slot or file entry that is wrong (for example a missing key, a duplicate name, or a file that is missing or not valid YAML) is skipped, and the problem is shown to Claude in `list_servers`. The other servers keep working. When a slot and the file use the same name, the slot wins. Under the hood the settings are passed to `sc-mcp serve -from-env` as `SC_SERVER_<n>_NAME`, `_ADDRESS`, `_KEY`, `_FINGERPRINT` and `SC_SERVERS_FILE`. When you start `sc-mcp` yourself you can set slots 1–20 this way.

Then ask Claude something like *"check disk usage on web1 and restart nginx if it's unhealthy"*.

## API keys and policies

Keys are managed on the server. These commands edit `config.yaml` in place and keep its comments:

```sh
sudo sc-server key add -name monitoring -scopes info,exec,services \
     -allow '^uptime$' -allow '^df( |$)' -service nginx -service 'app-*' \
     -ip 10.0.0.0/8 -expires 90d -rate 30
sudo sc-server key list
sudo sc-server key rotate -name monitoring     # new secret, same policy
sudo sc-server key revoke -name monitoring
sudo systemctl reload sc-server                # SIGHUP: applies key/limit changes without dropping jobs
```

Only the SHA-256 hash of each key is stored on the server. Keys look like `sck_` followed by 43 base62 characters (256 bits).

| Option | Config field | Effect |
|---|---|---|
| Scopes | `scopes` | `info`, `exec`, `jobs`, `files`, `services` (list/status), `services:manage` (start/stop/restart/reload/enable/disable), `cron` |
| Command allowlist | `commands.allow` | Regexes matched against the command's space-joined words. **If set, commands run without a shell** and `; \| & $ \` < > ( )` and newlines are rejected, so the list can't be bypassed by chaining. Environment overrides are refused too. |
| Command denylist | `commands.deny` | Regexes; matching commands are refused. Best effort only: with a shell, a determined user can obfuscate a command. Use an allowlist as the real boundary. |
| Paths | `paths.read`, `paths.write` | Roots for the file tools. Symlinks are resolved before checking; `write` implies `read`. No paths means no file access. |
| Services | `services.allow` | Globs on unit names (`nginx`, `app-*`, `*`). No globs means no units. |
| Source IPs | `ip_allow` | IPs or CIDRs; other sources get 403. |
| Expiry | `expires` | RFC 3339 time; after it the key gets 401. |
| Rate limit | `rate_limit.per_minute`, `burst` | Token bucket per key; excess requests get 429. |
| Disable | `disabled: true` | Temporarily switch a key off. |

The command policy also applies to background jobs and to commands placed in cron jobs. See [deploy/config.example.yaml](deploy/config.example.yaml) for global limits: timeouts, output and file size caps, job retention.

## MCP tools

`list_servers`, `server_info`, `run_command`, `start_job`, `job_status`, `list_jobs`, `kill_job`, `read_file`, `write_file`, `list_dir`, `download_file`, `upload_file`, `list_services`, `service_status`, `service_action`, `list_cron`, `set_cron`, `delete_cron`.

The plugin also ships a skill ([plugin/skills/server-control/SKILL.md](plugin/skills/server-control/SKILL.md)) that tells Claude how to use these tools safely.

## HTTP API (sc-server)

All endpoints except `/v1/health` need `Authorization: Bearer <key>`. Errors are returned as `{"error": "..."}` with status 400/401/403/404/413/429.

| Endpoint | Scope |
|---|---|
| `GET /v1/health` | none |
| `GET /v1/info` | info |
| `POST /v1/exec` `{command, cwd, env, stdin, timeout_seconds}` | exec |
| `POST /v1/jobs`, `GET /v1/jobs`, `GET /v1/jobs/{id}?offset=&wait=`, `DELETE /v1/jobs/{id}` | jobs |
| `GET /v1/files?path=`, `PUT /v1/files?path=` `{content_b64, mode, mkdir_all}`, `GET /v1/files/list?path=` | files |
| `GET /v1/services?pattern=`, `GET /v1/services/{unit}?journal_lines=` | services |
| `POST /v1/services/{unit}/{action}` | services:manage |
| `GET /v1/cron`, `PUT /v1/cron/{name}` `{schedule, command, user, comment}`, `DELETE /v1/cron/{name}` | cron |

Cron jobs are written as `/etc/cron.d/server-control-<name>`. Existing cron entries are never read or modified.

## Audit log

Every operation is appended to `/var/log/server-control/audit.log` (mode 0600) as one JSON object per line. Refused operations are included: wrong or expired key, wrong IP, missing scope, policy denial, unknown endpoint. Health checks are not logged. To use another file, set `audit_log: /path` in the config; to disable the log, set `audit_log: off`.

Each request entry has `time`, `op` (for example `exec`, `file.write`, `service.action`, `cron.set`), `key` (the key name, never the secret), `remote`, `method`, `path`, `status` and `duration_ms`, plus details for the operation:

| op | Extra fields |
|---|---|
| `exec`, `job.start` | `command`, `cwd`, `env_names` (names only, never values), `stdin_bytes`; for exec also `exit_code`, `timed_out`, `truncated`; for jobs `job_id` |
| `job.status`, `job.kill` | `job_id` |
| `file.read`, `file.write`, `file.list` | `file`, `resolved` (after symlinks), `bytes`; writes also `mode` and `created`. File contents are never logged. |
| `service.*` | `unit`, `action`, `active` (state after the action), `pattern` |
| `cron.*` | `cron_name`, `schedule`, `user`, `command` |

Refused requests add an `error` field and have level `WARN`. Besides request entries, the log has `server_start`, `config_reloaded`, `server_stop`, and `job_finished` (with `exit_code`, `status` and `duration_ms`) events.

```sh
sudo tail -f /var/log/server-control/audit.log | jq -c 'select(.level == "WARN")'   # watch refusals
sudo jq -r 'select(.op == "exec") | [.time, .key, .command, .exit_code] | @tsv' /var/log/server-control/audit.log
```

`install.sh` installs `deploy/sc-server.logrotate`, which rotates the log weekly and keeps 52 files. After rotating it runs `systemctl reload sc-server` so the server reopens the file. A SIGHUP always reopens the log.

## Security notes

- `sc-server` runs as root so that it can manage systemd and `/etc/cron.d`. A key without a command allowlist is therefore full root shell access; give such keys an `ip_allow` and an expiry.
- TLS 1.2+ is always on. Pinning the fingerprint (`sc-mcp add -fingerprint`) is the recommended setup with the self-signed certificate. Without a pin, the certificate must chain to a system CA. You can also point `tls.cert`/`tls.key` at a real certificate, such as one from Let's Encrypt.
- `servers.yaml` contains API keys and is written with mode 0600.
- Every operation is written to the audit log (see below) and to the journal (`journalctl -u sc-server`).
- Background jobs live in memory and are killed when the server stops.

## Development

```sh
go test ./...                 # runs on Windows too (Linux-only parts are stubbed)
make vet                      # vet for the host and for GOOS=linux
```

Layout: `cmd/sc-server`, `cmd/sc-mcp`, `internal/server` (API, auth, policy), `internal/client` (typed HTTPS client with pinning), `internal/mcpserver` (servers file and MCP tools), `internal/api` (shared wire types), `plugin/` (Claude plugin), `deploy/` (systemd unit, installer, example config), `tools/thirdparty` (collects third-party license notices).

### Releasing

Binaries are published as GitHub Release assets, not committed; `bin/` is ignored. From a clean checkout:

```sh
git tag -a v0.2.0 -m "server-control 0.2.0" && git push origin v0.2.0
.\build.ps1 -Release          # or: make release
```

This builds every binary with the tag as its version and writes `bin/THIRD_PARTY_LICENSES.txt` (generated by `go run ./tools/thirdparty`, and also packed into the bundle) and `bin/SHA256SUMS`. Then create a release for the tag on GitHub and attach the five files from `bin/`. Bump `version` in `mcpb/manifest.json` and `plugin/.claude-plugin/plugin.json` to match the tag first.

## License

[MIT](LICENSE) © 2026 adee42
