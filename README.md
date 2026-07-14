# opencode-pty

An OpenCode plugin for durable interactive PTY sessions and finite argv execution. It requires Bun 1.3.8 or later. PTYs remain owned by the per-user Bun daemon. When explicitly enabled and given a built Rust worker, finite exec processes are owned by a per-session native worker.

## Tools

| Tool | Purpose |
| --- | --- |
| `pty_spawn` | Start a permitted PTY session. |
| `pty_write` | Send input to a running session. |
| `pty_read` | Read or literal-search retained output. |
| `pty_list` | List durable session records. |
| `pty_kill` | Request termination; cleanup only after it is confirmed. |
| `shell_exec` | Run a finite permitted argv command with separate stdout/stderr. |
| `pty_wait` | Wait daemon-side for output evidence or process exit. |
| `pty_send_wait` | Send PTY input, then wait daemon-side. |

`pty_write` accepts terminal input, not a new command invocation. Permission checks therefore happen at `pty_spawn`, not per keystroke.

`notifyOnExit` remains accepted for compatibility but is rejected: the durable daemon has no safe event channel back into a completed OpenCode session.

`shell_exec` is `exec` mode, not a shell parser: `command` and `args` are passed as argv and a positive timeout is required. With the native worker enabled, a Rust per-session worker owns the finite child using `std::process`, exposes an authenticated loopback RPC endpoint, and writes redacted output to the existing session chunk journal. The daemon can reconnect to a reachable worker after restart and recover its output cursor and final state. Without the explicit worker configuration, exec retains the legacy Bun behavior.

`pty_spawn` is `pty` mode and remains interactive. A supplied `idempotencyKey` reuses only a matching active PTY scoped to the originating OpenCode session and canonical workdir; changing command, args, environment, timeout, or name is rejected. Titles and descriptions are presentation fields and do not affect reuse. `pty_wait` conditions are literal output, a limited-safe regex, or exit. They run in the daemon against output/exit events with a 3600-second maximum deadline, not plugin polling. `pty_send_wait` captures its output boundary after PTY input is accepted, so output that arrived before or during acceptance cannot satisfy the wait. Output readiness is evidence only; no bare `ready` state is claimed.

## Security Model

- The daemon binds only to `127.0.0.1` on a random port.
- Each RPC requires the bearer token in the private per-user daemon descriptor.
- The daemon persists metadata and output under `PTY_DAEMON_DIR`, or the user state directory by default.
- On Windows, the daemon replaces and verifies the `PTY_DAEMON_DIR` DACL before creating its ownership secret or descriptor. It grants Full Control only to the current user SID and LocalSystem; every daemon directory and sensitive file inherits only those ACEs. This applies to a custom `PTY_DAEMON_DIR` too. If the DACL cannot be applied or verified, daemon startup fails closed.
- Every non-health RPC carries a capability derived by the plugin from a private, persistent daemon ownership secret, OpenCode session ID, and canonical project directory. A session can only be listed, read, written, waited on, stopped, or deleted by that same owner context. Knowing an ID is insufficient. The secret is private to the daemon data directory; removing it deliberately revokes access to existing records, so retain it during backup/recovery and rotate only when that revocation is intended.
- `session.deleted` stops and removes only that owner's `conversation` sessions, including native exec records. `persistent` sessions remain until their owner explicitly stops and cleans them up. Controlled daemon restarts reconnect reachable native workers; workers independently enforce their direct-child timeout and per-stream output cap. A worker terminal result is complete only after its direct child exits and both stdout/stderr readers reach EOF; a bounded reader-drain timeout reports incomplete output as unknown rather than complete.
- Environment defaults to a small platform/project-safe allowlist plus explicitly supplied variables. Set `inheritEnv: true` only when the command needs the daemon environment. Raw environment values are never persisted: records retain only profile kind, redacted key markers, and a fingerprint. Output replaces values of obvious secret-named environment variables with `[REDACTED]` before PTY journal or exec output persistence. The streaming redactor retains at most 4095 UTF-8 characters (secret values are capped at 4096 bytes), so ordinary trailing output can wait for a later callback or process exit.
- Browser-facing APIs, WebSockets, and slash commands are intentionally not provided.

The installed OpenCode plugin SDK (1.3.13) exposes config reads and permission hooks, but no callable evaluator or prompt request API for a tool. Before every `pty_spawn` and `shell_exec`, this plugin reads OpenCode's merged config and locally applies the documented ruleset: global `permission` rules are evaluated in declaration order, then `agent.<agent>.permission` rules in declaration order, with the last matching rule winning. Thus an agent deny overrides a global allow, and an agent allow overrides a global deny. Only an effective matching `allow` permits a command; absent, unmatched, `ask`, unreadable, malformed, and `deny` rules deny it. Rules match the executable followed by the complete argv using OpenCode wildcards. External directories use canonical containment and require an effective matching `external_directory` allow for the resolved path. This is not an authoritative OpenCode permission invocation.

On Linux native `shell_exec` runs its child in a fresh POSIX session/process group. Timeout, output caps, rollback, and stop send `SIGTERM` to that group, then `SIGKILL` after a bounded grace period. Linux reports its `/proc` scan in `containment`/`termination`; only `posix_best_effort_empty` means that scan observed no remaining group or session members. It is not an absolute containment guarantee: a child can call `setsid`, and observed escapes are reported when still attributable. macOS reports verification unavailable conservatively. PTY sessions remain legacy Bun/bun-pty sessions: they are not worker-contained. This does not provide Windows Job Objects, cgroups, terminal emulation, signed binaries, or OS CPU/memory limits.

## Setup

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-pty"]
}
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PTY_DAEMON_DIR` | per-user state directory | Daemon descriptor, ownership secret, session metadata, and output; protected with the same restrictive DACL on Windows. |
| `PTY_MAX_OUTPUT_BYTES` | `1000000` | Maximum retained output bytes per session. |
| `PTY_NATIVE_WORKER_ENABLED` | unset | Set to `1` to route `shell_exec` through the native worker. |
| `PTY_NATIVE_WORKER_PATH` | unset | Required production path to a built `opencode-pty-worker` executable. |
| `PTY_NATIVE_WORKER_DEV` | unset | Set only in development to run `cargo run --manifest-path worker/Cargo.toml`; never a production fallback. |

Output is an append-only, session-local UTF-8 chunk journal. Callbacks are coalesced into bounded 64 KiB UTF-8 segments and retained output is capped at the configured value (up to 64 MiB), so fragmented output cannot create unbounded files. Each chunk records its byte sequence range and timestamp. Retention removes whole oldest chunks, so `pty_read` reports `retained_from` and `truncated`; line offsets remain compatible, and durable byte sequences are available in output and RPC responses.

The daemon `diagnostics` RPC reports whether Linux native exec containment is enabled and whether `/proc` verification is available. It never claims PTY containment or Windows Job Objects.

## Development

```bash
bun ci
bun typecheck
bun unittest
bun lint
bun format
bun build:prod
bun package:smoke
cargo build --locked --workspace
```

## License

MIT
