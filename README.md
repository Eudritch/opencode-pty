# opencode-pty

An OpenCode plugin for durable interactive PTY sessions and finite argv execution. It requires Bun 1.3.8 or later. A per-user Bun daemon owns processes and persisted PTY output; the plugin supplies tools and applies a local fail-closed permission adapter.

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

`shell_exec` is `exec` mode, not a shell parser: `command` and `args` are passed as argv and a positive timeout is required. It returns separately bounded stdout/stderr, observed exit evidence, timeout/output-limit flags, and whether termination was confirmed. Each exec record durably retains the captured streams and their byte/truncation metadata; inspect it through daemon RPC `execOutput`. Timeout and output limits request termination, wait briefly, then force-kill and return within a bounded interval. If the operating system cannot confirm termination, the record reports unknown termination rather than claiming success.

`pty_spawn` is `pty` mode and remains interactive. A supplied `idempotencyKey` reuses only a matching active PTY scoped to the originating OpenCode session and canonical workdir; changing command, args, environment, or timeout is rejected. Titles and descriptions are presentation fields and do not affect reuse. `pty_wait` conditions are literal output, a limited-safe regex, or exit. They run in the daemon against output/exit events with a 3600-second maximum deadline, not plugin polling. `pty_send_wait` captures the durable output sequence before its write and only accepts subsequent output. Output readiness is evidence only; no bare `ready` state is claimed.

## Security Model

- The daemon binds only to `127.0.0.1` on a random port.
- Each RPC requires the bearer token in the private per-user daemon descriptor.
- The daemon persists metadata and output under `PTY_DAEMON_DIR`, or the user state directory by default.
- Every non-health RPC carries a capability derived by the plugin from a private, persistent daemon ownership secret, OpenCode session ID, and canonical project directory. A session can only be listed, read, written, waited on, stopped, or deleted by that same owner context. Knowing an ID is insufficient. The secret is private to the daemon data directory; removing it deliberately revokes access to existing records, so retain it during backup/recovery and rotate only when that revocation is intended.
- `session.deleted` stops only that owner's `conversation` sessions. `persistent` sessions remain until their owner explicitly stops them. The daemon itself survives plugin/OpenCode restarts; active sessions become `lost` if the daemon restarts.
- Environment defaults to a small platform/project-safe allowlist plus explicitly supplied variables. Set `inheritEnv: true` only when the command needs the daemon environment. Raw environment values are never persisted: records retain only profile kind, redacted key markers, and a fingerprint. Output replaces values of obvious secret-named environment variables with `[REDACTED]`.
- Browser-facing APIs, WebSockets, and slash commands are intentionally not provided.

The installed OpenCode plugin SDK (1.3.13) exposes config reads and permission hooks, but no callable evaluator or prompt request API for a tool. Before spawn, this plugin applies a local matcher to `permission.bash`: only an explicit matching `allow` permits a command; absent, unmatched, `ask`, unreadable, and `deny` rules deny it. External directories use canonical containment and require explicit scalar `permission.external_directory: "allow"`; absent, object, `ask`, or `deny` rules fail closed. This is not an authoritative OpenCode permission invocation.

This tranche does not provide per-session worker processes, native Job Objects/cgroups, terminal emulation, browser UI, signed binaries, OS CPU/memory limits, or a native descendant-process termination guarantee. Bun limits session count per owner, PTY input size/rate, retained output, and exec runtime/output only.

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
| `PTY_DAEMON_DIR` | per-user state directory | Daemon descriptor, session metadata, and output. |
| `PTY_MAX_OUTPUT_BYTES` | `1000000` | Maximum retained output bytes per session. |

Output is an append-only, session-local UTF-8 chunk journal. Callbacks are coalesced into bounded 64 KiB UTF-8 segments and retained output is capped at the configured value (up to 64 MiB), so fragmented output cannot create unbounded files. Each chunk records its byte sequence range and timestamp. Retention removes whole oldest chunks, so `pty_read` reports `retained_from` and `truncated`; line offsets remain compatible, and durable byte sequences are available in output and RPC responses.

The daemon `diagnostics` RPC reports active Bun-enforced limits and explicitly reports that native containment and process-tree termination are unavailable. It intentionally exposes no secret values or global session data.

## Development

```bash
bun ci
bun typecheck
bun unittest
bun lint
bun format
bun build:prod
```

## License

MIT
