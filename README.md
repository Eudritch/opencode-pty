# opencode-pty

An OpenCode plugin for durable interactive PTY sessions and finite argv execution. It requires Bun 1.3.8 or later. Every process is owned by a per-session native worker from the matching installed optional package; unavailable workers fail closed.

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
| `pty_resize` | Resize a running native PTY. |
| `bash` | Foreground Bash-compatible shell command, rendered as OpenCode Bash. |

`pty_write` accepts terminal input, not a new command invocation. Permission checks therefore happen at `pty_spawn`, not per keystroke.

`notifyOnExit` remains accepted for compatibility but is rejected: the durable daemon has no safe event channel back into a completed OpenCode session.

`shell_exec` is `exec` mode, not a shell parser: `command` and `args` are passed as argv and a positive timeout is required. A Rust per-session worker owns every child, exposes an authenticated loopback RPC endpoint, and writes redacted output to the existing session chunk journal. The daemon resolves its platform-specific worker from the installed package, so no repository path is required. The daemon can reconnect to a reachable worker after restart and recover its output cursor and final state.

`bash` intentionally duplicates OpenCode's native Bash tool ID so compatible hosts render it with their native Bash UI. It is registered by default with `{command, workdir?, timeout?, description?}`; set the plugin option `{ "bash": false }` to retain all other tools without this override. This compatibility override requires an OpenCode host that permits duplicate tool IDs (the supported SDK baseline is 1.3.13); disable it if a future host rejects duplicates. It runs only a finite foreground shell: Windows uses `%ComSpec% /d /s /c`, while POSIX uses `/bin/sh -lc`; use `pty_spawn` for durable background work. `timeout` is milliseconds, defaults to 120000, and rounds down to the daemon's whole-second timeout (sub-second values are rejected).

The raw Bash command is opaque. Permission matching evaluates the complete original string under `bash`; it never authorizes the generated shell executable argv. Its path arguments cannot be statically scoped. An explicit `workdir` is canonicalized and still requires `external_directory` permission outside the project. `ask` creates a durable one-shot request, uses native `ctx.ask`, and consumes it only after that prompt succeeds; it never creates a session grant.

`pty_spawn` is `pty` mode and remains interactive. Unix workers use a real controlling terminal with merged redacted UTF-8 terminal output; `pty_resize` changes its columns and rows. There is no screen emulator, raw byte API, or screen snapshot. A supplied `idempotencyKey` reuses only a matching active PTY scoped to the originating OpenCode session and canonical workdir; changing command, args, environment, timeout, or name is rejected. Titles and descriptions are presentation fields and do not affect reuse. `pty_wait` conditions are literal output, a limited-safe regex, or exit. They run in the daemon against output/exit events with a 3600-second maximum deadline, not plugin polling. `pty_send_wait` captures its output boundary immediately after PTY input is accepted, so earlier output cannot satisfy the wait while an immediate reply can. Output readiness is evidence only; no bare `ready` state is claimed.

## Security Model

- The daemon binds only to `127.0.0.1` on a random port.
- Each RPC requires the bearer token in the private per-user daemon descriptor.
- The daemon persists metadata and output under `PTY_DAEMON_DIR`, or the user state directory by default.
- On Windows, the daemon replaces and verifies the `PTY_DAEMON_DIR` DACL before creating its ownership secret or descriptor. It grants Full Control only to the current user SID and LocalSystem; every daemon directory and sensitive file inherits only those ACEs. This applies to a custom `PTY_DAEMON_DIR` too. If the DACL cannot be applied or verified, daemon startup fails closed.
- Every non-health RPC carries a capability derived by the plugin from a private, persistent daemon ownership secret, OpenCode session ID, and canonical project directory. A session can only be listed, read, written, waited on, stopped, or deleted by that same owner context. Knowing an ID is insufficient. The secret is private to the daemon data directory; removing it deliberately revokes access to existing records, so retain it during backup/recovery and rotate only when that revocation is intended.
- `session.deleted` stops and removes only that owner's `conversation` sessions, including native exec records. `persistent` sessions remain until their owner explicitly stops and cleans them up. Controlled daemon restarts reconnect only workers whose descriptor, endpoint, token fingerprint, and authenticated health identity all match; incompatible records remain lost and readable. Exec workers enforce their direct-child timeout and aggregate output limit; PTYs have no worker deadline unless one is supplied and discard oldest journal output at the configured aggregate retention cap. A worker terminal result is complete only after its direct child exits and both stdout/stderr readers reach EOF; a bounded reader-drain timeout reports incomplete output as unknown rather than complete. `directChildExited` is direct-child evidence, not descendant containment evidence.
- Environment defaults to a small platform/project-safe allowlist plus explicitly supplied variables. Set `inheritEnv: true` only when the command needs the daemon environment. Raw environment values are never persisted: records retain only profile kind, redacted key markers, and a fingerprint. Output replaces values of obvious secret-named environment variables with `[REDACTED]` before PTY journal or exec output persistence. The streaming redactor retains at most 4095 UTF-8 characters (secret values are capped at 4096 bytes), so ordinary trailing output can wait for a later callback or process exit.
- Browser-facing APIs, WebSockets, and slash commands are intentionally not provided.

The installed OpenCode plugin SDK (1.3.13) exposes config reads and permission hooks, but no callable evaluator or prompt request API for a tool. Before every `pty_spawn` and `shell_exec`, this plugin reads OpenCode's merged config and locally applies the documented ruleset: global `permission` rules are evaluated in declaration order, then `agent.<agent>.permission` rules in declaration order, with the last matching rule winning. Thus an agent deny overrides a global allow, and an agent allow overrides a global deny. Only an effective matching `allow` permits a command; absent, unmatched, `ask`, unreadable, malformed, and `deny` rules deny it. Rules match the executable followed by the complete argv using OpenCode wildcards. External directories use canonical containment and require an effective matching `external_directory` allow for the resolved path. This is not an authoritative OpenCode permission invocation.

On Linux native exec and PTY children run in a fresh POSIX session/process group. Timeout, output caps, rollback, and stop signal only the owned direct-child handle with `SIGTERM`, then `SIGKILL` after a bounded grace period; they never signal a numeric process group, which could be reused. Linux reports `/proc` session/group scans as evidence only; only `posix_best_effort_empty` means a successful scan observed no remaining attributable members. A child can call `setsid`; observed escapes and survivors prevent containment confirmation. macOS uses libproc start-time identity plus authenticated health for worker recovery, but has no descendant verification: normal direct-child exit is terminal/readable/cleanable after output drain while containment remains `posix_containment_unknown`; stop and timeout do not claim descendant termination. Windows native exec and PTY children are created suspended, assigned to a non-breakaway Job Object with `KILL_ON_JOB_CLOSE`, then resumed. Windows PTYs use ConPTY with merged terminal IO and resize support. `windows_job_empty` means a bounded post-termination Job accounting query observed no active assigned processes; a deadline reports processes remaining and a query failure reports unknown, never confirmed. This does not provide cgroups, terminal emulation, signed binaries, or OS CPU/memory limits.

## Setup

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-pty"]
}
```

## TUI Companion

The default `opencode-pty` entry remains the server plugin. The optional TUI companion adds a compact `sidebar_content` panel for PTYs owned by the active OpenCode session and a `PTY approvals` command for reviewing pending requests and revoking session-scoped grants. It fetches the routed session through the supported OpenCode client API, then requires its canonical directory to match `api.state.path.directory`; it shows nothing and performs no approval action when that check fails. It does not use a directory fallback. It is a companion only: it does not replace OpenCode's transcript renderer or the inline native Bash card.

When a host installs package targets explicitly, load both target-exclusive entries:

```json
{
  "plugin": ["opencode-pty/server", "opencode-pty/tui"]
}
```

The root entry preserves legacy server behavior. The TUI never takes over a Bash approval race; the server's native `ctx.ask` prompt remains authoritative. Set `{ "bash": false }` on the server entry to keep PTY tools without the Bash compatibility override.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PTY_DAEMON_DIR` | per-user state directory | Daemon descriptor, ownership secret, session metadata, and output; protected with the same restrictive DACL on Windows. |
| `PTY_MAX_OUTPUT_BYTES` | `1000000` | Maximum retained output bytes per session. |
| `PTY_NATIVE_WORKER_ENABLED` | unset | Retained for compatibility; native workers are always required. |
| `PTY_NATIVE_WORKER_PATH` | unset | Explicit worker executable override. The default resolves the matching installed optional package. |
| `PTY_NATIVE_WORKER_DEV` | unset | Set only in development to run `cargo run --manifest-path worker/Cargo.toml`; never a production fallback. |

Output is an append-only, session-local UTF-8 chunk journal. Callbacks are coalesced into bounded 64 KiB UTF-8 segments and retained output is capped at the configured value (up to 64 MiB), so fragmented output cannot create unbounded files. Each chunk records its byte sequence range and timestamp. Retention removes whole oldest chunks, so `pty_read` reports `retained_from` and `truncated`; line offsets remain compatible, and durable byte sequences are available in output and RPC responses.

The daemon `diagnostics` RPC reports the native PTY/exec containment capability and platform verification source.

## Native Worker Packages

Native workers are packaged as matching optional npm dependencies for `linux-x64-gnu`, `linux-arm64-gnu`, `win32-x64`, `win32-arm64`, `darwin-arm64`, and `darwin-x64`. The Windows worker requires Windows 10 version 1809 or later for ConPTY. Linux workers require glibc; Alpine/musl is rejected before execution unless `PTY_NATIVE_WORKER_PATH` supplies a compatible worker. `npm` installs only the package matching its `os` and `cpu`; the main `opencode-pty` tarball contains no worker binary. If the matching optional package was omitted or the platform is unsupported, native PTY and exec fail closed.

Release assembly accepts exactly those six worker archives. It validates archive name, package version, `os`/`cpu`, worker binary, SHA-256 checksum, release SHA, and GitHub workflow provenance before signing and before each publish/resume step. The manifest and its Cosign signature are verified with one protected public key source (`NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY` or `NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY_FILE`); no public key is committed because no valid release key is present in this repository.

Releases require protected GitHub environments, matching native runners (`ubuntu-24.04`, `ubuntu-24.04-arm`, `windows-2025`, `windows-11-arm`, `macos-14`, and `macos-13`), npm trusted publishing, and Cosign private/public key material. Windows releases additionally require a PFX certificate, password, and RFC3161 timestamp URL. macOS releases additionally require a Developer ID identity plus App Store Connect API key credentials that the workflow imports into a temporary keychain/notary profile. Missing credentials, a mismatched runner architecture, unavailable artifacts, failed signing/notarization, or invalid registry integrity stops the release before root-package publication. GitHub runner labels and protected credentials are external release prerequisites; this repository cannot validate them locally.

## Development

```bash
bun install --frozen-lockfile
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
