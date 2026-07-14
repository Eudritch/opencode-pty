# Bun Daemon Design

## Goal

Replace the plugin-process PTY singleton with a per-user Bun daemon. The daemon owns live PTYs, session state, output, and lifecycle. The OpenCode plugin becomes a small authenticated client that preserves the existing `pty_*` tools.

The release provides deterministic control semantics where possible: idempotent daemon startup, stable output cursors, explicit state transitions, and no fabricated write, exit, or termination success.

## Non-goals

- Native service binaries, Windows Job Objects, POSIX process-group containment, cgroups, or verified descendant termination.
- A browser UI, REST API, or WebSocket endpoint.
- Per-keystroke authorization for an interactive terminal.
- Reattaching to a PTY after the daemon itself exits. A restarted daemon records prior sessions as lost rather than claiming recovery.
- `shell_resize` and a persistent `shell` command parser.

## Architecture

```text
OpenCode plugin
  -> authenticated loopback RPC
Per-user Bun daemon
  -> bun-pty sessions
  -> session metadata and output journal on disk
```

The plugin starts the daemon if a health-checked connection is unavailable. The daemon binds only to `127.0.0.1` on an ephemeral port. Its endpoint and a cryptographically random bearer token live in a per-user daemon descriptor. The plugin reads that descriptor, sends the token on every request, and rejects a daemon with an incompatible protocol version.

The descriptor is created atomically. It contains the daemon process ID, endpoint, protocol version, and token. Stale descriptors are replaced only after their daemon is unreachable. The daemon validates the token before parsing or dispatching every RPC operation. It never exposes an HTTP browser interface.

The daemon remains running when an OpenCode plugin instance exits, so plugin and OpenCode restarts do not terminate active sessions.

## Ownership And Policy

Each spawn records the originating OpenCode session ID, optional agent, and working directory. Existing tools keep global daemon visibility to preserve current behavior; this release does not claim cross-conversation isolation.

The protocol has two execution modes. `pty` is interactive and is used by the existing `pty_spawn`; `exec` runs one finite structured argv command through Bun pipes and returns separate stdout and stderr. There is no fake persistent shell parser. Plugin permission and canonical-workdir checks run before either mode starts a process.

An optional PTY idempotency key is scoped by originating OpenCode session and canonical workdir. It reuses only an active PTY with identical command, args, environment, timeout, and name. A collision with a changed specification fails rather than silently attaching to another process.

The plugin continues to evaluate spawn permissions using OpenCode integration before sending a spawn request. A successful interactive spawn is an explicit grant to control that terminal. `pty_write` does not parse or attempt to authorize terminal input as shell commands.

When OpenCode emits `session.deleted`, the plugin asks the daemon to stop sessions owned by that OpenCode session. This is a termination request, not a confirmed process-tree guarantee.

## RPC Contract

The daemon exports a small versioned request/response protocol:

```text
health
spawn
write
read
search
list
get
stop
cleanupByParentSession
exec
wait
sendWait
```

Every response contains a request ID and either a result or a structured error. Errors distinguish authentication, validation, not-found, session-closed, process, storage, and internal failures. RPC requests have bounded body sizes and timeouts.

The existing OpenCode tool names and inputs remain unchanged. Their responses may add truthful fields but do not remove current fields. The legacy `cleanup` option remains supported; cleanup only deletes an already-exited session record. It does not discard a live session immediately after requesting stop.

## Session And Lifecycle Model

Sessions have 128-bit random IDs and the following states:

```text
starting
running
stopping
exited
timed_out
lost
spawn_failed
```

Every state change is persisted with a timestamp and optional structured exit reason. Exit reasons are one of `code`, `signal`, `timeout`, `spawn_error`, or `unknown`. An absent exit code remains unknown; it is never converted to zero.

`stop` changes a running session to `stopping`, requests the PTY backend termination, and returns `requested: true`. It returns `terminationConfirmed: true` only after the PTY exit callback arrives. If the callback has not arrived before the request deadline, the session remains `stopping` and the response says `terminationConfirmed: false`.

`write` returns accepted byte and character counts only after `bun-pty` accepts the write. Exceptions and closed sessions produce failures. It never converts an exception into success.

Timeouts are persisted as `timed_out` before termination is requested. The daemon uses monotonic deadlines internally where Bun supplies them; persisted timestamps are wall-clock diagnostics only.

Wait conditions are daemon-side and deadline-bound: process exit, output literal, or a limited-safe regex over retained output. Wait results record whether they were satisfied, the observed output/exit evidence, truncation state, and timestamp. There is no unproven `ready` state. Regexes are deliberately limited to a 512-character non-quantified, non-grouping subset, with no backreferences.

Finite exec records mode, timestamps, exact available stdout/stderr, exit result, timeout, and output-limit evidence. Pipe output has a bounded per-stream limit; a limit breach kills the child and reports `output_limited` rather than pretending the result is complete.

## Durable Storage And Recovery

The daemon stores one session record and append-only output chunks per session in its per-user data directory. A chunk has an increasing session-local sequence number, timestamp, and UTF-8 text. Output is written before the corresponding cursor is reported.

Reads use stable sequence cursors instead of mutable line offsets internally. The compatibility `pty_read(offset, limit)` adapter derives lines from the persisted stream and includes the current cursor/truncation metadata. Search runs over persisted normalized text and returns stable output sequence positions in addition to compatibility line numbers.

At daemon startup, persisted sessions previously marked `starting`, `running`, or `stopping` are marked `lost`, because this Bun daemon cannot safely reclaim PTY handles after its own restart. Their retained output remains readable. This release never misrepresents a lost process as exited or killed.

Output retention is capped by a single configurable per-session byte limit. When old chunks are removed, the daemon persists the earliest retained sequence and a truncation marker. This is deliberately a simple byte-retention policy; time- and disk-wide retention are deferred.

## Plugin Changes

`src/plugin.ts` initializes a daemon client rather than the process-global PTY manager. Tool modules call the client through the same minimal manager-shaped interface during the migration. Notification behavior remains plugin-owned because only the plugin has the OpenCode client; it consumes daemon exit events when this can be done without synthetic polling.

The current Bun web server, browser commands, REST routes, and WebSocket callback bridge are removed from the plugin registration for this release. Removing an unauthenticated command/control surface is preferable to retaining it behind incomplete authorization.

## Testing

Focused tests must cover:

- daemon startup, stale descriptor replacement, authentication rejection, and protocol mismatch;
- spawn, output persistence, read-after-plugin-client recreation, and stable sequence cursors;
- write failure reporting and UTF-8 byte counting;
- exit reasons, unknown exits, timeouts, stop-request versus stop-confirmed behavior, and cleanup only after exit;
- daemon restart marking live records as `lost` while preserving output;
- plugin permission checks before spawn and parent-session cleanup requests.

Existing PTY integration tests remain the backend smoke tests. Web HTTP/WebSocket tests are removed with the web surface.

## Explicitly Deferred

- A secure human web client can be added later as a daemon client with a one-time capability token, origin validation, and operation-specific capabilities.
- Resize, terminal-screen emulation, session aliases, resource limits beyond finite exec output, secret redaction, and worker isolation each require independent design.
- Native containment and a signed platform daemon replace `bun-pty` only when their platform matrix and verification requirements can be tested.
