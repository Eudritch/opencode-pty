# Bun Daemon Implementation Plan

## 1. Define Daemon Contracts

Add `src/daemon/types.ts` with the versioned authenticated RPC request/response schema, durable session records, structured exit reasons, and manager-compatible read/search/write results. Use 128-bit `crypto.randomUUID()` session IDs and states from the approved design.

Add contract tests for response validation and explicit unknown exit reasons.

## 2. Add Durable Storage

Add `src/daemon/storage.ts` to resolve a per-user data directory, atomically write the daemon descriptor and session metadata, append output chunks, and enforce byte retention. Store each session in its own directory with JSON metadata and UTF-8 output chunks.

At startup, mark persisted live sessions as `lost`; preserve their output. Test retention, stale-session recovery, and descriptor replacement.

## 3. Implement Session Supervisor

Add `src/daemon/supervisor.ts` to own native worker references, durable session state, and output sequence cursors. It implements spawn, write, resize, read, search, list, get, stop, and parent-session cleanup.

Writes return accepted UTF-8 byte and character counts or throw structured failures. Stops distinguish requested termination from confirmed PTY exit and do not clean a running record. Exit callbacks persist exact code, signal, timeout, or unknown reasons.

Add native PTY integration tests for persistence, writes, timeout, stop confirmation, cleanup rules, and parent cleanup.

## 4. Implement Authenticated Daemon RPC

Add `src/daemon/server.ts` and `src/daemon/main.ts`. Bind Bun HTTP only to `127.0.0.1` on a random port, require an `Authorization: Bearer` token on every `/rpc` request, enforce request-size and protocol-version limits, and create the descriptor only after the server is listening.

Add test-only startup support so daemon integration tests can use an isolated data directory. Test authentication rejection, protocol mismatch, and request dispatch.

## 5. Replace The Plugin Singleton

Replace `src/plugin/pty/manager.ts` with a daemon client facade that retains the manager-shaped methods used by the tool adapters. Add `src/plugin/pty/daemon-client.ts` to discover/start the daemon, issue authenticated RPC requests, and surface structured failures. Tool calls become asynchronous where required.

Move exit notifications out of the former manager and defer them rather than silently fabricating daemon event delivery. The plugin still initializes permissions and calls daemon parent-session cleanup on `session.deleted`.

Remove the private `Terminal.prototype` monkey patch, callback arrays, `SessionLifecycleManager`, `OutputManager`, and in-memory `RingBuffer` from production use.

## 6. Correct Tool Semantics

Update the `pty_*` tools to await the daemon facade:

- `pty_spawn` keeps authoritative spawn permission checks.
- `pty_write` stops parsing terminal input as shell commands and reports UTF-8 accepted bytes.
- `pty_read` preserves line-offset compatibility while exposing the retained sequence cursor in output metadata.
- `pty_kill` states whether termination was confirmed and permits cleanup only after exit.
- `pty_list` renders the expanded state/exit details.

Update tool descriptions and README language so no documentation promises a browser control plane, persistent PTY reattachment, or verified process-tree termination.

## 7. Remove The Insecure Web Plane

Remove slash-command registration, the `open` dependency, the server export alias, Vite/web build scripts and dependencies, the `src/web` source tree, and HTTP/WebSocket tests. Keep the package focused on authenticated local daemon RPC through OpenCode tool adapters.

## 8. Verification

Run focused daemon and tool tests, then `bun typecheck`, `bun lint`, `bun format`, `bun unittest`, and the production build. Validate `npm pack` structure tests after changing the package entry points. Record any platform limitations in the README.
