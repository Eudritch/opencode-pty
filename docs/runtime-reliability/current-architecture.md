# Current Architecture and Ownership

**Status:** Partially verified

## Topology

```text
OpenCode host
  -> plugin tools: policy, owner context, display
  -> loopback daemon: bearer auth, owner authorization, registry, quotas
  -> one native worker per session: child creation, PTY/pipe I/O, journal, stop
  -> child process and its platform containment mechanism
```

The three layers are justified by distinct trust and failure boundaries. Phase 2 makes control-plane ownership explicit; Phase 1 has cut over persisted state, bounded registry-owned resources, and added local crash-cutover evidence.

## Current Responsibility Map

| Component | Owns today | Evidence | Assessment |
| --- | --- | --- | --- |
| Plugin | Host permission evaluation, workdir preflight, owner context, tool output, TUI approval bridge | `src/plugin.ts`, `src/plugin/pty/permissions.ts`, `src/plugin/pty/tools` | Essential adapter. Tool-side `get` preflights duplicate daemon checks but are non-authoritative. |
| Daemon server | Loopback transport, bearer auth, RPC validation, owner capability validation, ingress rate limit, and quota diagnostics | `src/daemon/server.ts` | Essential control-plane role. `dispatch` has 33 cyclomatic complexity and mixes routing, validation, approvals, and session control. |
| Supervisor | Recovery, native lifecycle orchestration, waits, and public daemon facade | `src/daemon/supervisor.ts` | Coordinates collaborators without owning their maps. Native lifecycle remains deliberately local until the Phase 3 engine boundary narrows. |
| Session registry | Session records, full-owner identity checks, active/durable/output reservations, wait permits, and queued-input permits | `src/daemon/session-registry.ts` | No worker RPC. Uncertain/lost records retain capacity and their full output reservation until strict proof or durable deletion. |
| Session router | Live worker references, owner-route checks, snapshot-version fences, persistence queue, and mutation lane | `src/daemon/session-router.ts` | No metadata quota logic. Its ordered queues retain the controller-lane and persistence-deadlock invariants. |
| Journal reader | Output loading, line paging, literal search, and raw output | `src/daemon/journal-reader.ts` | Read-only output boundary; it cannot mutate session state or contact workers. |
| Storage | Private directory, DACL/POSIX permissions, daemon descriptor/locks, V0/V1/V2 metadata decoding, inert unsupported-record handling, journal read/migration | `src/daemon/storage.ts` | V2 is the only writer; this remains the essential persistence boundary and also owns platform process-identity probing. |
| Native worker | Prepared authenticated bootstrap, start-frame-gated spawn, terminal/pipe I/O, redaction, journal writing, timeout/stop, platform containment | `worker/src/main.rs`, `src/daemon/worker-client.ts` | Sensitive bootstrap values are capped at 4,096 UTF-8 bytes and worker stderr is bounded/redacted; the mixed-platform engine and synchronous native input path remain hard to audit. |
| Native child | Actual command, shell, TTY behavior | OS | Must remain the sole process being described by PID and exit result. |

## Execution Modes

| Mode | Public entry | Current engine | Required semantics | Recommendation |
| --- | --- | --- | --- | --- |
| PTY | `pty_spawn`, then `write/read/wait/resize/kill` | Native worker controlling terminal or ConPTY | Interactive prompts, TTY detection, terminal size, merged terminal I/O | Keep only for genuine terminal workloads. |
| Exec | `shell_exec`, optional `execStart/execWait` | Native worker on supported route | Direct argv, separate stdout/stderr, finite timeout, no terminal emulation | Keep. Never silently turn direct argv into a shell. |
| Experimental Bash | `bash` opt-in | Native exec wrapping host shell | Opaque native-shell compatibility behavior | Keep default-off and separate from structured argv. |

## Lifecycle as Implemented

`session.json` is V2-only: its single `state` discriminant is `creating`, `running`, `stopping`, `terminal`, `unreachable`, or `cleaning`. Terminal payloads retain direct-child, drain, containment, and termination observations; an unproven terminal transition becomes `unreachable { lastKnown: terminal }` with that payload preserved. V0 and V1 decode into this representation, while the in-memory flat fields remain a non-persisted compatibility projection for the existing RPC shape.

Current transitions include:

```text
starting -> running -> stopping -> terminal outcome -> cleaned
starting -> spawn_failed | lost
running  -> timed_out | output_limited | exited | lost
```

`src/daemon/lifecycle.ts` supplies the pure V2 state reducer. `SessionSupervisor.transition()` refreshes observations, reduces V2 state, and only then projects status for compatibility; rejected snapshot transitions remain inert. `SessionRouter` owns a per-session controller lane for write, send-and-wait input acceptance, resize, stop, finalization, cleanup marking, and durable deletion; reads remain concurrent through `JournalReader`. Router persistence and mutation queues remain separate to avoid recursive finalization persistence deadlocks.

## Confirmed Problems

| Severity | Finding | Evidence | Root cause family |
| --- | --- | --- | --- |
| High | Windows ConPTY behavior has only one-host validation | Initial local `bun package:smoke` failure; guarded local package contract then passed 20/20 | Platform launch behavior needs the published Windows-version matrix and close-order evidence. |
| Medium | Budget defaults have only local functional evidence | `src/daemon/limits.ts`, `src/daemon/session-registry.ts` | Admission is bounded, but repeated pressure, disk-full, and multi-platform resource measurements remain Phase 4 work. |
| High | Worker-RPC-loss fallback kills only the worker PID | `WorkerClient.terminateOrphan` at `src/daemon/worker-client.ts:604-640`; POSIX child is in a separate session | Descriptor retention now preserves later reaping evidence, but orphan cleanup cannot claim child containment after control-plane loss. |
| Medium | Worker journal sharing-violation policy differs from daemon metadata writes | `worker/src/main.rs`; `src/daemon/storage.ts:130-155` | Standard atomic rename is validated locally, but worker journal writes do not share daemon retry classification. |

## Phase 0 Update

The initial Windows ConPTY failure is resolved locally. The retained `PseudoConsoleStdioGuard` scopes temporary parent console standard handles to `CreateProcessW` in the dedicated one-child worker. Disabling only the guard fails both live ConPTY tests; restoring it passes live and fresh-package tests. The prior partial-output symptom did not establish a Windows journal replacement defect: the standard `std::fs::rename` replacement behavior is directly tested and retained.

This is one-host evidence, not a portable ConPTY conclusion. The raw fixture and the published Windows version matrix remain required before changing the release claim.

The Phase 0 full-suite run also found a separate exec fault-path ambiguity. The worker had already reported a journal storage failure, but TypeScript could return a generic no-terminal-evidence error when containment was still unresolved. `finishNativeVersion()` now preserves the actionable `ESTORAGE` category for a worker `storageFailure`; the session is still recorded as `lost`. Its integration test now uses an explicit file gate instead of a 200 ms child timer.

## Phase 1 Update

V2 is the only persisted-session writer. Its pure reducer rejects stale regressions, including `stopping -> running`; a rejected worker snapshot is fully inert. The reducer retains a terminal payload when control becomes unreachable, and an authenticated `lost -> recovered -> running` projection exists only in persistent recovery after a fresh non-lost worker snapshot. Cleaning cannot revive a session.

Idempotent PTY reuse now requires the complete owner identity: parent session, canonical project directory, capability hash, canonical workdir, key, and matching specification. It no longer relies on an undocumented host session-ID uniqueness property.

`DaemonServer.start()` marks active or lost conversation sessions for cleanup before it publishes the daemon descriptor. Persistent records may reconnect and retry after an unreachable observation; marked conversations reconnect only for cleanup. Cleanup retains a tombstone unless an authenticated shutdown plus explicit direct-child and containment evidence proves it safe to delete. That same proof gate applies to persisted terminal records. Owner deletion retries tombstones rather than silently discarding their worker descriptor or journal. A memory-only cache now distinguishes a session that already completed a strict worker shutdown in the running daemon from a crash-recovered terminal record: normal finalization can delete without a redundant reconnect, while restart paths still require a fresh authenticated shutdown.

The current worker start path has a durable pre-activation checkpoint. `WorkerClient.prepare()` verifies the bootstrap-ready descriptor while the worker remains blocked on the inherited start/rollback pipe. The supervisor persists that verified reference before `client.start()` sends the frame that permits child creation. Health and snapshots remain post-start because the worker HTTP listener does not exist before the child is created. Reference-persistence failure rolls the prepared worker back without activating the command. On rollback or EOF before any valid `start`, the worker writes `prestart-no-child.json`; recovery accepts it only when its worker identity, endpoint, protocol, and token hash match the persisted reference. It never treats this receipt as evidence after `start`. A distinct retained `spawn-failure.json` plus `worker.json` now proves the narrower post-start case where `start` was accepted but no direct child was created, and that proof is recoverable only for a full compatible worker reference.

`SessionRegistry` now applies fixed limits before admission or mutation: 32 active sessions per owner and 64 globally; 64 durable records per owner and 128 globally; 8/32/128 pending waits by session/owner/daemon; 64 KiB/256 KiB/1 MiB queued input; and 64 MiB/128 MiB retained-output reservations. New records persist their effective per-session output cap. Active or unreachable records reserve their full cap; strict terminals reserve actual retained bytes. A terminal record becomes eligible for cleanup after 24 hours on a later admission attempt, but it is never force-deleted without the ordinary strict cleanup proof. `diagnostics` exposes limits plus owner/global usage.

The local cutover matrix combines deterministic pre-activation/reference/post-start/finalization tests with a source-daemon kill/restart test. The live-child case runs a persistent command with a durable marker, kills the daemon, reconnects the worker, and proves the marker has one start only. This is process-termination evidence on one Windows x64 host, not a power-loss or multi-platform claim.

## Phase 2 Update

The legacy `SessionSupervisor.exec()` and daemon-side collectors are deleted; public `exec` and `execStart` RPCs use the native worker path exclusively. `SessionSupervisor.list()` returns persisted metadata only, while `get()` and `execOutput()` refresh only their requested live worker.

Admission is owned by supervisor-local reservations keyed by the full owner identity: parent session, canonical project directory, and capability hash. A matching PTY idempotency request resolves before reservation, including at capacity. The first record-write failure releases immediately. After the first durable record, unknown/lost or unproven states retain capacity across restart; capacity releases only after strict terminal/no-child evidence or successful durable session deletion. No admission path snapshots another worker.

State-changing operations have a per-session controller lane. A write or send-and-wait reserves its input-acceptance position before a later resize or stop can run; terminal finalization and deletion are also serialized, so a stale queued monitor cannot finalize an already-released worker. `DaemonServer.stop()`, `Symbol.dispose`, and `Symbol.asyncDispose` share one idempotent shutdown path that stops the server, flushes supervisor persistence, and removes the owned descriptor once.

`SessionRegistry` owns the records and conservative full-owner admission slots. `SessionRouter` owns worker handles, owner-route checks, snapshot versions, and the ordered mutation/persistence queues. `JournalReader` owns all journal paging/search/raw reads. `SessionSupervisor` remains the narrow public facade and native lifecycle coordinator; it does not retain another record, quota, worker, or journal implementation.

Before validation, journal migration, or recovery, storage dispatches explicit V0, V1, and V2 decoders. V0/V1 records need a canonical owner tuple with a lowercase SHA-256 capability hash plus direct-child/containment proof to import as V2 terminal state with unknown stream drain. Live or unproven legacy records become forced-conversation cleanup-only V2 unreachable tombstones and retain legacy output. Explicit V0, future, incomplete, and null-owner artifacts are skipped in place without rewriting or quarantining the source artifact. A proven terminal import persists a cleanup marker before removing `output.log`; V2 retries removal after a crash/failure. Descriptor deletion is atomic with session-directory deletion: unconfirmed startup rollback or failed deletion retains `worker.json`, and authenticated orphan reaping remains possible. Incompatible worker references remain read-only tombstones and are never reconnected, signaled, or orphan-killed.

## What Is Essential Versus Accidental

**Essential:** authenticated loopback boundaries; owner-bound capabilities; direct argv by default; native Windows Job containment; direct-child versus descendant distinction; output redaction before persistence; bounded output retention; process identity checks before a PID action; recovery after a daemon/plugin restart.

**Accidental or reducible:** lifecycle truth spread across status plus booleans plus queues; worker-specific filesystem retry logic differing from storage; broad supervisor aggregation; cleanup semantics driven by `lost` rather than evidence of control and containment.
