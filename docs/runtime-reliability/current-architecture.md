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

The three layers are justified by distinct trust and failure boundaries, but responsibility is not yet consistently singular. The target architecture must retain only the parts of each layer that require that boundary.

## Current Responsibility Map

| Component | Owns today | Evidence | Assessment |
| --- | --- | --- | --- |
| Plugin | Host permission evaluation, workdir preflight, owner context, tool output, TUI approval bridge | `src/plugin.ts`, `src/plugin/pty/permissions.ts`, `src/plugin/pty/tools` | Essential adapter. Tool-side `get` preflights duplicate daemon checks but are non-authoritative. |
| Daemon server | Loopback transport, bearer auth, RPC validation, owner capability validation, per-owner session/input limits | `src/daemon/server.ts` | Essential control-plane role. `dispatch` has 33 cyclomatic complexity and mixes routing, validation, approvals, and session control. |
| Supervisor | Records, worker references, recovery, finalization queues, reads/waits, lifecycle mapping | `src/daemon/supervisor.ts` | Necessary responsibilities, but 1,738 lines and duplicate exec path indicate accidental aggregation. |
| Storage | Private directory, DACL/POSIX permissions, daemon descriptor/locks, V0/V1 metadata decoding, inert unsupported-record handling, journal read/migration | `src/daemon/storage.ts` | Essential persistence boundary, but it also owns platform process-identity probing. |
| Native worker | Prepared authenticated bootstrap, start-frame-gated spawn, terminal/pipe I/O, redaction, journal writing, timeout/stop, platform containment | `worker/src/main.rs`, `src/daemon/worker-client.ts` | The durable pre-activation reference checkpoint closes one lost-worker window; the mixed-platform engine remains hard to audit. |
| Native child | Actual command, shell, TTY behavior | OS | Must remain the sole process being described by PID and exit result. |

## Execution Modes

| Mode | Public entry | Current engine | Required semantics | Recommendation |
| --- | --- | --- | --- | --- |
| PTY | `pty_spawn`, then `write/read/wait/resize/kill` | Native worker controlling terminal or ConPTY | Interactive prompts, TTY detection, terminal size, merged terminal I/O | Keep only for genuine terminal workloads. |
| Exec | `shell_exec`, optional `execStart/execWait` | Native worker on supported route | Direct argv, separate stdout/stderr, finite timeout, no terminal emulation | Keep. Never silently turn direct argv into a shell. |
| Experimental Bash | `bash` opt-in | Native exec wrapping host shell | Opaque native-shell compatibility behavior | Keep default-off and separate from structured argv. |
| Legacy exec | `SessionSupervisor.exec()` | `Bun.spawn` in daemon | Direct process with daemon-side collectors | Delete after external-use confirmation. Server dispatch uses `nativeExec`, not this path. |

## Lifecycle as Implemented

`DaemonStatus` currently permits `starting`, `running`, `stopping`, `exited`, `timed_out`, `lost`, `spawn_failed`, and `output_limited` (`src/daemon/types.ts:19-27`). `SessionRecord` then stores independent booleans for timeout, termination requested/confirmed, direct-child exit, pending cleanup, output truncation, and optional containment/termination reports (`src/daemon/types.ts:200-251`).

**Inference:** This permits logically awkward combinations, such as a record that is `lost` yet has a confirmed direct-child exit, or a terminal status whose cleanup is pending. The fields are useful observations but should not all be independently mutable lifecycle state.

Current transitions include:

```text
starting -> running -> stopping -> terminal outcome -> cleaned
starting -> spawn_failed | lost
running  -> timed_out | output_limited | exited | lost
```

`src/daemon/lifecycle.ts` now supplies a pure reducer for the persisted status names. `SessionSupervisor.transition()` is the status-mutation gateway, and rejected snapshot transitions return before they can overwrite newer facts. `persistQueue`, `nativeFinalizations`, and `pendingConversationCleanup` still serialize I/O and cleanup (`src/daemon/supervisor.ts`), so the final discriminated persisted state model remains future Phase 1 work.

## Confirmed Problems

| Severity | Finding | Evidence | Root cause family |
| --- | --- | --- | --- |
| High | Windows ConPTY behavior has only one-host validation | Initial local `bun package:smoke` failure; guarded local package contract then passed 20/20 | Platform launch behavior needs the published Windows-version matrix and close-order evidence. |
| Medium | Persisted state is still status plus mutable observations | `src/daemon/types.ts:17-240`; reducer in `src/daemon/lifecycle.ts` | The reducer prevents known regressions, but a discriminated persisted terminal/tombstone model is not implemented yet. |
| High | Worker-RPC-loss fallback kills only the worker PID | `WorkerClient.terminateOrphan` at `src/daemon/worker-client.ts:604-640`; POSIX child is in a separate session | Descriptor retention now preserves later reaping evidence, but orphan cleanup cannot claim child containment after control-plane loss. |
| Medium | Each create path calls `supervisor.list`, which snapshots every native worker | `DaemonServer.withSessionSlot` at `src/daemon/server.ts:1001-1019`; `SessionSupervisor.list` at `1220-1229` | Admission control is coupled to global liveness polling. |
| Medium | Direct Bun exec duplicates native exec | `SessionSupervisor.exec` at `554-747`; supported RPC calls `nativeExec` | Two lifecycle implementations for one product capability. |
| Medium | `Symbol.dispose` only stops the HTTP server while `stop` also flushes/removes descriptor | `src/daemon/server.ts:124-133` | Shutdown has two unequal public paths. |
| Medium | Worker journal sharing-violation policy differs from daemon metadata writes | `worker/src/main.rs`; `src/daemon/storage.ts:130-155` | Standard atomic rename is validated locally, but worker journal writes do not share daemon retry classification. |

## Phase 0 Update

The initial Windows ConPTY failure is resolved locally. The retained `PseudoConsoleStdioGuard` scopes temporary parent console standard handles to `CreateProcessW` in the dedicated one-child worker. Disabling only the guard fails both live ConPTY tests; restoring it passes live and fresh-package tests. The prior partial-output symptom did not establish a Windows journal replacement defect: the standard `std::fs::rename` replacement behavior is directly tested and retained.

This is one-host evidence, not a portable ConPTY conclusion. The raw fixture and the published Windows version matrix remain required before changing the release claim.

The Phase 0 full-suite run also found a separate exec fault-path ambiguity. The worker had already reported a journal storage failure, but TypeScript could return a generic no-terminal-evidence error when containment was still unresolved. `finishNativeVersion()` now preserves the actionable `ESTORAGE` category for a worker `storageFailure`; the session is still recorded as `lost`. Its integration test now uses an explicit file gate instead of a 200 ms child timer.

## Phase 1 Update

The reducer accepts the existing persisted status vocabulary and rejects stale regressions, including `stopping -> running`. A rejected worker snapshot is fully inert: it cannot overwrite termination, exit, output, or containment facts. An authenticated `lost -> recovered -> running` transition exists only in persistent recovery after a fresh non-lost worker snapshot; ordinary worker-ready snapshots cannot revive a tombstone.

Idempotent PTY reuse now requires the complete owner identity: parent session, canonical project directory, capability hash, canonical workdir, key, and matching specification. It no longer relies on an undocumented host session-ID uniqueness property.

`DaemonServer.start()` marks active or lost conversation sessions for cleanup before it publishes the daemon descriptor. Persistent records may reconnect and retry after an unreachable observation; marked conversations reconnect only for cleanup. Cleanup retains a tombstone unless an authenticated shutdown plus explicit direct-child and containment evidence proves it safe to delete. That same proof gate applies to persisted terminal records. Owner deletion retries tombstones rather than silently discarding their worker descriptor or journal. A memory-only cache now distinguishes a session that already completed a strict worker shutdown in the running daemon from a crash-recovered terminal record: normal finalization can delete without a redundant reconnect, while restart paths still require a fresh authenticated shutdown.

The current worker start path has a durable pre-activation checkpoint. `WorkerClient.prepare()` verifies the bootstrap-ready descriptor while the worker remains blocked on the inherited start/rollback pipe. The supervisor persists that verified reference before `client.start()` sends the frame that permits child creation. Health and snapshots remain post-start because the worker HTTP listener does not exist before the child is created. Reference-persistence failure rolls the prepared worker back without activating the command. On rollback or EOF before any valid `start`, the worker writes `prestart-no-child.json`; recovery accepts it only when its worker identity, endpoint, protocol, and token hash match the persisted reference. It never treats this receipt as evidence after `start`. A distinct retained `spawn-failure.json` plus `worker.json` now proves the narrower post-start case where `start` was accepted but no direct child was created, and that proof is recoverable only for a full compatible worker reference.

New records are strict V1 metadata. Before any validation, journal migration, or recovery, storage decodes an unversioned V0 record. A V0 record needs a canonical owner tuple with a lowercase SHA-256 capability hash, explicit `directChildExited`, and explicit drained containment before it is rewritten as V1 terminal metadata. A V0 record that was live, lost, or only terminal-looking becomes a `lost` conversation tombstone with `pendingCleanup`, retains `output.log`, and cannot re-enter ordinary recovery or idempotent reuse. A proven terminal import persists a cleanup marker before removing `output.log`; V1 retries removal after a crash/failure. Null, incomplete, or unknown-version owner artifacts are skipped in place without rewriting or quarantining the source artifact, so they cannot block healthy session loading. Descriptor deletion is now atomic with session-directory deletion: unconfirmed startup rollback or failed deletion retains `worker.json`, and authenticated orphan reaping remains possible. Worker references with an incompatible protocol are similarly retained as read-only tombstones and are never reconnected, signaled, or orphan-killed. This is a compatibility fence, not the final discriminated persisted-state model.

## What Is Essential Versus Accidental

**Essential:** authenticated loopback boundaries; owner-bound capabilities; direct argv by default; native Windows Job containment; direct-child versus descendant distinction; output redaction before persistence; bounded output retention; process identity checks before a PID action; recovery after a daemon/plugin restart.

**Accidental or reducible:** a legacy execution path; global session snapshots on admission; lifecycle truth spread across status plus booleans plus queues; worker-specific filesystem retry logic differing from storage; broad supervisor aggregation; cleanup semantics driven by `lost` rather than evidence of control and containment.
