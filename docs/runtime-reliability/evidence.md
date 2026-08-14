# Evidence Register

**Status:** Partially verified

## Scope and Versions

| Item | Value | Evidence |
| --- | --- | --- |
| Local revision | `3f568d018b974f9da9df758466fb6de4115a940d` | Local Git inspection, 2026-08-12 |
| Historical upstream | `https://github.com/shekohex/opencode-pty`, `upstream/main` at `cc12a2b` | Local Git remote and ref |
| Merge base | `65eee77` | Local Git inspection |
| Fork divergence | 137 files, +20,423/-8,844; local has 120 commits after upstream divergence | `git diff --stat upstream/main...HEAD` |
| Declared Bun minimum | `>=1.3.8` | `package.json:80-83` |
| Local Bun used for experiments | `1.3.14` | `bun --version` |
| Current OS for runtime experiments | Windows x64 | Local environment |
| Worker language/runtime | Rust native executable, one optional package per supported target | `worker/Cargo.toml`, `package.json:91-97` |

## Primary Sources

| Topic | Source |
| --- | --- |
| Bun child process and terminal API | https://bun.com/docs/runtime/child-process |
| Bun terminal API reference | https://bun.com/reference/bun/Terminal |
| Bun 1.3.5 POSIX terminal release | https://bun.com/blog/bun-v1.3.5 |
| Bun 1.3.14 Windows ConPTY release | https://bun.com/blog/bun-v1.3.14 |
| Windows ConPTY lifecycle | https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session and https://learn.microsoft.com/en-us/windows/console/closepseudoconsole |
| Windows Job Objects | https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects and https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject |
| Linux sessions | https://man7.org/linux/man-pages/man2/setsid.2.html |
| macOS sessions | https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setsid.2.html |
| `node-pty` support/security statement | https://github.com/microsoft/node-pty/blob/main/README.md |

## Local Experiments

| Experiment | Result | Classification | Follow-up |
| --- | --- | --- | --- |
| `bun typecheck` | Passed | Fact | Keep in PR gate. |
| `cargo test --locked --workspace` | Passed, 11 Windows-compiled tests | Fact | Unit tests do not prove the ConPTY integration path. |
| `bun unittest` | 152 passed, 16 skipped, 1 failed, 1 unhandled start-lock cleanup error after about 200 seconds | Fact | Isolate the claimed-start-lock test; add a deterministic lifecycle fixture. |
| `bun package:smoke` | Failed: packaged ConPTY `sendWait` did not observe echoed input | Fact | Phase 0 must establish the correct launch sequence. |
| Bun 1.3.14 terminal child | Windows child reports TTY and configured dimensions; output includes ConPTY initialization sequences | Fact | Bun has genuine Windows ConPTY support, not byte-identical terminal output. |
| Bun 1.3.14 direct `kill(SIGTERM)` | Direct child ended promptly in a local test | Fact, narrow | Does not demonstrate process-tree containment. |

## Phase 0 Update: Local Windows Baseline

The rows above record the initial failure baseline. The following supersedes them for the current worktree.

| Experiment | Result | Classification | Limit |
| --- | --- | --- | --- |
| ConPTY A/B after controlling for journal replacement | Disabling only `PseudoConsoleStdioGuard` made both live Windows ConPTY tests fail; restoring only the guard passed both | Fact | One Windows x64 host using Bun 1.3.14. |
| Current source checks | `cargo fmt --check`, `cargo test` (13 pass), `cargo clippy -D warnings`, `bun typecheck`, direct Bun 1.3.14 `bun test` (189 pass, 16 skip, 712 expectations), and script-entry Bun 1.3.6 `bun unittest` (189 pass, 16 skip, 712 expectations) passed | Fact | Local only; neither result establishes the declared Bun 1.3.8 minimum. |
| Final package contract | `bun package:smoke` passed from a fresh release-worker package 20 consecutive times | Fact | One Windows x64 host only. |
| Journal replacement control | The direct Windows test proves `std::fs::rename` replaces an existing journal chunk; no custom `MoveFileExW` wrapper is retained | Fact | Does not test antivirus/indexer contention. |
| Raw worker fixture | `windows_conpty_echo_resize_and_job_drain` uses production `windows_spawn`, `cmd /d /c more`, resize, nonce echo, `TerminateJobObject`, and Job drain; it passed locally | Fact | One Windows x64 host only. |

The claimed-start-lock test now uses a 30-second explicit test deadline because its Windows identity probes can each consume their own five-second operating budget. No retry was added.

The full-suite run also exposed an independent native-exec fault-injection race. The test replaced the journal directory while a child used a fixed 200 ms timer, so it could race startup, journal creation, and cleanup. It now gates child output on a test-owned file created only after the directory is replaced. Separately, a worker-reported `storageFailure` now remains an `ESTORAGE` error even when containment is not yet confirmed; the record still truthfully remains `lost`. Both the deterministic fault path and the unconfirmed-containment error mapping have focused regression coverage.

## Phase 1 Update: Local Lifecycle Slice

| Experiment | Result | Classification | Limit |
| --- | --- | --- | --- |
| Reducer and recovery subset | 15 focused Bun tests passed: stale snapshots, full-owner reuse, persistent retry/recovery, conversation cleanup, tombstone retention, and obsolete-worker terminal records | Fact | Local Windows x64 only. |
| Source suite | Direct `bun test` under Bun 1.3.14 passed 189 tests with 16 skips and 712 expectations | Fact | Does not establish the declared Bun 1.3.8 minimum. |
| Package recovery contract | Fresh packed-worker contract passed after its deliberate restart-survival exec was marked `persistent` | Fact | One Windows x64 host; no version/architecture matrix. |
| Rust worker checks | `cargo fmt --check`, 13 worker tests, and `cargo clippy -D warnings` passed | Fact | Windows host only. |
| V0/V1-to-V2 record migration | Raw V0/V1 proven terminals rewrite as V2 terminal state with unknown drain; live and unproven terminal records become non-runnable cleanup tombstones; explicit V0, future versions, and incomplete owner tuples fail in place without quarantine or rewrite | Fact | Local decoder/storage coverage, not a crash-point or historical-data corpus. |
| Migration audit regression | A healthy V1 record loads beside untouched future-version/incomplete-owner artifacts; unconfirmed rollback and failed directory deletion retain `worker.json`; incompatible worker references are never reconnected, signaled, or orphan-killed | Fact | Local mocked control-plane coverage; it does not prove a historical worker can be safely controlled. |
| Legacy terminal migration | V0 terminal status needs explicit direct-child plus containment evidence; unproven records become cleanup tombstones and retain `output.log`. Proven terminal imports persist a cleanup marker before removal, and V1 retries a failed removal on later load. | Fact | Focused storage coverage, not a crash-point matrix. |
| Owner-hash validation | V1 persistence and RPC owners require 64 lowercase hexadecimal SHA-256 values; malformed V0 hashes stay untouched/inert rather than producing an uncleanable tombstone. | Fact | Shape validation does not establish that old data has a current owner. |
| Unconfirmed worker startup | A deliberately stalled ready frame returns unconfirmed rollback, retains `worker.json`, then permits identity-verified orphan reaping. | Fact | One Windows x64 host and test-only daemon fault. |
| Pre-bind worker reference | A prepared worker did not execute a real marker command before its start frame. Both supervisor launch paths persisted the verified reference before activation, and a failed reference write rolled back without starting a child while retaining the descriptor. | Fact | Local worker/control-plane coverage; no V2 codec or crash matrix yet. |
| Pre-start no-child reaping | A real prepared worker wrote a reference-bound receipt after rollback; a forged endpoint was rejected, no command marker appeared, and persistent recovery deleted the no-child session. A post-start worker never emits this receipt. | Fact | One Windows x64 host; same-user storage tampering is outside the accepted threat model. |
| V2 source/package regression | Direct Bun 1.3.14 `bun test` and script-entry Bun 1.3.6 `bun unittest` each passed 209 tests with 16 skips and 769 expectations; `bun package:smoke` passed after its raw worker-reference assertion moved into V2 state | Fact | One Windows x64 host. |
| Phase 1 registry budgets and source crash cutover | Registry tests bound and release active/durable/output/wait/input reservations, rebuild a persisted output reservation after restart, and reject queued input before worker acceptance. A source-daemon kill/restart reconnects a persistent live child without replaying its marker command. Direct Bun 1.3.14 and script-entry Bun 1.3.6 each passed 214 tests with 16 skips and 786 expectations; Rust format/test/clippy and package smoke passed. | Fact | One Windows x64 host; process termination is not power-loss, and no platform pressure matrix has run. |
| Terminal conversation shutdown proof cache | A terminal session that already completed `worker.shutdown()` with strict proof deletes without a redundant reconnect, while crash-recovered terminal conversations still require a fresh reconnect/shutdown proof. Windows ConPTY cleanup now passes through the same path. | Fact | In-memory proof cache only; restart still clears it by design. |
| Post-start no-child and Windows child-start evidence | Conversation `spawn_failed` records with a valid retained `spawn-failure.json` are selected and deleted on recovery. On Windows, `job_assign` now reports `directChildStarted: true` with a PID and is never accepted by the static no-child verifier. | Fact | One Windows x64 host and focused tests; no published Windows matrix yet. |
| Known pre-worker failures | Oversized bootstrap payloads and unavailable worker resolution now return typed `WorkerStartError.noWorkerSpawned`, with confirmed no-child cleanup and no retained descriptor or marker. | Fact | Direct `WorkerClient.prepare()` coverage on one host. |

The V2 writer persists one discriminated lifecycle state and no root lifecycle flags; `SessionSupervisor` reduces that state before projecting legacy fields for existing RPC consumers. The storage decoder classifies V0, V1, and V2 before recovery: a legacy terminal needs a canonical owner tuple, lowercase SHA-256 capability hash, explicit direct-child exit, and explicit drained containment to import as V2 terminal state with unknown drain. Other supported V0/V1 records become cleanup-only unreachable conversation tombstones retaining `output.log`; proven imports persist a cleanup marker so source-log deletion is retryable. Explicit V0, incomplete, or future-version artifacts are skipped untouched. Terminal payloads survive a later unreachable transition, while cleaning cannot revive a session. Daemon-start recovery marks conversations for cleanup before descriptor publication; only protocol-compatible persistent sessions can make the authenticated `lost -> recovered` transition. A prepared worker that exits before `start` can provide a strict receipt bound to its persisted reference; that sole no-child evidence permits deletion. A worker that accepted `start` but never created a child can prove that only with a retained descriptor plus a strict `spawn-failure.json`; Windows child-started failures remain excluded. Ambiguous failures remain readable owner-scoped tombstones until strict cleanup evidence exists.

| Environment authorization policy | Ask/unmatched `pty_spawn` and `shell_exec` reject non-empty `env` or `inheritEnv: true` before `ctx.ask`; explicit local `bash` allow permits them. The focused authorization/tool tests and full 174-pass source suite passed. | Fact | Restrictive host-API policy, not a binding environment-approval protocol. |

## Current Runtime Trace

The trace below is based on source inspection. It is a fact about the current code, not a recommendation.

1. `PTYPlugin` registers tools and maps host `session.deleted` to owner-scoped cleanup (`src/plugin.ts:15-48`).
2. Tool adapters apply local policy and canonicalize work directories before calling `DaemonClient` (`src/plugin/pty/permissions.ts`, `src/plugin/pty/tools/*.ts`).
3. `DaemonClient` starts/reconnects to a loopback daemon and derives an owner capability from the persistent secret, OpenCode parent session, and canonical project directory (`src/plugin/pty/daemon-client.ts:394-622`).
4. `DaemonServer` validates bearer authentication and each RPC, re-derives the owner, then dispatches operations (`src/daemon/server.ts:135-368`, `952-1032`).
5. `SessionSupervisor` persists a `starting` record, prepares a one-session native worker, persists its verified reference before sending the start frame, then records the initial snapshot and monitors it (`src/daemon/supervisor.ts`).
6. The worker receives an authenticated bootstrap, creates either PTY or piped exec child, owns output redaction/journaling, and exposes authenticated loopback RPC (`worker/src/main.rs:3412-4206`).
7. The worker is the journal writer; TypeScript storage owns record metadata and reads/migrates/quarantines journals (`worker/src/main.rs:2219-2851`, `src/daemon/storage.ts:736-890`).
8. On daemon restart, storage records are loaded and worker descriptors are authenticated before reconnection (`src/daemon/supervisor.ts:272-358`, `src/daemon/worker-client.ts:474-501`).

## History Relevant to Current Risk

| Commit | Fact | Significance |
| --- | --- | --- |
| `0797bc1` | Introduced daemon exec and PTY wait semantics | Beginning of durable architecture. |
| `e9abb76` | Routed sessions through a native worker | Separates process engine from plugin. |
| `319525f` / `5cb26da` | Added and hardened Windows ConPTY plus Job containment | Windows behavior is explicitly custom, not incidental. |
| `a321e6a`, `dcd420f`, `233e783` | Serialized snapshots, cleanup, and recovery paths | Prior bugs confirm timing-sensitive lifecycle coordination. |
| `a901d4a` | Added `PseudoConsoleStdioGuard`; commit says it restored silent ConPTY output in its environment | Local A/B independently supports the guard on one Windows host. |
| `c6713b2` | Removed the guard to avoid console allocation | Local A/B reproduces both ConPTY failures when the guard alone is disabled; that is not a universal Windows claim. |

## Evidence Limits

- The local runtime experiments prove current behavior only on one Windows x64 environment and Bun 1.3.14.
- Hosted CI evidence is historical and must be reproduced from a clean revision before it is used as a release conclusion.
- No current experiment proves macOS descriptor recovery, pre-Windows-11-24H2 ConPTY close behavior, ARM target behavior, or process-tree behavior after an intentionally escaping descendant.
- Commit messages are evidence of author intent and past observation, never sole proof of OS behavior.
