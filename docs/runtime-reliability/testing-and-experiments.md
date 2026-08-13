# Testing and Experiments

**Status:** Partially verified

## Current Test Inventory

The project has focused daemon, storage, plugin-client, approvals, TUI-state, worker-target, and package smoke tests. `test/daemon.test.ts` is a 5,212-line integration-heavy suite. Rust tests live in `worker/src/main.rs`. This is meaningful coverage, particularly for storage corruption, ownership RPC checks, recovery, and Linux containment, but it is not a green cross-platform release gate today.

## Verified Local Results

| Command | Result |
| --- | --- |
| `bun typecheck` | Pass |
| `cargo test --locked --workspace` | Pass, 11 Windows-targeted tests on local host |
| `bun unittest` | Fail: claimed-start-lock test timeout plus unhandled `ENOENT` during cleanup; 152 pass / 16 skip / 1 fail / 1 error |
| `bun package:smoke` | Fail: Windows packaged ConPTY did not echo input |

No implementation must claim the current state is production-ready while those results remain true.

## Phase 0 Update

The initial results above are the pre-fix baseline. On the retained configuration, local Windows x64 passed `cargo test` (13 tests), `cargo clippy -D warnings`, `bun typecheck`, direct Bun 1.3.14 `bun test` (189 pass, 16 skip, 712 expectations), script-entry Bun 1.3.6 `bun unittest` (189 pass, 16 skip, 712 expectations), and the fresh-package `bun package:smoke` contract. The earlier 20-run package result applies to the Phase 0 ConPTY guard configuration; Phase 1's package recovery case passed after declaring its restart-survival exec `persistent`.

The local A/B retained the scoped `PseudoConsoleStdioGuard`: disabling only that guard failed both interactive and finite ConPTY tests; restoring it passed both. The worker has one child only, so the temporary process-standard-handle change cannot cross session boundaries. This does not prove Windows 10 1809, pre-24H2, 24H2, ARM, or close-order behavior.

The Windows-only `windows_conpty_echo_resize_and_job_drain` worker test now provides the raw primitive: it uses production spawn, `cmd /d /c more`, one nonce write, resize, `TerminateJobObject`, and bounded Job drain. Run this test and the package contract 20 times on each published Windows variant.

The native-exec storage-failure test uses a child file gate instead of a wall-clock delay: it replaces the journal output directory first, then releases child output. A worker-reported storage failure is expected to reach callers as `ESTORAGE` even while containment is unresolved; the session remains `lost` until its own cleanup evidence is available.

Phase 1 adds deterministic recovery cases: stale snapshots cannot overwrite a stopping record's facts; same-key PTYs cannot reuse across full owner identities; persistent lost records retry and require a fresh authenticated snapshot before resuming; and conversation records are marked before daemon publication, reconnected only for cleanup, or retained as owner-cleanable tombstones. The packed restart case explicitly uses `lifecycle: 'persistent'`; restart survival is not the default.

Phase 1 also treats custom or inherited environment as a static-policy capability, not an approval detail: ask/unmatched `pty_spawn` and `shell_exec` reject non-empty `env` and `inheritEnv: true` before `ctx.ask`, while an explicit local `bash` allow permits them. Tool-adapter tests assert both tools pass those options to authorization and that rejection never includes a supplied secret value.

The V0 migration tests seed raw unversioned `session.json` artifacts. A terminal record rewrites as strict V1 only with a canonical owner tuple, lowercase SHA-256 capability hash, explicit direct-child exit, and explicit drained containment. Live or unproven terminal records rewrite as non-runnable cleanup tombstones and retain `output.log`; proven terminal imports persist a cleanup marker before deleting that log, and V1 retries a failed deletion on later load. The same explicit proof is required before a persisted terminal record can be cleaned. Incomplete or null owner tuples, malformed legacy hashes, and future versions stay byte-for-byte untouched and are not quarantined or startup-fatal. The audit regression also keeps a healthy record loadable beside those artifacts, preserves `worker.json` across unconfirmed startup rollback/failed deletion, and fences incompatible worker protocols from reconnect or reaping. This protects recovery from reviving legacy live state, but it is not yet the Phase 1 crash-point migration matrix or a discriminated persisted-state implementation.

Prepared-worker tests prove child creation is gated behind durable reference persistence: a real marker command remains absent before `client.start()`, both supervisor start paths block at the reference write, and a failed reference write rolls back before activation while retaining the descriptor. A pre-start rollback writes a strict reference-bound no-child receipt; recovery rejects a forged receipt, deletes only after valid receipt verification, and a post-start worker never emits one. A retained descriptor plus a strict `spawn-failure.json` now proves the separate post-start case where `start` was accepted but no direct child was created; a conversation `spawn_failed` record is selected and reaped on recovery without reconnecting. Windows `job_assign` now reports `directChildStarted:true` and is therefore excluded from that no-child path. Terminal conversation cleanup also records an in-memory fresh-shutdown proof so normal finalization deletes without a redundant reconnect, while crash-recovered terminal sessions still require a fresh authenticated shutdown. V2 storage remains unimplemented; the full crash matrix must still cover prepared worker, reference persistence, start-frame delivery, child creation, and terminal persistence.

## Minimum Test Tiers

| Tier | Trigger | Scope | Required platforms |
| --- | --- | --- |
| Fast unit | Every change | State reducer, authorization intent, serialization, parsing, Windows command-plan logic | Linux runner is enough for pure units; platform-conditional units run where meaningful. |
| Native contract | Every PR | Real worker: exec stdout/stderr, PTY marker/write/resize/read/stop/cleanup, worker identity absence | Windows x64, Linux x64, macOS arm64. |
| Package contract | Every PR | Build, fresh install optional worker, run same native contract from packed artifact | Windows x64, Linux x64, macOS arm64. |
| Reliability suite | Nightly and release candidate | Failure injection, daemon crash points, 100+ concurrent sessions, repeated cycles, output/input pressure, malicious RPC | Every published target where runner exists. |
| Release matrix | Release only | Clean checkout, exact release artifact/signature/provenance, install/import/smoke | linux x64/arm64, win x64/arm64, darwin x64/arm64. |

No retries are permitted for a lifecycle contract test. A failure is a defect or a test that does not control its environment.

## Required Conformance Cases

1. **Exec:** direct argv with independent stdout/stderr, Unicode output, invalid executable, timeout, output limit, child that stops reading stdin, and stop-before-exit.
2. **PTY:** TTY detection, initial size, resize, interactive nonce write/read, combined output, ANSI-containing output, abrupt child exit, slow output consumer, and a child that ignores a graceful stop.
3. **Session isolation:** two owners cannot see/control each other; two sessions do not share output; concurrent writes preserve per-session order; one stalled worker cannot block unrelated admission.
4. **Durability:** daemon restart after descriptor write, worker readiness, running child, child exit, and journal finalization. Expected outcomes are authenticated reconnect or a readable owner-cleanable tombstone, never silent disappearance.
5. **Containment:** explicit direct-child result plus platform containment evidence. Escaping POSIX descendants must prevent a clean containment claim.
6. **Shutdown:** signal the daemon entry point; verify descriptor removal/retention rule, no false finalization, and all conversation sessions get their intended cleanup policy.

## Focused Experiments

### EXP-01: Windows ConPTY launch and teardown

**Question:** Which exact launch and close sequence yields reliable interactive I/O without a visible terminal on supported Windows builds?

**Why:** Local failure is repaired, but the scoped guard has evidence from one host only and `ClosePseudoConsole` behavior remains version-sensitive.

**Procedure:** Build a minimal Rust fixture that creates ConPTY, launches `cmd /c more` and `cmd /c echo <nonce>`, drains output continuously, writes a nonce, resizes, stops the Job, waits for Job drain, then closes ConPTY. Test guarded and unguarded launch paths plus the documented Microsoft baseline. Repeat 20 times each.

**Environment:** Record Windows version/build, terminal host, parent std-handle types, worker architecture, Rust version, and Bun version if launched through Bun.

**Pass:** all 20 runs deliver the nonce, exit without hang, report Job-empty after bounded wait, and show no visible console.

**Limit:** Passing one build is not a broad Windows claim. Repeat on Windows 10 1809, Windows 11 before 24H2, and 24H2 where supported.

### EXP-02: State-machine crash matrix

**Question:** Can every interruption point result in an authoritative record and safe reaping behavior?

**Procedure:** Terminate daemon/worker after each boundary: record persisted, worker prepared, verified worker reference persisted, start frame accepted, child created, child Job assigned/session created, reader started, child exit observed, journal finalization started. Restart daemon and assert exactly one outcome: reattached, terminal record, or owner-cleanable unreachable tombstone. Recovery must never replay a start frame.

### EXP-03: Bun replacement conformance

**Question:** Does a Bun-only terminal/direct-exec engine meet the target contract on all platforms?

**Procedure:** Implement outside production code. Run the same PTY/exec, output-pressure, input-pressure, tree, close-order, and restart tests as the native engine.

**Pass:** all required semantics and containment/observability claims meet the stated contract. A successful happy-path shell is insufficient.

### EXP-04: Admission isolation

**Question:** Can a stalled worker delay unrelated owner session creation?

**Procedure:** Hold one worker snapshot RPC beyond its timeout while concurrently creating sessions for a different owner. Measure latency and success.

**Pass:** unrelated admission uses registry state and is unaffected; the stalled session alone becomes stale/unreachable through its own path.

## Test Design Rules

- Use a compact real-worker contract harness instead of proliferating overlapping end-to-end fixtures.
- Test state transitions through public RPC/tool paths and pure transition functions separately.
- Use deterministic child fixtures that report a nonce, hold, ignore a first signal, fork/escape where supported, flood output, or stop reading stdin. Do not use arbitrary installed shells as the only oracle.
- Assert semantic terminal behavior on Windows, not literal escape-sequence equality.
- Record resource baselines for repeated create/destroy cycles: process count, Windows handle count, open descriptors, retained journal bytes, and worker records.
