# Phase 1: Freeze Contract, Ownership, and State

**Status:** In progress. The compatibility-preserving reducer, full-owner idempotency, lifecycle-specific recovery, fail-closed environment policy, V0-to-V1 compatibility migration, and durable pre-start worker-reference checkpoint are implemented and locally verified. Unsupported artifacts are inert; terminal migration and cleanup require explicit evidence; terminal-log removal retries; rollback/deletion retain reaping credentials; incompatible worker references are fenced; strict pre-start and post-start no-child receipts are implemented; and normal terminal cleanup reuses fresh shutdown proof while restart still requires a fresh authenticated shutdown for conversation workers. Direct Bun 1.3.14 and script-entry Bun 1.3.6 each pass 189 tests with 16 skips and 712 expectations; package smoke passes. A discriminated persistent state and quotas remain.

## Changes

1. Write a machine-readable platform capability contract for `exec` and `pty`: direct-child result, stream drain result, containment result, supported shell kinds, and terminal output portability.
2. Replace `DaemonStatus` plus independent lifecycle booleans with the discriminated state model in `../target-architecture.md`. **Implemented compatibility slice:** strict V1 writes carry a root marker and lowercase SHA-256 owner hash. V0 is decoded before validation/recovery; only explicit direct-child and containment evidence permits a terminal migration or terminal cleanup. Live/unproven V0 records become owner-scoped cleanup tombstones, retain legacy output, and never reconstruct as live target sessions. Proven terminal imports use a persisted cleanup marker so output-log removal can retry. Unknown, incomplete, and null-owner artifacts remain inert and do not block healthy records. The final discriminated persistent state remains open.
3. Implement a pure transition reducer with a small transition table and tests for every legal/illegal transition. **Implemented compatibly:** `src/daemon/lifecycle.ts` covers the existing persisted statuses, including a recovery-only `lost -> recovered -> running` transition.
4. Separate `unreachable` from terminal outcome. Add a tombstone that retains owner, worker identity, last-known child identity, and cleanup attempts. Make recovery lifecycle-specific: recover only `persistent` sessions and immediately reap `conversation` sessions. **Implemented without a schema migration:** daemon startup marks conversation cleanup before descriptor publication; lost records are retained until strict proof permits deletion.
5. Define constant budgets for active sessions, pending waits, input queue bytes, per-owner/global retained bytes, and terminal-record retention. Publish the error categories and metrics.
6. Bind authorization intent to execution kind, canonical argv/shell, canonical workdir, environment profile fingerprint, and `inheritEnv` state. **Implemented safely for the current host API:** transient approval rejects non-empty `env` and `inheritEnv: true`; an explicit local `bash` allow is required because approval metadata cannot bind them.

## V2 Checkpoint

The V2 storage codec is not implemented. Its hard pre-bind prerequisite is locally implemented and tested: `WorkerClient.prepare()` verifies the ready descriptor while the worker remains blocked on its inherited control pipe; the supervisor persists that authenticated reference before `client.start()` sends the frame that makes child creation eligible. A persistence failure rolls back before start. A worker that confirms its pre-start exit writes a receipt bound to the persisted reference; recovery may delete only on that receipt, while missing or invalid evidence remains a tombstone.

Do not begin the V2 writer until all of these are designed and tested together:

1. Explicit V0, V1, and V2 decoders; future versions remain byte-for-byte inert.
2. V2 is the only writer and has one discriminated state; do not dual-write legacy status/flags beside it.
3. V1 terminal import requires explicit terminal evidence and records stream drain as `unknown`; V1 live/unproven records become cleanup-only tombstones.
4. Crash points cover preparation, reference persistence, start-frame delivery, child creation, and terminal persistence. Recovery never replays `start`.
5. Conversation cleanup remains pre-publication and persistent recovery requires fresh authenticated snapshots.

## Why

- Current records combine state, flags, and optional reports (`src/daemon/types.ts:17-240`).
- Legacy cleanup treated `lost` as ineligible; the current recovery path retains and retries owner-scoped tombstones instead.
- Transient approvals cannot safely bind a materially different environment; the plugin now rejects that combination unless local static policy explicitly permits it.
- Aggregate resource limits are undefined.

## Complexity Removed

- Delete flag combinations that duplicate facts derived from terminal outcome/termination observation.
- Eliminate cleanup decisions based solely on the string `lost`.

## New Responsibility

- The state reducer is the sole authority for lifecycle changes.
- The daemon registry owns quotas and tombstone retention; the engine only reports observations.

## Tests

- Exhaustive state transition tests.
- Migration/read tests for V0 terminal/live/unproven records, strict V1, incomplete owner tuples, and unknown future versions.
- V0 terminal proof, malformed legacy owner hashes, terminal output-log cleanup retry, and unconfirmed worker-start descriptor retention.
- Owner cleanup of `unreachable` sessions preserves tombstone until reaping evidence is terminal.
- Unsupported records do not block healthy loading; unconfirmed rollback and failed deletion retain `worker.json`; incompatible worker references never receive a control attempt.
- Transient approval rejects custom/inherited environment options without exposing their values; explicit local allow permits them.
- Quota tests for waits, aggregate retention, and concurrent reservations.
- Identical parent-session/key/workdir values under distinct full owner identities cannot reuse one another's session.
- Stale snapshots cannot mutate facts after their lifecycle transition is rejected.
- Persistent recovery requires an authenticated fresh snapshot; conversation recovery is cleanup-only and failed cleanup preserves a tombstone.
- Prepared workers cannot start a child before their verified reference is durable; reference persistence failure rolls back and retains unconfirmed cleanup evidence.
- A valid pre-start no-child receipt reaps a worker without child/containment claims; a forged receipt and every post-start failure remain non-deletable tombstones until ordinary proof exists.
- A valid post-start no-child receipt reaps only a full compatible worker reference with a retained descriptor and exact `directChildStarted: false` evidence; Windows child-started failures are excluded from that path.
- A terminal conversation record written by the running daemon reuses in-memory fresh shutdown proof for deletion retries, but crash-recovered terminal conversations still need a fresh authenticated shutdown.

## Platform Validation

This phase is platform-neutral logic, but run the native contract on Windows, Linux, and macOS because serialized snapshots change how engine results are recorded.

## Completion

- No public API returns a false clean/termination claim derived from unrelated flags.
- All stored lifecycle states have exactly one legal interpretation and one cleanup policy.
- Documentation and errors name the difference between direct child exit, stream completion, and containment.
- Remaining work has a persisted discriminated state, crash-point cutover matrix, explicit tombstone retention budget, and a supported-runtime matrix for the restrictive environment/inheritance policy.
