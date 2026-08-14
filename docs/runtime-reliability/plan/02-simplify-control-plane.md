# Phase 2: Simplify the Control Plane

**Status:** Locally complete. The control-plane slices delete legacy daemon-side direct exec, make `list()` metadata-only, replace global admission polling with registry-owned full-owner reservations, serialize session mutations through router lanes, unify daemon shutdown/disposal, and separate journal reads.

## Changes

1. Delete `SessionSupervisor.exec()` and its daemon-side `Bun.spawn` collectors after confirming no external API uses it. Keep only the native engine path for supported exec behavior. **Implemented.**
2. Replace `DaemonServer.withSessionSlot()` global `supervisor.list()` synchronization with an atomic registry reservation keyed by full owner identity. Registry counts change on state transitions, not worker snapshots. **Implemented.** Reservations are conservative: first-write failure releases, while later uncertain records retain capacity until strict proof or durable deletion.
3. Route liveness snapshots only to the requested session (`get`, explicit recovery, or controller operation), never to every active worker during unrelated admission. **Implemented.** `list()` is metadata-only.
4. Split the supervisor into small collaborators without adding a framework: `SessionRegistry` for records/admission/tombstones, `SessionRouter` for owner-checked worker routing and ordered queues, and `JournalReader` for read/search. Keep the daemon server as transport/validation only. **Implemented.**
5. Give each session one controller lane for state-changing operations. Reads can be concurrent; write/resize/stop/finalize have deterministic ordering and stop closes future input. **Implemented.** The lane also covers send-and-wait input acceptance, conversation cleanup marking, and durable deletion. Persistence remains separate so a finalizer does not recursively wait on itself.
6. Make `stop()` and disposal follow one shutdown implementation. It must stop accepting RPC, persist state, apply declared worker policy, and remove/update the descriptor once. **Implemented.** `stop()`, `Symbol.dispose`, and `Symbol.asyncDispose` share an idempotent shutdown promise.

## Why

- Server RPC dispatch and supervisor own too many unrelated concerns.
- Session start performs O(active workers) snapshot RPCs, so one stalled worker can affect unrelated owners.
- Two exec implementations encode incompatible cleanup semantics.
- Current queues are repairs around implicit state ownership.

## Complexity Removed

- Delete legacy direct Bun exec, `OutputRedactor` path used only by it, and duplicate stream collection behavior.
- Delete global live-worker sync from admission.
- Consolidate shutdown paths. **Implemented.**

## Invariants Afterward

- A session mutation passes through exactly one controller lane. **Implemented.**
- Admission does not issue worker RPC to another owner/session.
- Only the engine owns child I/O; only registry owns session metadata and quotas.
- A stale worker cannot overwrite a newer terminal/tombstone record.

## Tests

- Slow/failing snapshot for session A does not delay owner B's spawn/exec.
- Concurrent create requests enforce per-owner quota without oversubscription.
- Concurrent write/resize/stop yields one ordered, reproducible terminal result. **Locally verified.**
- Process daemon shutdown through `stop` and disposal; assert identical durable outcomes. **Locally verified.**

## Platform Validation

Run real PTY/exec sessions on Windows, Linux, and macOS. This phase must not alter native behavior, but its routing and shutdown contracts touch all platforms.

## Completion

- No supported code path calls the legacy direct `Bun.spawn` exec implementation.
- Session admission latency is independent of unrelated worker liveness.
- The architectural responsibility table in `../current-architecture.md` is updated with source references.

All local completion conditions are verified. The platform matrix remains an external release gate shared with the later phases.
