# Phase 3: Narrow the Native Engine and Complete Operational Policy

**Status:** In progress

## Changes

1. Refactor the Rust worker around a small internal `SessionChild` platform contract: spawn, ordered input, resize if terminal, direct-child observation, graceful/forced stop, containment observation, and final resource release.
2. Keep Windows ConPTY/Job and POSIX terminal/session code private to platform modules. Shared code handles only protocol, state snapshot serialization, journal writer, bounded queues, and redaction.
3. Give one journal writer ownership of chunk sequence, redaction, retention, and atomic persistence. Move Windows filesystem retry policy into this one writer path so metadata and journal behavior use the same classified transient errors.
4. Implement defined input backpressure and output/reader drain behavior. No write may block forever; no reader may cause unbounded retained memory.
5. Enforce the documented 4,096 UTF-8-byte secret limit before bootstrap. Redact structured diagnostics and stop inheriting unbounded worker stderr to host logs.
6. Restrict worker override paths to explicit development mode, or add runtime identity validation if the accepted threat model requires it.
7. Treat `.cmd`/`.bat` as explicit shell execution metadata and keep experimental Bash default-off.

## Why

- Mixed shared/platform worker code obscures ConPTY and cleanup ownership.
- Journal persistence and metadata persistence have divergent Windows lock behavior.
- Current redaction and environment-policy limits disagree with documentation.
- Resource boundaries need engine enforcement, not convention.

## Complexity Removed

- Remove platform conditionals from shared lifecycle/persistence logic.
- Remove duplicated journal/metadata retry classifications.
- Remove raw worker stderr as an implicit observability channel.

## Current Slice

The bootstrap boundary now rejects sensitive environment values over 4,096 UTF-8 bytes before admission and again in the worker. Worker stderr is continuously drained into a bounded redacted tail rather than inherited by the host, and `PTY_NATIVE_WORKER_PATH` now requires explicit development mode. The worker redaction regression for a complete multibyte secret at EOF is covered. Journal retry, native input backpressure, `SessionChild`, and Windows batch-policy binding remain open.

## Invariants Afterward

- One native engine owns one child and one journal.
- Windows child is assigned to its Job before it executes; POSIX claims remain conservative.
- Cleanup never calls a PID solely by number without an owned handle or start-identity verification.
- Terminal output is finalized only through documented direct-child + reader-drain + containment observations.

## Tests

- Worker protocol malformed/authenticated request tests.
- Input pressure, output pressure, slow reader, Unicode split chunks, binary-like terminal data, write-after-exit, and resize storms.
- Windows transient journal-rename fault injection.
- Batch command plan and environment Unicode/duplicate-key tests.
- Orphan worker/tombstone reaping tests on all platforms with platform-specific expected claims.

## Platform Validation

| Windows | Linux | macOS |
| --- | --- | --- |
| ConPTY conformance on supported builds; Job assignment/accounting; `cmd`, PowerShell, and batch behavior | PTY, direct exec, process-session and escaped descendant evidence | PTY, direct exec, direct-child exit with explicit unknown descendant containment |

## Completion

- Platform code is isolated and documented by capability/result, not leaked into TypeScript.
- All resource limit errors are structured and covered by contract tests.
- Security findings in `../security-and-operations.md` are resolved or recorded as accepted product limits.
