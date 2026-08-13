# Target Architecture

**Status:** Proposed from evidence. Start implementation only through the gated sequence in `plan/`.

## Design Goal

The smallest system that can honestly provide durable, owner-isolated interactive sessions and finite direct execution across Windows, macOS, and Linux:

```text
plugin adapter -> daemon registry/router -> per-session native engine -> one child session
```

There is one authoritative owner for each concern:

| Concern | Sole authority |
| --- | --- |
| Host permission decision and tool UX | Plugin adapter |
| Owner identity, admission budgets, session routing, metadata/tombstones | Daemon registry |
| One child process, PTY/pipes, I/O queues, output journal, platform stop primitive | Native engine for that session |
| Terminal/process behavior | Operating system child and platform API |

The daemon never writes a worker's output journal. The worker never decides ownership or global quotas. The plugin never treats a preflight read as authorization.

## Execution Contract

### Exec

- Direct executable plus argv only.
- Separate stdout/stderr streams, concurrent draining, bounded retained result.
- A required deadline and one explicit graceful-then-forced termination sequence.
- No shell unless the caller selected a named shell execution kind.
- Process result, stream completion, and descendant containment are reported separately.

### PTY

- Opt-in for TTY-required applications only.
- One combined terminal stream; stdin, output, and resize are session-specific ordered operations.
- No screen emulator and no byte-perfect transcript guarantee across platforms.
- Terminal close is not child exit. Finalization requires child/containment observation plus stream-drain policy.

## State Model

Persist one discriminated state rather than mutable status plus interpretation flags:

```text
creating
  -> running
  -> stopping
  -> terminal { outcome: exited | timed_out | output_limited | spawn_failed }
  -> unreachable { lastKnown: creating | running | stopping | terminal }
  -> cleaning
  -> deleted
```

`unreachable` means control cannot currently be authenticated/reconnected. It does not assert the child is dead and does not prevent owner cleanup. `terminal` contains immutable observations: direct child result, stream-drain result, containment report, and truncation. `cleaning` retains a tombstone until reaping succeeds or reports an explicit unconfirmed result.

Legal transitions are enforced by one pure transition reducer and one per-session controller. Invalid requests return a stable error category (`not_running`, `unreachable`, `already_terminal`, `resource_limit`, or `invalid_transition`) rather than silently changing state.

The immutable lifecycle mode determines recovery. A `persistent` session is explicitly allowed to reconnect after a daemon restart. A `conversation` session is stopped/reaped during daemon recovery and on the normal host-session deletion event. This favors deterministic cleanup over accidental survival; callers that need restart durability must opt in to `persistent`.

## Upgrade Policy

The registry writer version is explicit. Terminal records from supported prior versions are migrated into the new terminal representation. A pre-upgrade live record is never represented as a live target session because target controller/engine ownership cannot be reconstructed safely. It becomes an owner-scoped `unreachable` legacy tombstone that retains the old worker descriptor/identity only for authenticated reaping, then is deleted under the normal tombstone policy.

## I/O and Backpressure

- The engine has one bounded ordered input queue and rejects overload before accepting data.
- PTY resize is serialized with terminal ownership; after stopping starts, write/resize fail deterministically.
- Reader threads/callbacks submit chunks to one journal writer path. That path allocates monotonically increasing sequences, redacts, persists, and performs bounded whole-chunk eviction.
- Slow readers do not block child output draining; they observe `retained_from`, `truncated`, and byte sequence cursors.
- Output limits are service safety controls, not a substitute for child-tree containment.

## Platform Boundary

The Rust engine contains all platform-specific spawn, terminal, stop, containment, and low-level handle behavior behind an internal `SessionChild` contract. TypeScript sees only normalized snapshots and stable error categories. It must not branch on ConPTY, termios, Job, signals, `PATHEXT`, or platform handle lifetimes.

| Contract | Windows implementation | Linux implementation | macOS implementation |
| --- | --- | --- | --- |
| PTY | ConPTY | controlling PTY | controlling PTY |
| Tree control | suspended create -> non-breakaway Job -> resume; `KILL_ON_JOB_CLOSE` | fresh session; direct-child signal only | fresh session; direct-child signal only |
| Clean containment result | Job accounting empty | successful `/proc` observation empty | unavailable; unknown |
| Terminal finalization | validated EXP-01 close order | EOF/drain policy | EOF/drain policy |

## Invariants

1. A session ID is an opaque registry identity, never a PID.
2. Exactly one engine owns a live child and exactly one engine writes its journal.
3. No operation crosses an owner boundary, even with guessed session IDs.
4. No state transition occurs without the session controller; records cannot be overwritten by stale snapshots.
5. All memory, journal, input, waiter, and admission queues have a declared bound and failure behavior.
6. Direct-child exit, I/O drain, and descendant containment are distinct facts. The API never manufactures a clean claim from one of them.
7. `unreachable` preserves enough identity and ownership data to retry/reap safely; cleanup does not destroy the last control evidence before a result is known.
8. Shell parsing is explicit and audited. Structured argv remains direct execution.
9. Platform differences are confined to the engine and exposed as normalized capability/containment data.
10. Daemon shutdown has one behavior: stop accepting requests, flush registry state, preserve or stop workers according to declared lifecycle, then update descriptor atomically.
11. Lifecycle events are structured and content-free by default.
12. A session cannot delay, corrupt, or consume the output/state budget of another session except through documented global admission limits.

## Deliberate Non-Goals

- A sandbox or privilege boundary for arbitrary untrusted programs.
- Byte-identical ANSI output across ConPTY and POSIX terminals.
- Guaranteed descendant termination on macOS or against POSIX descendants that deliberately escape their session.
- A browser API, WebSocket terminal streaming layer, or screen emulator.
- A Bun-only implementation before it passes the full conformance gate.
