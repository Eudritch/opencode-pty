# Platforms, Bun, and Dependency Evaluation

**Status:** Partially verified

## Bun Capability Assessment

| Capability | Fact | Consequence |
| --- | --- | --- |
| Direct argv spawn | `Bun.spawn` accepts `cmd`, `cwd`, `env`, piped stdio, `AbortSignal`, timeout, and direct-child `kill` | Suitable for ordinary finite direct-child execution if the caller manages journaling, retention, and semantics. |
| Pipe I/O | stdout/stderr are Web `ReadableStream`s; stdin is `FileSink` | Drain both outputs concurrently. Do not assume undocumented `FileSink` pressure information is a durable backpressure contract. |
| PTY | `terminal` creates a real POSIX PTY and Windows ConPTY; terminal I/O is combined and `stdout`/`stderr` are null | Bun now covers the minimum PTY mechanism. It does not by itself provide the daemon's durable lifecycle contract. |
| Terminal exit | terminal `exit` represents terminal-stream closure, not child exit; `proc.exited` is separate | Any Bun candidate must model I/O completion and direct-child exit independently. |
| Windows terminal output | ConPTY may re-encode/coalesce/reorder terminal output and differs from POSIX termios behavior | Tests must assert semantic protocol behavior, not byte-identical ANSI transcripts. |
| Process tree | Bun docs describe control of the spawned child, not portable descendant containment | Never claim child-tree cleanup from `kill`, timeout, or AbortSignal alone. |
| Runtime version | Windows ConPTY arrived after this project's declared 1.3.8 minimum; local tested version is 1.3.14 | A Bun PTY migration requires a minimum-version increase and matrix proof. |

**Conclusion (inference):** Bun is credible for a non-durable, direct-child exec implementation. It is not yet a replacement for the project's native engine because that engine also supplies Windows Job ownership, per-session worker recovery, authenticated native control, durable journaling, and conservative containment reporting. The narrow-native recommendation remains provisional until EXP-01 and the conformance suite pass; a future replacement requires those experiments, not an API-only judgment.

## Provisional Decision Matrix (Inference)

Hard gates before scoring: true PTY only where required; explicit direct-child/descendant claim; Windows Job or an accepted weaker contract; restart behavior; signed/fresh installation; owner isolation; bounded output and writes.

Scores are 1 (unacceptable) through 5 (demonstrated strong fit). `Unproven` means a hard platform/conformance gate is still open. These are comparative evidence summaries, not release approval.

| Option | Simplicity | Lifecycle/security | Windows | Durability | Install risk | Bun fit | Total / 30 | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Current architecture unchanged | 1 | 3 | 1 | 4 | 3 | 5 | 17 | Reject: verified Windows failure and duplicate complexity. |
| Repair current native design in place | 3 | 4 | Unproven | 4 | 3 | 5 | N/A | Viable transition path, but must simplify ownership/state. |
| Narrow native engine plus simplified control plane | 4 | 5 | Unproven | 5 | 3 | 5 | N/A | Recommended provisionally, pending EXP-01 and conformance results. |
| Bun direct exec plus Bun Terminal PTY | 5 | 2 | Unproven | 1 | 5 | 5 | N/A | Prototype only; lacks parity proof and needs new durability machinery. |
| `node-pty` | 2 | 2 | 2 | 1 | 2 | 1 | 10 | Reject: Bun support is not maintained; native install fallback risk remains. |
| `bun-pty` | 3 | 2 | 2 | 1 | 3 | 4 | 15 | Reject for production: in-process FFI widens failure boundary; insufficient Job/recovery evidence. |
| `portable-pty` inside worker | 2 | 3 | 3 | 3 | 3 | 5 | 19 | Do not adopt now. It replaces only PTY primitives and increases dependencies. |

## Dependency Audit

| Dependency or facility | Why it exists | Risk/value | Decision |
| --- | --- | --- | --- |
| Rust `windows-sys` | Direct ConPTY, handles, Job Objects, process creation | Native API complexity, but exposes required Windows primitives without a second terminal binding | Retain in narrow native engine. |
| Rust `libc` | POSIX PTY/session/signals | Required low-level POSIX behavior | Retain. |
| Rust `serde` / `serde_json` | Bootstrap, worker RPC, journal metadata | Small, maintained serialization dependency | Retain. |
| Optional worker packages | Ship exact executable per OS/architecture | Six target release/signing burden | Retain only while native engine is justified. Expand smoke coverage before trusting. |
| Bun runtime | Plugin, daemon, tooling | Version-specific behavior and minimum-version mismatch | Retain; pin/test a supported minimum rather than using an unproven range. |
| OpenCode/OpenTUI dependencies | Host tool and optional TUI integration | API compatibility is separate from process engine | Keep pinned as currently documented. |

## Platform Contract

| Behavior | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Interactive terminal | ConPTY. Output is semantically equivalent, not byte-identical. Close order is sensitive on older Windows. | Real controlling PTY. | Real controlling PTY. |
| Exec I/O | Direct argv plus independent stdout/stderr pipes. | Same. | Same. |
| Direct-child stop | Worker has owned process/Job handle. | Signal direct child. | Signal direct child. |
| Descendant handling | Non-breakaway Job plus `KILL_ON_JOB_CLOSE`; verify Job accounting as evidence. | Fresh session/process group and conservative `/proc` observation; descendants can escape. | No equivalent verified enumeration; containment is unknown. |
| Correct clean claim | `windows_job_empty` only after bounded accounting observation. | `posix_best_effort_empty` only after successful scan. | Direct-child exit only; descendant containment remains unknown. |
| Worker recovery | Authenticated descriptor and process identity. | Same architecture. | Same architecture. |

## Windows-Specific Findings

1. The worker deliberately creates the child suspended, assigns it to a non-breakaway Job with `KILL_ON_JOB_CLOSE`, then resumes it (`worker/src/main.rs:898-1100`). This is the correct ordering for ownership, not an optional implementation detail.
2. `.cmd` and `.bat` cannot be direct `CreateProcessW` targets; current code resolves `PATH`/`PATHEXT` and deliberately invokes `cmd.exe /d /c` (`worker/src/main.rs:705-762`). Treat these as shell-interpreted commands in policy and tests.
3. `a901d4a` added temporary parent-console std-handle rebinding during ConPTY `CreateProcessW`; `c6713b2` removed it. Current packed echo fails. The causality is a hypothesis until the controlled bisect/experiment passes.
4. Closing a pseudoconsole and reader ordering are independent of child exit. The target must kill/verify the child tree, drain or time-bound terminal output, then release ConPTY in the OS-supported order.

## Rejected Simplification

Removing the native layer because Bun now has `terminal` would replace an explicit native boundary with unproven in-process runtime behavior and require rebuilding the durable registry, recovery, containment evidence, redaction/journal, and Windows Job control. That is more code and less evidence, not simplification.
