# Runtime Reliability Investigation

**Status:** Investigating. Phase 0 recovered the local Windows baseline. Phase 1 is locally complete: V2 discriminated persisted state, pure state reduction, lifecycle-specific recovery, compatibility decoding, durable worker-reference checkpoints, bounded registry admission/waits/input/output/records, and source-daemon crash recovery are locally verified. Phase 2 is locally complete: it removes the daemon-side direct-exec path and global admission polling, adds controller lanes/unified shutdown, and separates records, worker routing, and journal reads. Phase 3 is in progress: sensitive bootstrap values are bounded, worker stderr is not inherited, and source-worker overrides are development-only; native input, journal retry, and batch-policy work remain. Cross-platform pressure, crash, and release matrices remain open.

This directory is the engineering record for rebuilding the process and terminal runtime. It deliberately treats `shekohex/opencode-pty` as historical input rather than a design authority.

## Index

| Area | Status | Canonical document | Important conclusion |
| --- | --- | --- | --- |
| Evidence and scope | Verified | [evidence.md](evidence.md) | Findings are tied to source, official documentation, history, or an experiment. |
| Current runtime | Partially verified | [current-architecture.md](current-architecture.md) | The fork is a major durable-runtime rewrite; recovery distinguishes persistent sessions from conversation cleanup and the decoder fences legacy live records from recovery. |
| Bun and dependencies | Partially verified | [platforms-and-dependencies.md](platforms-and-dependencies.md) | Bun has a PTY API, but it has not demonstrated parity with the durable native-worker contract. |
| Windows and concurrency | Partially verified | [risk-scorecard.md](risk-scorecard.md) | Local packaged ConPTY is repaired by a scoped console-handle guard; admission is per-owner and independent of unrelated worker liveness, while the Windows build/close-order matrix remains open. |
| Security and operations | Partially verified | [security-and-operations.md](security-and-operations.md) | Owner-scoped reuse, inert incompatible-worker records, evidence-retaining V2 tombstones, and fixed registry budgets are implemented; transient approvals reject custom/inherited environments. |
| Tests and experiments | Partially verified | [testing-and-experiments.md](testing-and-experiments.md) | Local native/package checks are green; cross-platform release confidence is blocked by the unrun Windows and macOS matrices. |
| Target architecture | Proposed from evidence | [target-architecture.md](target-architecture.md) | Keep the mode split and narrow native engine; simplify the control plane and make state authority explicit. |
| Open questions | Open | [open-questions.md](open-questions.md) | Only unresolved questions that can change a decision or release claim remain here. |
| Migration plan | Ready after baseline gate | [plan/README.md](plan/README.md) | Sequential implementation phases with evidence, invariants, platform validation, and stop/go criteria. |

## Current Architectural Conclusions

1. A real PTY is only needed for interactive terminal behavior: TTY detection, prompts, raw keys, ANSI terminal traffic, and resize. Direct argv execution with piped streams is a separate mode.
2. The existing public split between `pty_spawn` and finite `shell_exec` is correct. Do not force ordinary subprocesses through terminal emulation.
3. A native child engine remains justified today for the published durable contract: Windows ConPTY plus Job Object ownership, Unix terminal setup, durable reconnection, and conservative containment evidence. Bun 1.3.14 has PTY support, but lacks demonstrated parity for those responsibilities.
4. The native engine must be narrow: it owns one child session and its I/O. The daemon owns only authentication, owner-scoped session metadata, routing, and bounded admission. The plugin owns host policy and presentation.
5. The local Windows PTY failure is repaired, but the guard has evidence from one Windows x64 host only. Do not publish a broader Windows claim until the focused experiment validates the supported build matrix and close behavior.

## Reading Rules

- **Fact** means directly supported by a cited source, official documentation, commit history, or recorded experiment.
- **Inference** is a conclusion from facts and names the uncertainty.
- **Hypothesis** is a testable explanation, not a design premise.
- Platform claims always identify Windows, macOS, and Linux separately. No document treats Linux behavior as portable Unix proof.

## Decision Log

| Decision | Status | Why |
| --- | --- | --- |
| Retain execution modes (`pty`, `exec`) | Accepted | Different semantics and resource/lifecycle needs are real. |
| Retain a native engine for released durable sessions | Provisional | Stronger current lifecycle and containment evidence than direct Bun or Bun-only bindings. Re-evaluate only after the Bun conformance gate. |
| Do not adopt `node-pty`, `bun-pty`, or `portable-pty` as a replacement | Accepted for this migration | They do not remove the hard ownership, durability, Job, and recovery work; `node-pty` has no supported Bun contract. |
| Remove the legacy in-daemon `Bun.spawn` exec path | Accepted | It duplicates the supported native path and provides weaker lifecycle semantics. |
| Redesign state before broad reliability fixes | Accepted | Current state combines lifecycle, observability, and cleanup flags, allowing contradictory records. |
| Retain the scoped ConPTY console-handle guard | Accepted locally | A controlled local A/B proves it is required for interactive and finite ConPTY output on this host; validate the supported Windows matrix before treating it as universal. |
| Scope idempotency to the full owner identity | Accepted | Correctness does not depend on an undocumented OpenCode session-ID uniqueness guarantee. |
| Only persistent sessions survive daemon recovery | Accepted target contract | Conversation sessions are reaped during recovery; persistence requires explicit opt-in. |
| Same OS user is the trusted local principal | Accepted threat model | Controls resist other-user access and accidental misuse, not malicious code already executing as the same user. |
| Interactive shells remain supported PTY workloads | Accepted product contract | Approval grants an interactive terminal capability and must say so clearly. |
| Preserve existing persisted data safely | Accepted migration policy | Terminal records migrate; old live records become owner-cleanable legacy tombstones rather than live target sessions. |
| Package-test all six published worker targets for release | Accepted | A published target is a release claim requiring executable evidence. |
| Fail closed for custom/inherited environments under transient approval | Accepted interim policy | OpenCode approval metadata cannot bind those options; explicit local `bash` allow is required instead. |
| Version persisted records before recovery | Implemented V2 cutover | V2 is the only writer and contains one discriminated state; V0/V1 readers import proven terminals with unknown stream drain and turn live/unproven records into cleanup-only unreachable tombstones. Explicit V0, unknown future, incomplete, and null-owner artifacts remain untouched and inert. |
| Persist worker reference before activation | Implemented checkpoint | The worker remains blocked on its authenticated bootstrap pipe until the daemon persists its verified reference; a failed reference write rolls back without starting a child. |
| Reap verified pre-start workers | Implemented checkpoint | A reference-bound no-child receipt is accepted only before a `start` frame; it permits deletion without inventing child/containment facts. |
| Reap verified post-start no-child workers | Implemented checkpoint | A full worker reference plus a retained descriptor can authenticate `spawn-failure.json` only when it proves `directChildStarted: false`; child-started failures are never treated as no-child. |
| Reuse fresh shutdown proof for normal terminal cleanup | Implemented checkpoint | A session that already proved terminal shutdown in-process can delete without a redundant reconnect, while crash-recovered terminal records still require fresh authenticated shutdown proof. |
| Use conservative per-owner reservations for admission | Implemented Phase 2 slice | A full-owner slot is reserved before the first record write; matching PTY reuse happens first, first-write failure releases, and uncertain/lost records continue to occupy capacity until strict proof or durable deletion releases them. |
| Remove daemon-side direct exec | Implemented Phase 2 slice | All supported exec requests now use the native worker path; list reads metadata without snapshotting workers. |
| Serialize session mutations | Implemented Phase 2 slice | Writes, send-and-wait input acceptance, resize, stop, finalization, cleanup marking, and durable deletion share one per-session lane. |
| Unify daemon shutdown | Implemented Phase 2 slice | `stop`, synchronous disposal, and async disposal share one idempotent descriptor-cleanup path. |
| Split the control-plane state owners | Implemented Phase 2 slice | `SessionRegistry` owns records/admission, `SessionRouter` owns workers/ordered control lanes, and `JournalReader` owns output paging/search. |
| Make V2 state authoritative | Implemented Phase 1 slice | `SessionSupervisor` reduces V2 state before projecting legacy fields for RPC compatibility; a terminal transition without strict child/containment or no-child evidence becomes an unreachable tombstone retaining its terminal payload. |
| Bound registry resources | Implemented Phase 1 slice | Registry reservations bound active sessions, durable records, pending waits, queued input, and aggregate retained output; terminal records are eligible for safe reaping after 24 hours. |
| Verify crash cutover | Implemented Phase 1 slice | Deterministic checkpoint tests cover pre-start/reference/finalization boundaries; a source-daemon crash/restart test proves a persistent live child reconnects without replaying its start frame. |

## Completion Gates

Research completes only when the open questions that could invalidate the target architecture are resolved or accepted as explicit product limits. Production readiness is separate: it requires the automated acceptance criteria in `testing-and-experiments.md`, on every supported operating system and packaged target.
