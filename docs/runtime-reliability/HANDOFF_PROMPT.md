# Runtime Reliability Orchestrator Prompt

You are taking over the `opencode-pty` reliability program in the repository at:

`C:\Users\User\Desktop\Need\05 - Coding\opencode-pty`

You are not here to preserve upstream architecture.
You are here to finish the reliability program from the current state, using the existing research and plans as authoritative engineering memory.

## Prime Directive

Continue from where the prior agent stopped.
Do not restart research from zero.
Read the existing runtime-reliability docs first, then execute the remaining phases in order, updating the canonical docs as facts change.

Operate as an orchestrator:

- read the current plan/status docs first
- inspect the current worktree and tests before changing code
- delegate parallel research/review questions to subagents where useful
- implement in small, verified slices
- update docs after each verified slice
- commit and push incremental, coherent checkpoints as you go

## Required First Reads

Read these before editing anything:

1. `docs/runtime-reliability/README.md`
2. `docs/runtime-reliability/current-architecture.md`
3. `docs/runtime-reliability/evidence.md`
4. `docs/runtime-reliability/security-and-operations.md`
5. `docs/runtime-reliability/testing-and-experiments.md`
6. `docs/runtime-reliability/risk-scorecard.md`
7. `docs/runtime-reliability/open-questions.md`
8. `docs/runtime-reliability/target-architecture.md`
9. `docs/runtime-reliability/plan/README.md`
10. `docs/runtime-reliability/plan/01-contract-and-state.md`
11. `docs/runtime-reliability/plan/02-simplify-control-plane.md`
12. `README.md`

Then inspect the current worktree and recent commits.

## Current Truths

These are already implemented locally and must be preserved unless new evidence disproves them:

- Windows local ConPTY baseline is repaired with the scoped `PseudoConsoleStdioGuard` approach and raw worker fixture coverage.
- Lifecycle mutations go through the reducer in `src/daemon/lifecycle.ts`.
- PTY idempotency is scoped to the full owner identity.
- Recovery is persistent-only; conversation sessions are cleanup-only on restart.
- Transient approval rejects custom/inherited environments unless explicit local `bash` allow exists.
- V0 to V1 persisted record compatibility exists with strict owner/hash/proof rules.
- Pre-start and post-start no-child receipts exist and are strictly bound.
- Terminal cleanup reuses fresh in-process shutdown proof, while restart cleanup for conversation workers still requires a fresh authenticated shutdown.

## Hard External Blockers

You must never say the project is production-ready, cross-platform-ready, or release-ready unless all of these are actually validated and documented:

1. Windows 10 version 1809
2. Windows 11 before 24H2
3. Windows 11 24H2
4. ConPTY `ClosePseudoConsole` timing/order behavior on supported Windows builds
5. Bun `>=1.3.8` behavior on the supported matrix

If these are still unavailable, say so plainly and keep going on the code/docs/tests that can be completed locally.

## Current Phase Status

- Phase 0: locally green, externally incomplete due Windows matrix/close-order validation
- Phase 1: locally green for the implemented compatibility slice, but not complete overall because V2 persisted state, crash-cutover matrix, and budget work remain
- Phase 2: in progress
- Phase 3: pending
- Phase 4: pending

## Immediate Next Work

Resume exactly here:

### Phase 2 first slice

Finish and verify these items:

1. Remove all remaining legacy direct `supervisor.exec` test usage and stale typing.
2. Keep `supervisor.list()` metadata-only.
3. Complete Supervisor-owned per-owner reservations with conservative occupancy.
4. Ensure PTY idempotency is resolved before reservation and still works at capacity.
5. Ensure first-record write failure releases, later uncertainty retains, and durable proof/delete releases.
6. Add/repair focused tests for:
   - cap enforcement and concurrent same-owner requests
   - different-owner isolation
   - matching PTY idempotency at cap
   - lost/unproven restart occupancy
   - strict terminal/no-child release
   - preactivation starting-record cleanup
   - metadata-only list not snapshotting workers
   - admission isolation from unrelated worker liveness

### Phase 2 later slices

Only after the first slice is green:

1. Implement controller lanes for mutating operations.
2. Unify daemon async shutdown/disposal.
3. Update Phase 2 docs/status.

### Phase 1 remaining structural work

After Phase 2 is stable, return to the remaining Phase 1 deep work:

1. V2 persisted discriminated state codec
2. crash-point cutover matrix
3. explicit tombstone/resource budgets

Then Phase 3 and Phase 4 per the plan.

## Execution Rules

1. Do not redo settled research unless a contradiction appears.
2. Update the canonical doc instead of creating competing notes.
3. Keep changes minimal and evidence-driven.
4. Preserve the strict proof semantics already implemented.
5. Do not invent a global cap in Phase 2.
6. Do not reintroduce global worker snapshotting in admission.
7. Do not weaken lost/tombstone conservatism just to make tests easier.
8. Do not start V2/state-codec work until Phase 2 first slice is green.

## Validation Discipline

For each material slice, run the smallest focused tests first, then the broader gate.

When code changes are substantial, aim to finish with:

```bash
cargo fmt --check && cargo test --locked --workspace && cargo clippy --locked --workspace -- -D warnings && bun format && bun typecheck && bun test && bun unittest && bun package:smoke && git diff --check
```

If a subset is more appropriate for an intermediate slice, run that first, then the full gate before closing the slice.

## Git Expectations

The user explicitly wants commits and pushes as progress is made.

Before each commit:

1. inspect `git status --short`
2. inspect the relevant diff
3. ensure only intended files are staged
4. verify tests appropriate to the slice have passed

Then create a small, truthful commit and push it.

Do not batch unrelated slices into one commit.

## Reporting Rules

When you report status:

- distinguish local verification from unvalidated release claims
- name remaining blockers explicitly
- tie conclusions back to the docs/plan

## Starting Command Sequence

Start your work with this sequence:

1. Read the required docs listed above.
2. Inspect `git status --short` and the current Phase 2 diffs.
3. Finish the legacy direct-exec removal/test conversion.
4. Run focused reservation/typecheck tests.
5. Finish the reservation slice.
6. Run the full gate.
7. Update Phase 2 docs/status.
8. Commit and push that slice.

Proceed from there until no more locally-completable planned work remains.

## Final Honesty Rule

You are allowed to finish all locally-completable phases.
You are not allowed to say "production ready" unless the external OS/Bun matrix and Windows close-order evidence are actually complete.
