# Migration Plan

**Status:** Sequential plan. Phase 0 is a hard stop/go gate; later phases must consume the evidence documents rather than repeat their research.

| Phase | Status | Document | Completion outcome |
| --- | --- | --- | --- |
| 0 | Locally green, externally incomplete | [00-recover-baseline.md](00-recover-baseline.md) | Explain and regress Windows ConPTY failure; restore deterministic test baseline. |
| 1 | In progress | [01-contract-and-state.md](01-contract-and-state.md) | Freeze portable contract, ownership, budgets, and state transition model. |
| 2 | In progress | [02-simplify-control-plane.md](02-simplify-control-plane.md) | Duplicate exec/global admission polling are deleted and controller lanes are live; the planned responsibility split remains. |
| 3 | Pending | [03-native-engine-and-security.md](03-native-engine-and-security.md) | Narrow engine boundary, complete platform lifecycle policy, fix security/resource rules. |
| 4 | Pending | [04-verification-and-release.md](04-verification-and-release.md) | Green native/package contract matrix and release evidence. |

## Rules for Implementation Agents

1. Read `../README.md`, `../target-architecture.md`, relevant evidence, and all preceding completed phases before editing.
2. Update the canonical research document if a result contradicts it. Do not create a competing plan.
3. Run the exact completion checks on the local platform and record unavailable platform checks as unverified, not passed.
4. Do not retain a compatibility path unless released data or an external consumer needs it. If it is needed, identify the supported versions and deletion date.
5. Do not begin a later phase when the prior phase's stop/go condition is unresolved.

## Open-Question Gates

| Before phase | Questions that must be resolved or explicitly accepted in the public contract |
| --- | --- |
| 1 | OQ-01; OQ-03, OQ-04, and OQ-07 are accepted target policies and must be encoded. |
| 3 | OQ-05 and OQ-06 are accepted target policies and must be encoded. |
| 4 / release | OQ-02, OQ-08, OQ-09 |
