# Architecture and Production-Readiness Scorecards

**Status:** Partially verified

## Scale

Scores use 1-5: **1** broken or unproven for a required contract, **2** substantial known risk, **3** adequate with known gaps, **4** strong evidence and bounded risk, **5** simple/demonstrated/operationally sustainable. A score is not a substitute for its cited evidence.

## Current Architecture Scorecard

| Dimension | Score | Evidence and explanation |
| --- | ---: | --- |
| Simplicity | 2 | Registry, worker routing, and journal reads are separated from the supervisor, and legacy daemon-side exec is deleted; server, storage, and mixed-platform worker remain large. |
| Lifecycle determinism | 4 | The V2 state reducer blocks stale regression, preserves terminal evidence through unreachable/cleaning tombstones, and V0/V1 imports fence legacy live state; crash-matrix evidence remains incomplete. |
| PTY correctness | 2 | Local guarded ConPTY live/package contracts pass, but supported-build and close-order evidence is incomplete. |
| Windows reliability | 2 | Local recovery is repeatable, but there is no Windows version/architecture matrix and the Bun minimum remains unproven. |
| Linux reliability | 3 | Conservative direct-child and `/proc` containment evidence; needs fresh full-matrix verification. |
| macOS reliability | 2 | Native path exists, but CI/build and packaged-smoke evidence is incomplete; descendant verification is intentionally unavailable. |
| Concurrency isolation | 4 | Owner capability and per-session workers isolate data; full-owner reservations replace global worker polling, controller lanes serialize mutations, and focused tests prove unrelated liveness cannot delay admission. |
| Durability/recovery | 3 | Persistent recovery and conversation cleanup/tombstones are explicit; verified worker references persist before activation; rollback/deletion retain reaping credentials; normal terminal cleanup now reuses fresh shutdown proof without a redundant reconnect; and incompatible workers are inert. Crash matrix and cross-platform evidence remain incomplete. |
| Resource bounding | 3 | Per-session output and input limits exist; aggregate retained-byte, process, waiter, and durable-record budgets do not. |
| Security | 3 | Strong loopback/capability/DACL controls; full-owner reuse, owner-safe V0 decoding, tombstone retention, and fail-closed dynamic environments improve isolation, but worker override and aggregate policy remain open. |
| Observability | 3 | Structured records and diagnostics exist, but lifecycle events are not a concise authoritative stream and worker stderr can leak to host logs. |
| Testability | 3 | Local source/package contracts and reducer/recovery regressions pass; platform gates and crash/stress coverage remain incomplete. |
| Installation/release | 3 | Signed/provenanced optional artifacts are strong; six-target release is costly and macOS package smoke is absent from PR gate. |
| Long-term sustainability | 2 | Rapid repair history and concentrated mixed-platform code raise regression cost. |

**Current weighted conclusion:** Not production ready. The local Windows PTY break is repaired and the control plane has one persisted V2 state authority, but build-matrix evidence, crash coverage, and aggregate resource limits remain open.

## Production-Readiness Blockers

| Blocker | Evidence | Required closure |
| --- | --- | --- |
| Windows PTY has no supported-build matrix | Local live/package contract passes 20/20 with the guard; no Windows 10/pre-24H2/24H2 evidence | Phase 0 raw fixture and 20 clean repeated runs on each published Windows variant. |
| Start-lock test deadline was shorter than its Windows work | Local `bun unittest` passes after an explicit 30-second budget | Keep the explicit deadline; no retry masking. |
| Declared Bun 1.3.8 contract not established | CI pins 1.3.8 while local works on 1.3.14; historical matrix failures reported | Green exact-version matrix or raise and pin minimum. |
| Crash and tombstone-retention policy remain incomplete | V2 is the only persisted writer, but interruption coverage and terminal-retention limits are incomplete | Complete the crash matrix and enforce tombstone retention budget. |
| Release test prerequisite mismatch | `README.md` says debug worker required; release builds release worker before Bun suite | Build/test the declared worker artifact from a clean checkout. |
| Aggregate resource policy absent | Unbounded waiters and aggregate output/durable records | Define and enforce budgets before service claims. |

## Root-Cause Families

| Family | Symptoms | Architectural response |
| --- | --- | --- |
| Terminal lifecycle conflated with child lifecycle | Early/late output loss, close hangs, false exit claims | Record child exit, stream drain, and containment observations independently; terminal outcome only after explicit finalization policy. |
| Recoverability conflated with process lifetime | `lost` sessions skip cleanup or delete recovery metadata | Treat unreachable control as an observation; retain tombstones and worker credentials until reaping result is known. |
| Distributed state with global reconciliation | Unrelated spawn delays; stale workers; race repair queues | Registry is authoritative for admission; a session has one controller; reconcile only targeted/stale records. |
| Platform policy spread across layers | Different Windows rename behavior; unclear cleanup guarantees | Each platform mechanism belongs in the native engine; one storage owner defines filesystem persistence policy. |
| Compatibility workarounds without conformance proof | Console-allocation regression; minimum Bun mismatch | Keep a documented experiment and release gate for each workaround; delete unproven paths. |
