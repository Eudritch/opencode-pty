# Phase 4: Verify, Package, and Gate Release

**Status:** Pending Phase 3

## Changes

1. Consolidate real-worker checks into a reusable native/package contract harness. It must run from the source worker and freshly installed optional package.
2. Run every PR native and packaged contract on Windows x64, Linux x64, and macOS arm64. Build the debug worker before tests that require it; make the release workflow use the same declared prerequisite.
3. After `native:sign`, run `native:verify` on the exact archive set. Fresh-install those verified signed worker packages, then run the package contract and validate checksum, provenance, signature, package metadata, import contract, daemon recovery, PTY, exec, cleanup, and no leaked worker. Pre-sign smoke is not signature/provenance validation.
4. Add crash-point, admission-isolation, unauthorized RPC, output/input pressure, repeated create/destroy, and shutdown drivers to the nightly suite.
5. Emit concise structured lifecycle diagnostics in the harness on failure: platform/build/runtime, state transitions, containment, reader drain, resource counters, and redacted error category.

## Why

- Current CI does not package-smoke macOS on PRs and currently pins a minimum Bun version without fresh green proof.
- `release.yml` builds only release worker before a Bun suite that expects a debug worker.
- Normal-path pass is insufficient for durable process infrastructure.

## Completion Criteria

1. Source and package contracts pass from clean workspaces on Windows, Linux, and macOS with the documented Bun version.
2. Windows PTY passes 20 consecutive nonce/resize/stop/package runs on each supported Windows family/build.
3. No identity-matching direct child or worker remains after successful stop/cleanup. Where containment is unknown, the result explicitly says unknown and retains/cleans tombstone according to policy.
4. Two owners cannot read, write, wait on, stop, clean, or consume approval state for each other's resources under concurrent load.
5. Repeated create/destroy and crash recovery stay within declared handle/process/disk budgets.
6. Release matrix proves every published optional package, not just a source-tree debug worker.

## Production Readiness Declaration

Only declare production readiness after this phase has recorded green artifacts for the supported OS/version matrix and all unresolved questions in `../open-questions.md` are either resolved or visible as accepted limitations in the public contract.
