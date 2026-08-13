# Phase 0: Recover the Executable Baseline

**Status:** Partially verified. The local Windows x64 baseline and worker-level raw fixture are green; the published Windows matrix and close-order evidence remain release-blocking.

## Changes

1. Maintain the Windows worker-level ConPTY fixture for `cmd /c more` nonce echo, resize, Job stop, and Job drain. Add explicit close-order telemetry before treating it as complete cross-version evidence.
2. Bisect and compare the current launch logic with `a901d4a` and `c6713b2`; record parent std-handle types, Windows build, and console visibility.
3. Select the smallest documented launch path that passes the fixture. Do not retain temporary console manipulation unless it is necessary on the supported Windows floor and the fixture proves it.
4. Move the proven behavior into a focused worker integration test plus the packaged smoke contract.
5. Give the claimed-start-lock test an explicit deadline that covers its bounded Windows identity probes, then ensure cleanup waits for that test-owned work. Do not add retries.

## Local Progress

1. Guarded and unguarded worker runs isolate the local ConPTY failure to terminal attachment: disabling only the guard fails both live tests; restoring it passes the live and fresh-package contracts.
2. The retained configuration passed the fresh-package contract 20 consecutive times on local Windows x64.
3. Standard Rust rename replacement is directly tested on Windows, so the custom `MoveFileExW` experiment was deleted.
4. The claimed-start-lock test has an explicit 30-second deadline matching its Windows identity-probe budget; no retry was introduced.
5. The Windows-only raw fixture covers production spawn, nonce echo, resize, Job termination, and bounded Job drain.
6. Native-exec storage fault injection now has a file gate rather than a timer, and known worker storage failure remains `ESTORAGE` when containment is unresolved.

The Windows 10 1809/pre-24H2/24H2 matrix and close-order evidence remain incomplete.

## Why

- The initial package contract did not echo ConPTY input; guarded and unguarded local runs now demonstrate the attachment condition.
- The initial claimed-start-lock test timed out before its own Windows probe work completed.
- `a901d4a` introduced the guard and `c6713b2` removed it. The local A/B establishes local necessity, while only the fixture/matrix can establish a portable rule.

## Complexity Removed

- No custom Windows journal replacement wrapper is retained: standard rename replacement has direct test coverage.
- No retry was added for the start-lock test; its deadline now matches the operations it awaits.

## Invariants Afterward

- A locally validated Windows PTY has functional input/output, no visible console, and Job-owned cleanup. Bounded close remains unproven before Windows 11 24H2.
- Test teardown leaves no fixture directory, worker, or child before reporting success.
- No contract test relies on rerun/retry to pass.

## Platform Validation

| Platform | Required validation |
| --- | --- |
| Windows | 20 repeated fixture and packed-worker runs on Windows 10 version 1809, Windows 11 before 24H2, and Windows 11 24H2; include nonce, resize, finite output, stop, and Job-empty observation. If a build cannot support the contract, update the published README floor before excluding it. |
| Linux | Run existing PTY/package contract to ensure shared changes do not regress controlling terminal behavior. |
| macOS | Run existing PTY/package contract; record any unavailable runner as blocked. |

## Completion

- `bun unittest` is green from a clean workspace on local Windows.
- `bun package:smoke` passes 20 consecutive local Windows runs.
- Experiment report is added to `../testing-and-experiments.md` with precise version/build evidence.
- The root cause is classified as confirmed or explicitly remains a bounded platform workaround with regression coverage.
