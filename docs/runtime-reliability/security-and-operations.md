# Security, Resource, and Observability Model

**Status:** Partially verified

## Current Positive Controls

| Control | Evidence |
| --- | --- |
| Loopback daemon with bearer token and strict POST/RPC validation | `src/daemon/server.ts:82-211` |
| Owner capability derived from private persistent secret, parent session, and canonical project directory | `src/plugin/pty/daemon-client.ts:589-622`, `src/daemon/server.ts:955-991` |
| Server overwrites client-supplied owner fields and checks every non-health operation | `src/daemon/server.ts:213-368` |
| Per-session worker endpoint has independent authenticated bootstrap/control | `src/daemon/worker-client.ts`, `worker/src/main.rs` |
| Safe/inherit environment profiles; raw values omitted from session metadata | `src/daemon/supervisor.ts:162-249` |
| Sensitive named environment values redacted before durable output | `worker/src/main.rs:1228-1290`, `2506-2688` |
| Restrictive Unix permissions and Windows DACL verification | `src/daemon/storage.ts:291-309`, `1247-1455` |
| Artifact signature/provenance checks in release flow | `.github/workflows/release.yml`, `scripts/native-artifact-verifier.ts` |
| Idempotent PTY reuse requires the full authenticated owner identity | `src/daemon/supervisor.ts` `idempotentSession()` and daemon tests |
| Lost cleanup retains an owner-scoped tombstone without strict shutdown/containment proof | `src/daemon/supervisor.ts` `cleanup()` and recovery tests |
| V1 writes require a complete owner tuple with a lowercase SHA-256 capability hash; V0 decoding does not infer unknown owners | `src/daemon/storage.ts` V0/V1 decoder and migration tests |
| Unsupported metadata is skipped untouched, while an incompatible worker reference is fenced from reconnect and orphan control | `src/daemon/storage.ts`, `src/daemon/supervisor.ts`, and migration audit tests |
| `worker.json` is retained until recursive session deletion succeeds | `rollbackNative()`, `deleteNativeSession()`, and descriptor-retention tests |
| Verified worker reference is persisted before the start frame permits child creation | `WorkerClient.prepare()`, supervisor launch paths, and pre-bind ordering tests |
| A no-child receipt is bound to the persisted worker identity and token hash before it permits pre-start deletion | `worker/src/main.rs`, `WorkerClient.hasVerifiedPrestartNoChildReceipt()`, and recovery test |
| A post-start no-child receipt needs both the retained descriptor and a full compatible worker reference | `WorkerClient.hasVerifiedNoChildSpawnFailureReceipt()`, `spawn_failed` recovery tests, and invalid-command cleanup |
| Normal terminal cleanup reuses fresh shutdown proof only within the running daemon; restart still requires a fresh authenticated shutdown for conversation workers | `SessionSupervisor.finalizeNativeVersion()`, `cleanup()`, and terminal cleanup tests |
| Per-owner session admission reserves before the first record write and remains conservative after uncertainty | `SessionRegistry.reserve()`, `rebuildSlots()`, `releaseIfSettled()`, and reservation tests |
| Registry-owned fixed budgets bound active sessions, durable records, waits, queued input, and aggregate retained output | `src/daemon/limits.ts`, `SessionRegistry`, quota regressions, and daemon diagnostics |
| One per-session lane serializes state-changing control operations | `SessionRouter.mutate()`, controller-lane and terminal-finalization tests |
| A foreign owner is rejected before a routed worker can be snapshotted | `SessionRouter.owns()`, `DaemonServer.authorize()`, and foreign-owner route test |

## Findings and Required Target Rules

| Finding | Evidence | Target rule |
| --- | --- | --- |
| Transient approval cannot bind `env` or `inheritEnv` | `createSpawnAuthorizer()` rejects non-empty `env` and `inheritEnv: true` before `ctx.ask` unless local `bash` policy explicitly allows the command; both adapters pass the options into that check | **Mitigated restrictively:** do not add an environment fingerprint to approval metadata. `pty_spawn` and `shell_exec` require explicit local `bash` allow for custom or inherited environments. |
| Sensitive values can extend streaming redaction state | Sensitive values are now rejected above 4,096 UTF-8 bytes in the effective daemon environment and worker bootstrap; Rust repeats the byte check | **Mitigated locally:** exact 4,096-byte ASCII/Unicode boundaries and complete multibyte EOF redaction have regression coverage. |
| Native worker writes can still block after TypeScript accepts input | The registry bounds queued mutation-lane bytes, but `write_all` remains synchronous in the worker | Phase 3 must add a bounded native input queue and stable `input_backpressure` outcome. |
| Tombstone retention is conservative rather than force-expiring | A 24-hour terminal cleanup attempt still requires ordinary strict proof | Keep failed cleanup evidence and let the durable-record cap deny new admission; add pressure/operations measurements in Phase 4. |
| Persisted-state cutover is one-way | V0 records are rewritten as V1 only after strict classification; an old daemon cannot safely interpret V1 tombstone semantics | Backward recovery means restoring the daemon-data backup, not running an old daemon against migrated state. |
| Persisted terminal facts may be incomplete | Status and `terminationConfirmed` alone are not proof of safe terminal cleanup | Require explicit direct-child and platform containment evidence for V0 migration and terminal cleanup. Otherwise retain a cleanup-only tombstone and preserve legacy output. |
| Terminal V0 log removal can be interrupted | Metadata and journal may be durable before old `output.log` removal | Persist a V1 cleanup marker, remove only after terminal migration is durable, and retry removal on later V1 loads. |
| Historic worker protocol mismatch | Worker RPC is version-sensitive and cannot safely be probed for shutdown | Retain the descriptor/output as an inert tombstone. A compatible daemon version or operator procedure is required for reaping. |
| Worker override path is a powerful runtime control | `PTY_NATIVE_WORKER_PATH` / development fallback in `worker-client.ts` | **Mitigated restrictively:** both path overrides and Cargo fallback require `PTY_NATIVE_WORKER_DEV=1`; released deployments fail closed. Same-user runtime identity validation remains outside the accepted threat model. |
| Terminal authorization is capability authorization | After PTY approval, `write` sends arbitrary input | Document this explicitly. Do not approve an interactive shell when policy intends to authorize only one command. |
| Batch scripts invoke `cmd.exe` | `worker/src/main.rs:734-762` | Mark `.cmd`/`.bat` as shell execution in policy/audit data. |

## Security Boundary Contract

1. Direct argv is the default and never gets shell parsing from this project.
2. A shell is an explicit execution kind with exact interpreter, script, environment profile, and workdir included in authorization/audit data.
3. A PTY is an interactive capability. It is not command-by-command authorization after creation.
4. Session identifiers are opaque application IDs; PID is diagnostic only and is never authorization identity.
5. A process operation requires both the session's owner capability and current state eligibility. A stale PID is never acted on without the engine's owned process handle or verified start identity.
6. The service does not claim sandboxing. Jobs/sessions help lifecycle containment, not privilege isolation, CPU quota, filesystem access, or network confinement.
7. A transient `ctx.ask` approval cannot authorize a changed execution environment. `pty_spawn` and `shell_exec` reject custom `env` and `inheritEnv: true` unless an explicit local `bash` allow rule covers the command.
8. Storage never invents an owner for legacy metadata. V0 records without a complete canonical owner tuple and lowercase SHA-256 capability hash, including null tuple fields, remain non-actionable and unchanged.
9. A worker descriptor is retained until the containing session directory is successfully deleted. An incompatible worker protocol grants this daemon no reconnect, shutdown, or PID-control authority.
10. A child is not eligible to start until the daemon has persisted the verified worker reference. Pre-start health is intentionally unavailable because the worker listener starts only after child creation.
11. Only a strict pre-start receipt can prove no child was eligible. It includes a raw worker token only in protected session storage; TypeScript compares its hash to the persisted reference and never logs it.
12. A post-start no-child receipt is weaker: it is valid only together with a retained `worker.json` bound to a full compatible worker reference, and it must explicitly say `directChildStarted: false` with `directChildPid: null`.
13. A terminal conversation record written by the running daemon may reuse its in-memory fresh shutdown proof for later cleanup in that same daemon. After restart, that memory is intentionally gone and cleanup must obtain fresh authenticated shutdown proof again.

## Resource Policy for the Target

| Resource | Enforcement point | Proposed behavior |
| --- | --- | --- |
| Active sessions | Daemon registry | 32 per owner, 64 globally; reserve before the first write. Unproven/lost records retain occupancy; strict terminal/no-child proof or deletion releases it. |
| Durable records | Daemon registry | 64 per owner, 128 globally. Strict terminals are eligible for normal cleanup after 24 hours on admission; uncertain tombstones are never force-deleted. |
| Pending waits | Daemon registry | 8 per session, 32 per owner, 128 globally. Immediate output/exit matches take no permit; pending waits release on match, terminal, deadline, or failed send-and-wait input. |
| Input queue | Daemon registry and native worker | 64 KiB per session, 256 KiB per owner, 1 MiB globally for queued controller-lane input; ingress also remains 64 KiB/request and 256 KiB/minute per owner. Native write backpressure remains Phase 3 work. |
| Output journal | Native worker writer and daemon registry | Per session: configured cap up to 64 MiB. Registry reserves 64 MiB per owner and 128 MiB globally; active/unreachable records reserve their cap and strict terminals retain actual bytes. |
| Aggregate disk | Daemon registry | Deny admission when durable-record or retained-output reservations are exhausted; diagnostics exposes owner/global use. |
| Runtime | Native engine | Exec always needs deadline; PTY deadline only when requested. Stop has a finite grace and one documented force phase. |
| Worker process | Daemon watchdog | One engine per live session; record and alarm on unreaped workers rather than deleting evidence. |

## Observability Contract

Emit structured lifecycle metadata, never terminal contents by default. Required fields: timestamp, session ID, owner hash (not secret), execution mode, platform/arch/runtime version, previous/new state, child PID only as diagnostic, worker identity, duration, exit category, containment observation, resource counters, and a stable error category.

Required events: `session_created`, `spawn_started`, `spawn_failed`, `child_running`, `input_rejected`, `resize_applied`, `output_truncated`, `child_exit_observed`, `stream_drain_complete`, `stop_requested`, `force_stop_requested`, `containment_observed`, `worker_unreachable`, `cleanup_complete`, `cleanup_unconfirmed`, and `daemon_shutdown`.

Worker stderr is continuously drained from a pipe into a bounded redacted startup-failure tail; normal worker stderr is discarded after draining. Do not inherit arbitrary worker stderr into a host log. Structured lifecycle events remain Phase 4 work.
