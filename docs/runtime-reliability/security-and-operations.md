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
| Per-owner session admission reserves before the first record write and remains conservative after uncertainty | `SessionSupervisor.reserveSlot()`, `rebuildOwnerSlots()`, `releaseSlotIfSettled()`, and reservation tests |
| One per-session lane serializes state-changing control operations | `SessionSupervisor.enqueueMutation()`, controller-lane and terminal-finalization tests |

## Findings and Required Target Rules

| Finding | Evidence | Target rule |
| --- | --- | --- |
| Transient approval cannot bind `env` or `inheritEnv` | `createSpawnAuthorizer()` rejects non-empty `env` and `inheritEnv: true` before `ctx.ask` unless local `bash` policy explicitly allows the command; both adapters pass the options into that check | **Mitigated restrictively:** do not add an environment fingerprint to approval metadata. `pty_spawn` and `shell_exec` require explicit local `bash` allow for custom or inherited environments. |
| Native bootstrap does not enforce the documented 4,096-byte secret limit | README says 4 KiB; RPC validation permits 16,384 UTF-16 code units, while native bootstrap forwards sensitive values without the 4,096-byte check | Enforce a 4,096 UTF-8-byte maximum before worker bootstrap and test split secrets at the limit. |
| Waiters, durable records, and aggregate output are unbounded | `wait` registrations have no aggregate cap; output cap is per session | Define per-owner and global budgets: active sessions, pending waits, input bytes/minute, retained bytes, terminal record TTL, and admission behavior. |
| Tombstone retention has no aggregate expiry/budget policy | Lost cleanup now retains metadata without strict shutdown/containment proof | Define owner/global tombstone count, disk budget, alerting, and an explicit operator expiry procedure. |
| Persisted-state cutover is one-way | V0 records are rewritten as V1 only after strict classification; an old daemon cannot safely interpret V1 tombstone semantics | Backward recovery means restoring the daemon-data backup, not running an old daemon against migrated state. |
| Persisted terminal facts may be incomplete | Status and `terminationConfirmed` alone are not proof of safe terminal cleanup | Require explicit direct-child and platform containment evidence for V0 migration and terminal cleanup. Otherwise retain a cleanup-only tombstone and preserve legacy output. |
| Terminal V0 log removal can be interrupted | Metadata and journal may be durable before old `output.log` removal | Persist a V1 cleanup marker, remove only after terminal migration is durable, and retry removal on later V1 loads. |
| Historic worker protocol mismatch | Worker RPC is version-sensitive and cannot safely be probed for shutdown | Retain the descriptor/output as an inert tombstone. A compatible daemon version or operator procedure is required for reaping. |
| Worker override path is a powerful runtime control | `PTY_NATIVE_WORKER_PATH` / development fallback in `worker-client.ts` | Production builds reject overrides unless an explicit development mode is enabled; if same-user installation integrity is in scope, verify worker identity at runtime. |
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
| Active sessions | Daemon registry | Per-owner quota atomically reserves before spawn. Unproven/lost records retain occupancy; strict terminal/no-child proof or successful deletion releases it. A global cap is intentionally not introduced in Phase 2. |
| Pending waits | Daemon session controller | Fixed per-session/per-owner quota; reject excess with `resource_limit`, never silently drop. |
| Input queue | Native worker | Bounded bytes and write count; preserve write order; return `not_running` or `input_backpressure` rather than allocate indefinitely. |
| Output journal | Native worker writer | Bounded per session; evict whole oldest chunks with durable sequence cursor; report truncation. |
| Aggregate disk | Daemon storage | Quota across owner and daemon root; deny new session or evict terminal records according to explicit retention policy. |
| Runtime | Native engine | Exec always needs deadline; PTY deadline only when requested. Stop has a finite grace and one documented force phase. |
| Worker process | Daemon watchdog | One engine per live session; record and alarm on unreaped workers rather than deleting evidence. |

## Observability Contract

Emit structured lifecycle metadata, never terminal contents by default. Required fields: timestamp, session ID, owner hash (not secret), execution mode, platform/arch/runtime version, previous/new state, child PID only as diagnostic, worker identity, duration, exit category, containment observation, resource counters, and a stable error category.

Required events: `session_created`, `spawn_started`, `spawn_failed`, `child_running`, `input_rejected`, `resize_applied`, `output_truncated`, `child_exit_observed`, `stream_drain_complete`, `stop_requested`, `force_stop_requested`, `containment_observed`, `worker_unreachable`, `cleanup_complete`, `cleanup_unconfirmed`, and `daemon_shutdown`.

Worker stderr must be treated as sensitive diagnostics: capture a bounded redacted ring or route only structured error categories to the daemon. Do not inherit arbitrary worker stderr into a host log by default.
