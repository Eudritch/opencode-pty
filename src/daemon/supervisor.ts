import { realpathSync } from 'node:fs'
import { join, resolve } from 'node:path'
import type { PTYSessionInfo, ReadResult, SearchResult, SpawnOptions } from '../plugin/pty/types.ts'
import { NATIVE_WORKER_PROTOCOL_VERSION } from '../shared/native-worker-targets.ts'
import { DaemonError } from './errors.ts'
import { JournalReader, lineCount } from './journal-reader.ts'
import { isActiveDaemonStatus, reduceDaemonStatus, type LifecycleEvent } from './lifecycle.ts'
import { containmentDrained, SessionRegistry, terminalDirectChild } from './session-registry.ts'
import { SessionRouter } from './session-router.ts'
import type { DaemonStorage } from './storage.ts'
import type { SpawnFailure } from './types.ts'
import {
  type EnvironmentProfile,
  type ExecResult,
  type ExitReason,
  MAX_EXEC_RUNTIME_SECONDS,
  MAX_EXEC_WAIT_SECONDS,
  OUTPUT_JOURNAL_VERSION,
  SESSION_RECORD_VERSION,
  type SessionRecord,
  type StopResult,
  type WaitCondition,
  type WaitResult,
  type WorkerPrestartAuthority,
  type WorkerReference,
  type WriteResult,
} from './types.ts'
import type { WorkerClient, WorkerSnapshot } from './worker-client.ts'
import { WorkerClient as NativeWorkerClient, WorkerStartError } from './worker-client.ts'

const DEFAULT_MAX_OUTPUT_BYTES = 1000000
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024
const RECOVERY_CONCURRENCY = 4
const EXEC_TERMINAL_WAIT_SECONDS = MAX_EXEC_WAIT_SECONDS - MAX_EXEC_RUNTIME_SECONDS
const SAFE_ENVIRONMENT_KEYS = new Set([
  'PATH',
  'HOME',
  'USERPROFILE',
  'APPDATA',
  'LOCALAPPDATA',
  'SYSTEMROOT',
  'SYSTEMDRIVE',
  'WINDIR',
  'TEMP',
  'TMP',
  'TERM',
  'LANG',
  'ComSpec',
  'ProgramData',
  'ALLUSERSPROFILE',
  'PATHEXT',
  'PUBLIC',
])
const SENSITIVE_ENVIRONMENT_KEY =
  /(token|secret|password|credential|api[_-]?key|auth|cookie|(?:^|[_-])(?:ssh|tls)?[_-]?private[_-]?key(?:$|[_-])|(?:^|[_-])signing[_-]?key(?:$|[_-]))/i

export interface ExecOptions extends SpawnOptions {
  maxOutputBytes?: number
}

interface PendingWait {
  condition: WaitCondition
  settle: (result: WaitResult) => void
  timer: ReturnType<typeof setTimeout>
  settled: boolean
}

export class ProcessError extends Error {
  constructor(
    message: string,
    readonly spawnFailure?: SpawnFailure
  ) {
    super(message)
  }
}

export function effectiveMaxOutputBytes(value = process.env.PTY_MAX_OUTPUT_BYTES): number {
  const parsed = Number.parseInt(value ?? '', 10)
  return Number.isSafeInteger(parsed) && parsed > 0
    ? Math.min(parsed, MAX_OUTPUT_BYTES)
    : DEFAULT_MAX_OUTPUT_BYTES
}

function safeRegex(pattern: string): RegExp {
  if (pattern.length > 512 || /[()*+?{|}]/.test(pattern) || /\\[1-9]/.test(pattern)) {
    throw new Error('Regex wait pattern is outside the limited-safe subset.')
  }
  try {
    return new RegExp(pattern)
  } catch {
    throw new Error('Invalid regex wait pattern.')
  }
}

function activeStatus(record: SessionRecord): boolean {
  return isActiveDaemonStatus(record.status)
}

// Sessions without an explicit workdir run in the owner's project directory, never in whatever
// directory the daemon process happens to have been started from.
function canonicalWorkdir(workdir: string | undefined, ownerProjectDirectory?: string): string {
  return realpathSync(resolve(workdir ?? ownerProjectDirectory ?? process.cwd()))
}

function canonicalEnv(env: Record<string, string> | undefined): string {
  return JSON.stringify(
    Object.entries(env ?? {}).sort(([left], [right]) => left.localeCompare(right))
  )
}

function environmentProfile(env: Record<string, string>, inherited: boolean): EnvironmentProfile {
  const sourceKeys = Object.keys(env)
  const keys = sourceKeys
    .map((key) => (SENSITIVE_ENVIRONMENT_KEY.test(key) ? '[REDACTED_ENV_KEY]' : key))
    .sort()
  return {
    kind: inherited ? 'inherit' : 'safe',
    keys,
    fingerprint: new Bun.CryptoHasher('sha256').update(canonicalEnv(env)).digest('hex'),
    sensitive: sourceKeys.some((key) => SENSITIVE_ENVIRONMENT_KEY.test(key)),
  }
}

export function runtimeEnvironment(
  requested: Record<string, string> | undefined,
  inherit: boolean,
  source: NodeJS.ProcessEnv = process.env,
  windows = process.platform === 'win32'
): Record<string, string> {
  const isPath = (key: string) => (windows ? key.toUpperCase() === 'PATH' : key === 'PATH')
  const isSafe = (key: string) => {
    if (!windows) return SAFE_ENVIRONMENT_KEYS.has(key)
    return [...SAFE_ENVIRONMENT_KEYS].some((safe) => safe.toUpperCase() === key.toUpperCase())
  }
  const trustedPath = Object.entries(source).find(([key]) => isPath(key))?.[1]
  const base = inherit
    ? source
    : Object.fromEntries(
        Object.entries(source).filter(
          ([key]) => isPath(key) || isSafe(key) || key.startsWith('LC_')
        )
      )
  // Native worker knobs are daemon-controlled fault/readiness injection points; caller-supplied
  // or inherited copies must never reach user commands.
  const environment = Object.fromEntries(
    [...Object.entries(base), ...Object.entries(requested ?? {})].filter(
      ([key]) => !isPath(key) && !/^OPENCODE_PTY_NATIVE_WORKER_/.test(key)
    )
  ) as Record<string, string>
  // ponytail: command lookup gets only the daemon's PATH; callers cannot redirect an allowed bare command.
  if (trustedPath !== undefined) environment.PATH = trustedPath
  return environment
}

export class SessionSupervisor {
  private readonly registry = new SessionRegistry()
  private readonly waits = new Map<string, PendingWait[]>()
  private readonly router = new SessionRouter(this.registry)
  private readonly nativeFinalizations = new Map<string, Promise<ExecResult | PTYSessionInfo>>()
  private readonly pendingConversationCleanup = new Map<string, Promise<void>>()
  private readonly confirmedWorkerShutdowns = new Set<string>()
  private readonly journal: JournalReader
  private persistQueue = Promise.resolve()

  constructor(
    private readonly storage: DaemonStorage,
    private readonly maxOutputBytes: number = effectiveMaxOutputBytes(),
    private readonly recoveryAttempts = 30,
    private readonly recoveryRetryMs = 100
  ) {
    this.journal = new JournalReader(storage, () => this.flush())
  }

  private get records(): Map<string, SessionRecord> {
    return this.registry.records
  }

  private get nativeWorkers(): Map<string, WorkerClient> {
    return this.router.workers
  }

  async initialize(reconnect = true): Promise<void> {
    await this.storage.initialize()
    for (const record of await this.storage.loadSessions()) {
      if (record.status === 'starting' && !record.worker && !record.workerPrestart) {
        try {
          await this.storage.deleteSession(record.id)
          continue
        } catch (error) {
          console.warn(
            `Retained pre-activation PTY session ${JSON.stringify(record.id)} after cleanup failed: ${String(error)}.`
          )
        }
      }
      this.records.set(record.id, record)
      if (
        record.worker &&
        record.worker.protocolVersion !== NATIVE_WORKER_PROTOCOL_VERSION &&
        !terminalDirectChild(record)
      ) {
        this.transition(record, 'unreachable')
        record.terminationConfirmed = false
        record.exitReason = {
          kind: 'unknown',
          message: `Native worker protocol v${record.worker.protocolVersion} is incompatible with this daemon; output remains readable but the worker cannot be reconnected or controlled.`,
        }
        record.updatedAt = new Date().toISOString()
        await this.storage.writeSession(record)
      }
    }
    this.registry.rebuildSlots()
    if (reconnect) {
      await this.reconcileWorkers()
    }
  }

  async reconcileWorkers(): Promise<void> {
    const pending = [...this.records.values()].filter(
      (record) =>
        !this.incompatibleWorker(record) &&
        (!record.legacyTombstone || record.pendingCleanup === true) &&
        (this.prestartReceiptAuthority(record) !== undefined ||
          this.postStartNoChildFailureEligible(record) ||
          (record.lifecycle === 'persistent' &&
            (activeStatus(record) || record.status === 'lost')) ||
          (record.pendingCleanup === true && (activeStatus(record) || record.status === 'lost')))
    )
    let next = 0
    await Promise.all(
      Array.from({ length: Math.min(RECOVERY_CONCURRENCY, pending.length) }, async () => {
        while (next < pending.length) {
          const record = pending[next++]
          if (!record) continue
          await this.reconcileWorker(record).catch((error) =>
            console.warn(
              `Skipped PTY worker recovery for ${JSON.stringify(record.id)}: ${String(error)}.`
            )
          )
        }
      })
    )
  }

  private async reconcileWorker(record: SessionRecord): Promise<void> {
    if (this.incompatibleWorker(record)) return
    const prestartAuthority = this.prestartReceiptAuthority(record)
    if (prestartAuthority) {
      for (let attempt = 0; attempt < this.recoveryAttempts; attempt += 1) {
        if (
          await NativeWorkerClient.hasVerifiedPrestartNoChildReceipt(
            join(this.storage.rootDirectory, 'sessions', record.id),
            prestartAuthority
          )
        ) {
          await this.deleteNativeSession(record)
          return
        }
        if (attempt + 1 < this.recoveryAttempts) await Bun.sleep(this.recoveryRetryMs)
      }
      return
    }
    if (await this.hasVerifiedNoChildSpawnFailure(record)) {
      await this.deleteNativeSession(record)
      return
    }
    const reference = record.worker
    let worker: WorkerClient | null = null
    if (reference) {
      for (let attempt = 0; attempt < this.recoveryAttempts && !worker; attempt += 1) {
        worker = await NativeWorkerClient.reconnect(
          join(this.storage.rootDirectory, 'sessions', record.id),
          reference
        )
        if (!worker && attempt + 1 < this.recoveryAttempts) await Bun.sleep(this.recoveryRetryMs)
      }
    }
    if (worker) {
      if (record.pendingCleanup) {
        this.nativeWorkers.set(record.id, worker)
        await this.cleanupConversation(record)
        return
      }
      if (record.status === 'lost') {
        const snapshot = await worker.snapshot()
        // A lost response is not evidence that the session is usable again. Only an authenticated
        // live or terminal snapshot can leave the tombstone state.
        if (snapshot.status === 'lost' || !this.transition(record, 'recovered')) return
        this.nativeWorkers.set(record.id, worker)
        if (this.nativeTerminal(snapshot)) {
          await this.finalizeNative(record, worker, snapshot)
          return
        }
        await this.finishNative(record, snapshot)
        void this.monitorNative(record, worker)
        return
      }
      this.nativeWorkers.set(record.id, worker)
      void this.monitorNative(record, worker)
      return
    }
    // The worker is unreachable as a session but may still be running; PTY workers have no
    // deadline, so a best-effort termination is the only thing preventing immortal orphans.
    if (record.lifecycle !== 'persistent' || record.pendingCleanup)
      await this.terminateOrphanWorker(record)
    const output = await this.storage.readOutput(record.id)
    this.transition(record, 'unreachable')
    record.exitReason = { kind: 'unknown' }
    record.outputBytes = Buffer.byteLength(output)
    record.lineCount = lineCount(output)
    record.outputHasPartialLine = Boolean(output) && !output.endsWith('\n')
    record.updatedAt = new Date().toISOString()
    await this.storage.writeSession(record)
  }

  async markConversationRecoveryCleanup(): Promise<void> {
    const terminal: SessionRecord[] = []
    for (const record of this.records.values()) {
      if (record.lifecycle !== 'conversation') continue
      if (activeStatus(record) || record.status === 'lost') {
        if (record.pendingCleanup) continue
        record.pendingCleanup = true
        record.updatedAt = new Date().toISOString()
        await this.storage.writeSession(record)
      } else if (this.isTerminal(record)) {
        terminal.push(record)
      }
    }
    await Promise.all(terminal.map((record) => this.cleanupConversation(record)))
  }

  async spawn(options: SpawnOptions, maxSessionsPerOwner = 32): Promise<PTYSessionInfo> {
    await this.flush()
    if (!options.command) throw new Error('command is required')
    if (
      options.timeoutSeconds !== undefined &&
      (!Number.isInteger(options.timeoutSeconds) || options.timeoutSeconds <= 0)
    ) {
      throw new Error('timeoutSeconds must be a positive integer in seconds')
    }
    const args = options.args ?? []
    const existing = this.idempotentSession(options, args)
    if (existing) return this.toInfo(existing)
    const id = `pty_${crypto.randomUUID()}`
    const now = new Date().toISOString()
    const environment = runtimeEnvironment(options.env, options.inheritEnv === true)
    const record: SessionRecord = {
      recordVersion: SESSION_RECORD_VERSION,
      id,
      title:
        options.title ??
        (`${options.command} ${args.join(' ')}`.trim() || `Terminal ${id.slice(-8)}`),
      description: options.description,
      command: options.command,
      args,
      mode: 'pty',
      name: options.name,
      idempotencyKey: options.idempotencyKey,
      workdir: canonicalWorkdir(options.workdir, options.ownerProjectDirectory),
      ownerProjectDirectory: canonicalWorkdir(options.ownerProjectDirectory ?? options.workdir),
      ownerCapabilityHash: options.ownerCapabilityHash ?? '',
      lifecycle: options.lifecycle ?? 'conversation',
      environment: environmentProfile(environment, options.inheritEnv === true),
      status: 'starting',
      pid: 0,
      createdAt: now,
      startedAt: now,
      updatedAt: now,
      parentSessionId: options.parentSessionId,
      parentAgent: options.parentAgent,
      timeoutSeconds: options.timeoutSeconds,
      timedOut: false,
      terminationRequested: false,
      terminationConfirmed: false,
      directChildExited: false,
      nextSequence: 0,
      firstRetainedSequence: 0,
      outputBytes: 0,
      outputTruncated: false,
      lineCount: 0,
      outputHasPartialLine: false,
      outputJournalVersion: OUTPUT_JOURNAL_VERSION,
    }
    const reservation = this.registry.reserve(record, maxSessionsPerOwner)
    this.records.set(id, record)
    this.registry.commit(reservation)
    try {
      await this.storage.writeSession(record)
    } catch (error) {
      this.records.delete(id)
      this.registry.releaseReservation(reservation)
      throw error
    }
    let prepared: Awaited<ReturnType<typeof NativeWorkerClient.prepare>> | undefined
    try {
      prepared = await NativeWorkerClient.prepare(
        {
          command: record.command,
          args: record.args,
          workdir: record.workdir,
          env: environment,
          redactionSecrets: this.redactionSecrets(environment),
          sessionDirectory: join(this.storage.rootDirectory, 'sessions', id),
          timeoutSeconds: options.timeoutSeconds,
          maxOutputBytes: this.maxOutputBytes,
          mode: 'pty',
          cols: 120,
          rows: 40,
        },
        async (authority) => {
          record.workerPrestart = authority
          record.workerStartAttempted = false
          record.updatedAt = new Date().toISOString()
          await this.storage.writeSession(record)
        }
      )
      record.worker = prepared.reference
      record.workerStartAttempted = false
      record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(record)
      record.workerStartAttempted = true
      try {
        await this.storage.writeSession(record)
      } catch (error) {
        record.workerStartAttempted = false
        throw error
      }
      const initial = await prepared.client.start()
      record.pid = initial.pid
      record.containment = initial.containment
      record.termination = initial.termination
      this.transition(record, 'worker_ready')
      record.updatedAt = new Date().toISOString()
      this.nativeWorkers.set(id, prepared.client)
      await this.storage.writeSession(record)
      void this.monitorNative(record, prepared.client)
      return this.toInfo(record)
    } catch (error) {
      const cleanup =
        error instanceof WorkerStartError
          ? error.cleanup
          : prepared
            ? await prepared.client.rollback().catch((rollbackError) => ({
                requested: false,
                terminationConfirmed: false,
                method: 'none' as const,
                message: String(rollbackError),
              }))
            : { requested: false, terminationConfirmed: false, method: 'none' as const }
      if (!prepared && error instanceof WorkerStartError && error.prestartReference) {
        record.worker = error.prestartReference
        record.workerStartAttempted = false
      }
      this.transition(record, cleanup.terminationConfirmed ? 'spawn_failed' : 'unreachable')
      record.terminationRequested = cleanup.requested
      record.terminationConfirmed = cleanup.terminationConfirmed
      record.exitReason = {
        kind: 'spawn_error',
        message: error instanceof Error ? error.message : String(error),
        cleanup,
      }
      record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(record)
      this.registry.releaseIfSettled(record)
      if (error instanceof WorkerStartError && error.noWorkerSpawned)
        await this.deleteNativeSession(record).catch(() => false)
      throw new ProcessError(
        `Failed to spawn PTY '${id}': ${error instanceof Error ? error.message : String(error)}`,
        { cleanup }
      )
    }
  }

  async write(id: string, data: string): Promise<WriteResult> {
    await this.flush()
    return this.enqueueMutation(id, async () => {
      const worker = this.nativeWorkers.get(id)
      const record = this.recordFor(id)
      if (!worker || record.status !== 'running' || record.pendingCleanup)
        throw new DaemonError(`PTY session '${id}' is closed.`, 'session_closed')
      try {
        await worker.write(data)
        return { acceptedBytes: Buffer.byteLength(data), acceptedCharacters: [...data].length }
      } catch (error) {
        throw new ProcessError(
          `Failed to write to PTY '${id}': ${error instanceof Error ? error.message : String(error)}`
        )
      }
    })
  }

  async sendWait(
    id: string,
    data: string,
    condition: WaitCondition,
    timeoutSeconds: number
  ): Promise<WaitResult> {
    await this.flush()
    this.validateWait(condition, timeoutSeconds)
    const afterSequence = await this.enqueueMutation(id, async () => {
      const worker = this.nativeWorkers.get(id)
      const record = this.recordFor(id)
      if (!worker || record.status !== 'running' || record.pendingCleanup)
        throw new DaemonError(`PTY session '${id}' is closed.`, 'session_closed')
      try {
        // The worker returns the cursor at the input acceptance boundary. On Windows this is before
        // WriteFile because ConPTY reads block and an immediate echo may be published concurrently.
        return (await worker.write(data)).arrivalSequence
      } catch (error) {
        throw new ProcessError(
          `Failed to write to PTY '${id}': ${error instanceof Error ? error.message : String(error)}`
        )
      }
    })
    return this.wait(
      id,
      { ...condition, ...(condition.kind === 'output' ? { afterSequence } : {}) },
      timeoutSeconds
    )
  }

  async resize(id: string, cols: number, rows: number): Promise<{ cols: number; rows: number }> {
    await this.flush()
    return this.enqueueMutation(id, async () => {
      const record = this.recordFor(id)
      if (record.mode !== 'pty') throw new Error(`Session '${id}' is not a PTY.`)
      if (record.status !== 'running' || record.pendingCleanup)
        throw new DaemonError(`PTY session '${id}' is closed.`, 'session_closed')
      const worker = this.nativeWorkers.get(id)
      if (!worker) throw new DaemonError(`PTY session '${id}' is closed.`, 'session_closed')
      return worker.resize(cols, rows)
    })
  }

  async wait(id: string, condition: WaitCondition, timeoutSeconds: number): Promise<WaitResult> {
    await this.flush()
    this.validateWait(condition, timeoutSeconds)
    const record = this.recordFor(id)
    if (record.pendingCleanup || record.status === 'lost')
      throw new DaemonError(`PTY session '${id}' is closed.`, 'session_closed')
    const matched = await this.waitMatch(record, condition)
    if (matched) return this.finishWait(record, matched)
    if (!activeStatus(record)) return this.finishWait(record, this.waitEnded(record, condition))
    return new Promise<WaitResult>((resolve) => {
      const timer = setTimeout(() => {
        pending.settle({
          satisfied: false,
          reason: 'deadline',
          observedAt: new Date().toISOString(),
          outputTruncated: record.outputTruncated,
        })
      }, timeoutSeconds * 1000)
      const pending: PendingWait = {
        condition,
        timer,
        settled: false,
        settle: (result) => {
          if (pending.settled) return
          pending.settled = true
          this.removeWait(id, pending)
          void this.finishWait(record, result).then(resolve)
        },
      }
      const pendingWaits = this.waits.get(id) ?? []
      pendingWaits.push(pending)
      this.waits.set(id, pendingWaits)
      void this.waitMatch(record, condition).then(async (result) => {
        if (!result) return
        pending.settle(result)
      })
    })
  }

  async nativeExec(options: ExecOptions, maxSessionsPerOwner = 32): Promise<ExecResult> {
    const session = await this.nativeExecStart(options, maxSessionsPerOwner)
    return this.nativeExecWait(
      session.id,
      Math.min((options.timeoutSeconds ?? 0) + EXEC_TERMINAL_WAIT_SECONDS, MAX_EXEC_WAIT_SECONDS)
    )
  }

  async nativeExecStart(
    options: ExecOptions,
    maxSessionsPerOwner = 32
  ): Promise<{ id: string; status: SessionRecord['status']; mode: 'exec'; pid: number }> {
    await this.flush()
    if (!options.command) throw new Error('command is required')
    const timeoutSeconds = options.timeoutSeconds
    if (
      timeoutSeconds === undefined ||
      !Number.isInteger(timeoutSeconds) ||
      timeoutSeconds <= 0 ||
      timeoutSeconds > MAX_EXEC_RUNTIME_SECONDS
    )
      throw new Error(
        `timeoutSeconds must be a positive integer up to ${MAX_EXEC_RUNTIME_SECONDS} for exec`
      )
    const args = options.args ?? []
    const now = new Date().toISOString()
    const id = `exec_${crypto.randomUUID()}`
    const environment = runtimeEnvironment(options.env, options.inheritEnv === true)
    const record: SessionRecord = {
      recordVersion: SESSION_RECORD_VERSION,
      id,
      title: options.title ?? `${options.command} ${args.join(' ')}`.trim(),
      description: options.description,
      command: options.command,
      args,
      mode: 'exec',
      workdir: canonicalWorkdir(options.workdir, options.ownerProjectDirectory),
      ownerProjectDirectory: canonicalWorkdir(options.ownerProjectDirectory ?? options.workdir),
      ownerCapabilityHash: options.ownerCapabilityHash ?? '',
      lifecycle: options.lifecycle ?? 'conversation',
      environment: environmentProfile(environment, options.inheritEnv === true),
      status: 'starting',
      pid: 0,
      createdAt: now,
      startedAt: now,
      updatedAt: now,
      parentSessionId: options.parentSessionId,
      parentAgent: options.parentAgent,
      timeoutSeconds,
      timedOut: false,
      terminationRequested: false,
      terminationConfirmed: false,
      nextSequence: 0,
      firstRetainedSequence: 0,
      outputBytes: 0,
      outputTruncated: false,
      lineCount: 0,
      outputHasPartialLine: false,
      outputJournalVersion: OUTPUT_JOURNAL_VERSION,
    }
    const reservation = this.registry.reserve(record, maxSessionsPerOwner)
    this.records.set(id, record)
    this.registry.commit(reservation)
    try {
      await this.storage.writeSession(record)
    } catch (error) {
      this.records.delete(id)
      this.registry.releaseReservation(reservation)
      throw error
    }
    const redactionSecrets = Object.entries(environment)
      .filter(([key, value]) => SENSITIVE_ENVIRONMENT_KEY.test(key) && value.length >= 4)
      .map(([, value]) => value)
    let prepared: Awaited<ReturnType<typeof NativeWorkerClient.prepare>> | undefined
    try {
      prepared = await NativeWorkerClient.prepare(
        {
          command: record.command,
          args: record.args,
          workdir: record.workdir,
          env: environment,
          redactionSecrets,
          sessionDirectory: join(this.storage.rootDirectory, 'sessions', id),
          timeoutSeconds,
          maxOutputBytes: Math.min(
            options.maxOutputBytes ?? this.maxOutputBytes,
            this.maxOutputBytes
          ),
          mode: 'exec',
        },
        async (authority) => {
          record.workerPrestart = authority
          record.workerStartAttempted = false
          record.updatedAt = new Date().toISOString()
          await this.storage.writeSession(record)
        }
      )
      record.worker = prepared.reference
      record.workerStartAttempted = false
      record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(record)
      record.workerStartAttempted = true
      try {
        await this.storage.writeSession(record)
      } catch (error) {
        record.workerStartAttempted = false
        throw error
      }
      const initial = await prepared.client.start()
      record.pid = initial.pid
      record.containment = initial.containment
      record.termination = initial.termination
      this.transition(record, 'worker_ready')
      record.updatedAt = new Date().toISOString()
      this.nativeWorkers.set(id, prepared.client)
      await this.storage.writeSession(record)
      void this.monitorNative(record, prepared.client)
      return { id, status: record.status, mode: 'exec', pid: record.pid }
    } catch (error) {
      const cleanup =
        error instanceof WorkerStartError
          ? error.cleanup
          : prepared
            ? await prepared.client.rollback().catch((rollbackError) => ({
                requested: false,
                terminationConfirmed: false,
                method: 'none' as const,
                message: String(rollbackError),
              }))
            : { requested: false, terminationConfirmed: false, method: 'none' as const }
      if (!prepared && error instanceof WorkerStartError && error.prestartReference) {
        record.worker = error.prestartReference
        record.workerStartAttempted = false
      }
      this.transition(record, cleanup.terminationConfirmed ? 'spawn_failed' : 'unreachable')
      record.terminationRequested = cleanup.requested
      record.terminationConfirmed = cleanup.terminationConfirmed
      record.exitReason = { kind: 'spawn_error', message: String(error), cleanup }
      record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(record)
      this.registry.releaseIfSettled(record)
      if (error instanceof WorkerStartError && error.noWorkerSpawned)
        await this.deleteNativeSession(record).catch(() => false)
      throw new ProcessError(String(error), { cleanup })
    }
  }

  async nativeExecWait(id: string, timeoutSeconds: number): Promise<ExecResult> {
    if (
      !Number.isInteger(timeoutSeconds) ||
      timeoutSeconds <= 0 ||
      timeoutSeconds > MAX_EXEC_WAIT_SECONDS
    )
      throw new Error(
        `timeoutSeconds must be a positive integer up to ${MAX_EXEC_WAIT_SECONDS} for exec wait`
      )
    const record = this.recordFor(id)
    if (record.mode !== 'exec') throw new Error(`Session '${id}' is not an exec session.`)
    const waited = await this.wait(
      id,
      { kind: 'exit' },
      Math.min(timeoutSeconds, MAX_EXEC_RUNTIME_SECONDS)
    )
    if (waited.reason === 'deadline' && activeStatus(record)) {
      await this.stop(id)
      const stopped = await this.wait(id, { kind: 'exit' }, EXEC_TERMINAL_WAIT_SECONDS)
      if (stopped.reason === 'deadline')
        throw new ProcessError('Exec stop completed without terminal evidence.')
    }
    let current = this.recordFor(id)
    if (waited.reason === 'exit' || current.status === 'lost')
      await this.nativeFinalizations.get(id)
    current = this.recordFor(id)
    if (!this.isTerminal(current) || current.status === 'lost' || current.status === 'spawn_failed')
      throw new ProcessError('Exec wait completed without terminal evidence.')
    const output = current.execOutput
    return {
      session: { id: current.id, status: current.status, mode: 'exec', pid: current.pid },
      stdout: output?.stdout ?? '',
      stderr: output?.stderr ?? '',
      exitCode: current.exitCode,
      exitSignal: current.exitSignal,
      timedOut: current.timedOut,
      outputLimited: current.outputTruncated,
      terminationConfirmed: current.terminationConfirmed,
      containment: current.containment,
      termination: current.termination,
      startedAt: current.startedAt ?? current.createdAt,
      exitedAt: current.exitedAt ?? current.updatedAt,
    }
  }

  private async monitorNative(record: SessionRecord, worker: WorkerClient): Promise<void> {
    while (this.nativeWorkers.get(record.id) === worker) {
      try {
        let result = await worker.wait(1000)
        while (!this.nativeTerminal(result)) {
          await this.finishNative(record, result)
          result = await worker.wait(1000)
        }
        await this.finalizeNative(record, worker, result)
        return
      } catch {
        if (this.nativeWorkers.get(record.id) !== worker) return
        await this.rollbackNative(
          record,
          worker,
          new Error('Native worker RPC became unavailable.')
        )
        return
      }
    }
  }

  private nativeTerminal(result: WorkerSnapshot): boolean {
    if (result.status === 'lost') return true
    return this.nativeTerminalProof(result)
  }

  private nativeTerminalProof(result: WorkerSnapshot): boolean {
    return (
      result.terminationConfirmed &&
      result.status !== 'running' &&
      result.directChildExited &&
      (containmentDrained({
        containment: result.containment,
        terminationConfirmed: result.terminationConfirmed,
        directChildExited: result.directChildExited,
      }) ||
        process.platform === 'darwin')
    )
  }

  private async rollbackNative(
    record: SessionRecord,
    worker: WorkerClient,
    error: unknown
  ): Promise<void> {
    return this.enqueueMutation(record.id, () => this.rollbackNativeInLane(record, worker, error))
  }

  private async rollbackNativeInLane(
    record: SessionRecord,
    worker: WorkerClient,
    error: unknown
  ): Promise<void> {
    if (this.nativeWorkers.get(record.id) !== worker) return
    const version = this.bumpNativeVersion(record.id)
    const cleanup = await worker.rollback().catch((rollbackError) => ({
      requested: false,
      terminationConfirmed: false,
      method: 'none' as const,
      message: String(rollbackError),
    }))
    this.transition(record, 'unreachable')
    record.terminationRequested = cleanup.requested
    record.terminationConfirmed = cleanup.terminationConfirmed
    record.exitReason = {
      kind: 'unknown',
      message: `Native worker control failed: ${String(error)}; cleanup=${JSON.stringify(cleanup)}`,
    }
    record.updatedAt = new Date().toISOString()
    await this.enqueueNativePersist(record.id, async () => {
      if (this.records.get(record.id) !== record || version !== this.nativeVersion(record.id))
        return
      await this.storage.writeSession(record)
      this.bumpNativeVersion(record.id)
    })
    this.nativeWorkers.delete(record.id)
  }

  private async finalizeNative(
    record: SessionRecord,
    worker: WorkerClient,
    result: WorkerSnapshot
  ): Promise<ExecResult | PTYSessionInfo> {
    return this.enqueueMutation(record.id, () => this.finalizeNativeInLane(record, worker, result))
  }

  private async finalizeNativeInLane(
    record: SessionRecord,
    worker: WorkerClient,
    result: WorkerSnapshot
  ): Promise<ExecResult | PTYSessionInfo> {
    // A queued duplicate can run after the first finalizer removed this worker.
    if (this.nativeWorkers.get(record.id) !== worker) return this.toInfo(record)
    const existing = this.nativeFinalizations.get(record.id)
    if (existing) return existing
    const version = this.bumpNativeVersion(record.id)
    const finalization = this.finalizeNativeVersion(record, worker, result, version)
    this.nativeFinalizations.set(record.id, finalization)
    void finalization.then(
      () => {
        if (this.nativeFinalizations.get(record.id) === finalization)
          this.nativeFinalizations.delete(record.id)
      },
      () => undefined
    )
    return finalization
  }

  private async finalizeNativeVersion(
    record: SessionRecord,
    worker: WorkerClient,
    result: WorkerSnapshot,
    version: number
  ): Promise<ExecResult | PTYSessionInfo> {
    let final = result
    try {
      if (this.nativeTerminal(result)) final = await worker.finalSnapshot()
      return await this.finishNativeInLane(record, final, version, this.nativeTerminal(final))
    } catch (error) {
      await this.persistNativeFinalizationFailure(record, final, error)
      const failure = new Error(`Native finalization failed: ${String(error)}`)
      Object.assign(failure, { code: 'ESTORAGE' })
      throw failure
    } finally {
      if (this.nativeTerminal(final)) {
        try {
          const shutdown = await worker.shutdown().catch(() => undefined)
          if (shutdown && this.nativeTerminalProof(shutdown))
            this.confirmedWorkerShutdowns.add(record.id)
        } finally {
          this.nativeWorkers.delete(record.id)
        }
      }
    }
  }

  private async finishNative(
    record: SessionRecord,
    result: WorkerSnapshot,
    version = this.nativeVersion(record.id),
    terminal = false
  ): Promise<ExecResult | PTYSessionInfo> {
    return this.enqueueMutation(record.id, () =>
      this.finishNativeInLane(record, result, version, terminal)
    )
  }

  private async finishNativeInLane(
    record: SessionRecord,
    result: WorkerSnapshot,
    version = this.nativeVersion(record.id),
    terminal = false
  ): Promise<ExecResult | PTYSessionInfo> {
    return this.enqueueNativePersist(record.id, async () => {
      if (this.records.get(record.id) !== record || version !== this.nativeVersion(record.id))
        return this.toInfo(record)
      try {
        return await this.finishNativeVersion(record, result)
      } finally {
        // A terminal write invalidates snapshots that completed while it was in flight.
        if (terminal) this.bumpNativeVersion(record.id)
      }
    })
  }

  private async finishNativeVersion(
    record: SessionRecord,
    result: WorkerSnapshot
  ): Promise<ExecResult | PTYSessionInfo> {
    // A stale snapshot must not overwrite a newer stop or terminal observation just because its
    // status transition was rejected.
    if (!this.transition(record, this.workerEvent(result))) return this.toInfo(record)
    record.pid = result.pid
    record.nextSequence = result.nextSequence
    record.firstRetainedSequence = result.firstRetainedSequence
    record.outputBytes = result.stdoutBytes + result.stderrBytes
    record.outputTruncated = result.outputTruncated
    record.timedOut = result.timedOut
    if (record.mode === 'exec' && result.stdout !== undefined && result.stderr !== undefined)
      record.execOutput = {
        stdout: result.stdout,
        stderr: result.stderr,
        stdoutBytes: result.stdoutBytes,
        stderrBytes: result.stderrBytes,
        stdoutTruncated: result.stdoutTruncated,
        stderrTruncated: result.stderrTruncated,
        containment: result.containment,
        termination: result.termination,
      }
    record.exitCode = result.exitCode ?? undefined
    record.exitSignal = result.exitSignal ?? undefined
    record.terminationRequested = result.terminationRequested
    record.terminationConfirmed = result.terminationConfirmed
    record.directChildExited = result.directChildExited
    record.containment = result.containment
    record.termination = result.termination
    record.storageFailure = result.storageFailure ?? undefined
    record.diagnostics = result.diagnostics?.length ? result.diagnostics : undefined
    if (result.storageFailure || result.readerFailure || result.outputIncomplete)
      record.exitReason = {
        kind: 'unknown',
        message: result.storageFailure
          ? `Native worker storage failure: ${result.storageFailure}`
          : result.readerFailure
            ? `Native worker output incomplete: ${result.readerFailure}`
            : 'Native worker output incomplete: reader drain deadline elapsed.',
      }
    else if (result.exitReason === 'timeout') record.exitReason = { kind: 'timeout' }
    else if (result.exitReason === 'output_limit') record.exitReason = { kind: 'output_limit' }
    else if (result.exitReason === 'stopped') record.exitReason = { kind: 'stopped' }
    else if (result.exitReason?.startsWith('signal:'))
      record.exitReason = {
        kind: 'signal',
        signal: result.exitSignal ?? result.exitReason.slice(7),
      }
    else if (record.terminationConfirmed)
      record.exitReason = this.exitReason(result.exitCode ?? null, result.exitSignal ?? undefined)
    else record.exitReason = { kind: 'unknown' }
    record.exitedAt = result.exitedAt ?? undefined
    record.updatedAt = new Date().toISOString()
    record.outputBytes =
      record.mode === 'exec'
        ? result.stdoutBytes + result.stderrBytes
        : result.nextSequence - result.firstRetainedSequence
    record.lineCount = result.outputLineCount
    record.outputHasPartialLine = result.outputHasPartialLine
    try {
      await this.storage.writeSession(record)
    } catch (error) {
      await this.persistNativeFinalizationFailure(record, result, error)
      const failure = new Error(`Native finalization failed: ${String(error)}`)
      Object.assign(failure, { code: 'ESTORAGE' })
      throw failure
    }
    this.registry.releaseIfSettled(record)
    this.resolveOutputWaits(record)
    if (!activeStatus(record)) this.resolveExitWaits(record)
    if (
      result.storageFailure ||
      ((result.readerFailure || result.outputIncomplete) && result.terminationConfirmed)
    ) {
      const error = new Error(
        result.storageFailure
          ? `Native worker output storage failed: ${result.storageFailure}`
          : `Native worker output incomplete${result.readerFailure ? `: ${result.readerFailure}` : '.'}`
      )
      Object.assign(error, { code: 'ESTORAGE' })
      throw error
    }
    if (record.mode === 'pty') return this.toInfo(record)
    return {
      session: { id: record.id, status: record.status, mode: 'exec', pid: record.pid },
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      exitCode: record.exitCode,
      exitSignal: record.exitSignal,
      timedOut: record.timedOut,
      outputLimited: record.outputTruncated,
      terminationConfirmed: record.terminationConfirmed,
      containment: record.containment,
      termination: record.termination,
      startedAt: record.startedAt ?? record.createdAt,
      exitedAt: record.exitedAt ?? record.updatedAt,
    }
  }

  private async persistNativeFinalizationFailure(
    record: SessionRecord,
    result: WorkerSnapshot,
    error: unknown,
    previous?: SessionRecord
  ): Promise<void> {
    if (previous) Object.assign(record, previous)
    this.transition(record, 'unreachable')
    record.exitCode =
      result.exitCode !== null &&
      result.exitCode !== undefined &&
      Number.isSafeInteger(result.exitCode) &&
      result.exitCode >= 0
        ? result.exitCode
        : undefined
    record.storageFailure = `Native finalization failed: ${String(error)}`
    record.exitReason = { kind: 'unknown', message: record.storageFailure }
    record.updatedAt = new Date().toISOString()
    await this.storage.writeSession(record)
    this.resolveOutputWaits(record)
    this.resolveExitWaits(record)
  }

  async read(id: string, offset = 0, limit?: number, sequence?: number): Promise<ReadResult> {
    return this.journal.read(this.recordFor(id), offset, limit, sequence)
  }

  async search(
    id: string,
    pattern: string,
    ignoreCase = false,
    offset = 0,
    limit?: number,
    sequence?: number
  ): Promise<SearchResult> {
    return this.journal.search(this.recordFor(id), pattern, ignoreCase, offset, limit, sequence)
  }

  async get(id: string): Promise<PTYSessionInfo | null> {
    await this.flush()
    const record = this.records.get(id)
    const native = this.nativeWorkers.get(id)
    if (record?.worker && native) {
      await this.syncNative(record, native)
    }
    return record ? this.toInfo(record) : null
  }

  async list(): Promise<PTYSessionInfo[]> {
    await this.flush()
    return [...this.records.values()].map((record) => this.toInfo(record))
  }

  owns(
    id: string,
    parentSessionId: string,
    projectDirectory: string,
    capabilityHash: string
  ): boolean {
    return this.router.owns(id, parentSessionId, projectDirectory, capabilityHash)
  }

  async rawOutput(id: string): Promise<{
    raw: string
    byteLength: number
    containment?: SessionRecord['containment']
    termination?: SessionRecord['termination']
  } | null> {
    await this.flush()
    const record = this.records.get(id)
    if (!record) return null
    return this.journal.raw(record)
  }

  async execOutput(id: string): Promise<import('./types.ts').ExecOutput | null> {
    await this.flush()
    const record = this.records.get(id)
    const native = this.nativeWorkers.get(id)
    if (record?.worker && native) {
      await this.syncNative(record, native)
    }
    return record?.execOutput
      ? { ...record.execOutput, containment: record.containment, termination: record.termination }
      : null
  }

  async stop(id: string): Promise<StopResult> {
    await this.flush()
    return this.enqueueMutation(id, async () => {
      const native = this.nativeWorkers.get(id)
      if (native) {
        const record = this.recordFor(id)
        record.terminationRequested = true
        this.transition(record, 'stop_requested')
        await this.storage.writeSession(record)
        await this.finalizeNativeInLane(record, native, await native.stop())
        return {
          requested: true,
          terminationConfirmed: record.terminationConfirmed,
          directChildExited: record.directChildExited,
          containment: record.containment,
          termination: record.termination,
        }
      }
      const record = this.records.get(id)
      if (!record) throw new DaemonError(`PTY session '${id}' not found.`, 'not_found')
      return {
        requested: false,
        terminationConfirmed: record.terminationConfirmed,
        directChildExited: record.directChildExited,
        containment: record.containment,
        termination: record.termination,
      }
    })
  }

  async cleanup(id: string): Promise<boolean> {
    await this.flush()
    const record = this.records.get(id)
    if (!record) return false
    await this.nativeFinalizations.get(id)
    const prestartAuthority = this.prestartReceiptAuthority(record)
    if (
      prestartAuthority &&
      (await NativeWorkerClient.hasVerifiedPrestartNoChildReceipt(
        join(this.storage.rootDirectory, 'sessions', record.id),
        prestartAuthority
      ))
    ) {
      return this.deleteNativeSession(record)
    }
    if (await this.hasVerifiedNoChildSpawnFailure(record)) return this.deleteNativeSession(record)
    if (record.status === 'lost') {
      if (terminalDirectChild(record)) return this.deleteNativeSession(record)
      if (this.incompatibleWorker(record)) return false
      const worker =
        this.nativeWorkers.get(id) ??
        (record.worker
          ? await NativeWorkerClient.reconnect(
              join(this.storage.rootDirectory, 'sessions', record.id),
              record.worker
            )
          : undefined)
      if (!worker) {
        if (record.worker) await this.terminateOrphanWorker(record)
        return false
      }
      try {
        if (!this.nativeTerminalProof(await worker.shutdown())) return false
      } catch {
        await this.terminateOrphanWorker(record)
        return false
      }
      return this.deleteNativeSession(record)
    }
    if (!this.isTerminal(record)) return false
    const existingWorker = this.nativeWorkers.get(id)
    const requiresFreshConversationProof =
      record.lifecycle === 'conversation' &&
      record.worker !== undefined &&
      !existingWorker &&
      !this.confirmedWorkerShutdowns.has(id)
    const worker =
      existingWorker ??
      (requiresFreshConversationProof && !this.incompatibleWorker(record)
        ? await NativeWorkerClient.reconnect(
            join(this.storage.rootDirectory, 'sessions', record.id),
            record.worker!
          )
        : undefined)
    if (requiresFreshConversationProof && !worker) return false
    if (worker) {
      try {
        const shutdown = await worker.shutdown()
        if (!this.nativeTerminalProof(shutdown)) return false
        this.confirmedWorkerShutdowns.add(id)
      } catch {
        // A completed worker may have already removed its listener; its persisted terminal record is authoritative.
        if (requiresFreshConversationProof) return false
        if (!terminalDirectChild(record)) return false
      }
    }
    return this.deleteNativeSession(record)
  }

  async cleanupByParentSession(
    parentSessionId: string,
    projectDirectory: string,
    capabilityHash: string
  ): Promise<void> {
    await Promise.all(
      [...this.records.values()]
        .filter(
          (record) =>
            record.parentSessionId === parentSessionId &&
            record.ownerProjectDirectory === projectDirectory &&
            record.ownerCapabilityHash === capabilityHash &&
            record.lifecycle === 'conversation'
        )
        .map((record) => this.cleanupConversation(record))
    )
  }

  private cleanupConversation(record: SessionRecord): Promise<void> {
    const existing = this.pendingConversationCleanup.get(record.id)
    if (existing) return existing
    const cleanup = (async () => {
      const active = await this.enqueueMutation(record.id, async () => {
        record.pendingCleanup = true
        await this.storage.writeSession(record)
        return activeStatus(record)
      })
      if (record.status === 'lost' || !active) {
        await this.cleanup(record.id)
        return
      }
      if (!this.nativeWorkers.has(record.id)) return
      await this.stop(record.id)
      await this.cleanup(record.id)
    })().finally(() => this.pendingConversationCleanup.delete(record.id))
    this.pendingConversationCleanup.set(record.id, cleanup)
    return cleanup
  }

  async flush(): Promise<void> {
    await this.persistQueue
  }

  async shutdown(): Promise<void> {
    // Workers deliberately survive a daemon stop; they are reconciled on the next daemon start.
  }

  // Best-effort termination of a worker this daemon can no longer reconnect or control. Failures
  // are recorded but never block reconciliation or cleanup.
  private async terminateOrphanWorker(record: SessionRecord): Promise<void> {
    if (!record.worker || this.incompatibleWorker(record)) return
    try {
      const result = await NativeWorkerClient.terminateOrphan(
        join(this.storage.rootDirectory, 'sessions', record.id)
      )
      if (result.detail)
        console.warn(
          `Orphaned PTY worker termination for ${JSON.stringify(record.id)} (${result.outcome}): ${result.detail}.`
        )
    } catch (error) {
      console.warn(
        `Orphaned PTY worker termination for ${JSON.stringify(record.id)} failed: ${String(error)}.`
      )
    }
  }

  private enqueuePersist(task: () => Promise<void>): void {
    this.persistQueue = this.persistQueue.then(task, task)
  }

  private incompatibleWorker(record: SessionRecord): boolean {
    return (
      record.worker !== undefined &&
      record.worker.protocolVersion !== NATIVE_WORKER_PROTOCOL_VERSION
    )
  }

  private prestartReceiptAuthority(
    record: SessionRecord
  ): WorkerReference | WorkerPrestartAuthority | undefined {
    if (
      record.workerStartAttempted === false &&
      (record.status === 'starting' || record.status === 'lost' || record.status === 'spawn_failed')
    )
      return record.worker ?? record.workerPrestart
    return undefined
  }

  private postStartNoChildFailureEligible(record: SessionRecord): boolean {
    return (
      record.worker !== undefined &&
      record.workerStartAttempted === true &&
      (record.status === 'spawn_failed' || record.status === 'lost')
    )
  }

  private async hasVerifiedNoChildSpawnFailure(record: SessionRecord): Promise<boolean> {
    return Boolean(
      !this.incompatibleWorker(record) &&
        this.postStartNoChildFailureEligible(record) &&
        record.worker &&
        (await NativeWorkerClient.hasVerifiedNoChildSpawnFailureReceipt(
          join(this.storage.rootDirectory, 'sessions', record.id),
          record.worker
        ))
    )
  }

  private nativeVersion(id: string): number {
    return this.router.version(id)
  }

  private bumpNativeVersion(id: string): number {
    return this.router.bumpVersion(id)
  }

  private async syncNative(record: SessionRecord, worker: WorkerClient): Promise<void> {
    const version = this.nativeVersion(record.id)
    const result = await worker.snapshot()
    if (this.nativeWorkers.get(record.id) !== worker) {
      await this.nativeFinalizations.get(record.id)?.catch(() => undefined)
      return
    }
    if (this.nativeTerminal(result)) {
      await this.finalizeNative(record, worker, result)
      return
    }
    await this.finishNative(record, result, version)
    if (version !== this.nativeVersion(record.id))
      await this.nativeFinalizations.get(record.id)?.catch(() => undefined)
  }

  private enqueueNativePersist<T>(id: string, task: () => Promise<T>): Promise<T> {
    return this.router.persist(id, task)
  }

  private enqueueMutation<T>(id: string, task: () => Promise<T>): Promise<T> {
    return this.router.mutate(id, task)
  }

  private deleteNativeSession(record: SessionRecord): Promise<boolean> {
    return this.enqueueMutation(record.id, () =>
      this.enqueueNativePersist(record.id, async () => {
        if (this.records.get(record.id) !== record) return false
        this.bumpNativeVersion(record.id)
        this.nativeWorkers.delete(record.id)
        await this.storage.deleteSession(record.id)
        this.confirmedWorkerShutdowns.delete(record.id)
        this.registry.release(record.id)
        this.records.delete(record.id)
        return true
      })
    )
  }

  private idempotentSession(options: SpawnOptions, args: string[]): SessionRecord | undefined {
    if (!options.idempotencyKey) return undefined
    const existing = [...this.records.values()].find(
      (record) =>
        activeStatus(record) &&
        !record.pendingCleanup &&
        !record.legacyTombstone &&
        record.mode === 'pty' &&
        record.parentSessionId === options.parentSessionId &&
        record.ownerProjectDirectory ===
          canonicalWorkdir(options.ownerProjectDirectory ?? options.workdir) &&
        record.ownerCapabilityHash === (options.ownerCapabilityHash ?? '') &&
        record.workdir === canonicalWorkdir(options.workdir, options.ownerProjectDirectory) &&
        record.idempotencyKey === options.idempotencyKey
    )
    if (!existing) return undefined
    const environment = environmentProfile(
      runtimeEnvironment(options.env, options.inheritEnv === true),
      options.inheritEnv === true
    )
    if (
      existing.command !== options.command ||
      JSON.stringify(existing.args) !== JSON.stringify(args) ||
      existing.environment.kind !== environment.kind ||
      existing.environment.fingerprint !== environment.fingerprint ||
      existing.name !== options.name ||
      existing.timeoutSeconds !== options.timeoutSeconds
    ) {
      throw new Error(
        'Idempotency key matches an active PTY with a different command or specification.'
      )
    }
    return existing
  }

  private validateWait(condition: WaitCondition, timeoutSeconds: number): void {
    if (
      !Number.isInteger(timeoutSeconds) ||
      timeoutSeconds <= 0 ||
      timeoutSeconds > MAX_EXEC_RUNTIME_SECONDS
    ) {
      throw new Error(
        `wait timeoutSeconds must be a positive integer up to ${MAX_EXEC_RUNTIME_SECONDS}.`
      )
    }
    if (condition.kind !== 'output') return
    if (Boolean(condition.literal) === Boolean(condition.regex)) {
      throw new Error('Output wait requires exactly one of literal or regex.')
    }
    if (condition.literal && Buffer.byteLength(condition.literal) > 4096) {
      throw new DaemonError('Output wait literal exceeds the size limit.', 'limit')
    }
    if (condition.regex) safeRegex(condition.regex)
  }

  private async waitMatch(
    record: SessionRecord,
    condition: WaitCondition
  ): Promise<WaitResult | undefined> {
    if (condition.kind === 'exit') return activeStatus(record) ? undefined : this.exitWait(record)
    const output = await this.journal.output(record.id)
    const after = condition.afterSequence ?? record.firstRetainedSequence
    const scoped =
      after <= record.firstRetainedSequence
        ? output
        : Buffer.from(output)
            .subarray(after - record.firstRetainedSequence)
            .toString('utf8')
    const matched = condition.literal
      ? scoped.includes(condition.literal)
        ? condition.literal
        : undefined
      : safeRegex(condition.regex ?? '').exec(scoped)?.[0]
    return matched === undefined
      ? undefined
      : {
          satisfied: true,
          reason: 'output',
          observedAt: new Date().toISOString(),
          matched,
          outputTruncated: record.outputTruncated,
        }
  }

  private exitWait(record: SessionRecord): WaitResult {
    return {
      satisfied: true,
      reason: 'exit',
      observedAt: record.exitedAt ?? record.updatedAt,
      exitCode: record.exitCode,
      exitSignal: record.exitSignal,
      outputTruncated: record.outputTruncated,
      containment: record.containment,
      termination: record.termination,
    }
  }

  private waitEnded(record: SessionRecord, condition: WaitCondition): WaitResult {
    const exit = this.exitWait(record)
    return condition.kind === 'exit' ? exit : { ...exit, satisfied: false }
  }

  private async finishWait(record: SessionRecord, result: WaitResult): Promise<WaitResult> {
    const complete = {
      ...result,
      containment: record.containment,
      termination: record.termination,
    }
    record.lastWaitResult = complete
    record.updatedAt = new Date().toISOString()
    this.enqueuePersist(() => this.storage.writeSession(record))
    await this.persistQueue
    return complete
  }

  private resolveOutputWaits(record: SessionRecord): void {
    const pending = this.waits.get(record.id)
    if (!pending) return
    void Promise.all(
      pending
        .filter((wait) => wait.condition.kind === 'output')
        .map(async (wait) => {
          const result = await this.waitMatch(record, wait.condition)
          if (!result) return
          wait.settle(result)
        })
    )
  }

  private resolveExitWaits(record: SessionRecord): void {
    const pending = this.waits.get(record.id)
    if (!pending) return
    void this.persistQueue.then(async () => {
      for (const wait of [...(this.waits.get(record.id) ?? [])]) {
        const matched = await this.waitMatch(record, wait.condition)
        wait.settle(matched ?? this.waitEnded(record, wait.condition))
      }
    })
  }

  private removeWait(id: string, wait: PendingWait): void {
    clearTimeout(wait.timer)
    const pending = this.waits.get(id)
    if (!pending) return
    const remaining = pending.filter((candidate) => candidate !== wait)
    if (remaining.length) this.waits.set(id, remaining)
    else this.waits.delete(id)
  }

  private exitReason(exitCode: number | null, signal?: number | string): ExitReason {
    if (exitCode !== null) return { kind: 'code', code: exitCode }
    if (signal) return { kind: 'signal', signal: String(signal) }
    return { kind: 'unknown' }
  }

  private transition(record: SessionRecord, event: LifecycleEvent): boolean {
    const reduction = reduceDaemonStatus(record.status, event)
    if (!reduction.ok) return false
    record.status = reduction.status
    return true
  }

  private workerEvent(result: WorkerSnapshot): LifecycleEvent {
    if (result.status === 'lost') return 'unreachable'
    if (result.status === 'running') return 'worker_ready'
    if (result.exitReason === 'output_limit') return 'output_limited'
    if (result.timedOut) return 'timed_out'
    return 'child_exited'
  }

  private redactionSecrets(environment: Record<string, string>): string[] {
    return Object.entries(environment)
      .filter(([key, value]) => SENSITIVE_ENVIRONMENT_KEY.test(key) && value.length >= 4)
      .map(([, value]) => value)
  }

  private recordFor(id: string): SessionRecord {
    const record = this.records.get(id)
    if (!record) throw new DaemonError(`PTY session '${id}' not found.`, 'not_found')
    return record
  }

  private isTerminal(record: SessionRecord): boolean {
    return !activeStatus(record) && terminalDirectChild(record)
  }

  private toInfo(record: SessionRecord): PTYSessionInfo {
    return {
      id: record.id,
      title: record.title,
      description: record.description,
      command: record.command,
      args: record.args,
      mode: record.mode,
      lifecycle: record.lifecycle,
      name: record.name,
      idempotencyKey: record.idempotencyKey,
      workdir: record.workdir,
      status: record.status,
      timeoutSeconds: record.timeoutSeconds,
      timedOut: record.timedOut,
      terminationRequested: record.terminationRequested,
      terminationConfirmed: record.terminationConfirmed,
      directChildExited: record.directChildExited,
      containment: record.containment,
      termination: record.termination,
      exitCode: record.exitCode,
      exitSignal: record.exitSignal,
      exitReason: record.exitReason,
      pid: record.pid,
      createdAt: record.createdAt,
      startedAt: record.startedAt,
      exitedAt: record.exitedAt,
      lineCount: record.lineCount,
      outputSequence: record.nextSequence,
      firstRetainedSequence: record.firstRetainedSequence,
      outputTruncated: record.outputTruncated,
      diagnostics: record.diagnostics,
      lastWaitResult: record.lastWaitResult,
      execOutput: record.execOutput,
      environment: record.environment,
    }
  }
}
