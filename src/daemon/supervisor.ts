import { realpathSync } from 'node:fs'
import { join, resolve } from 'node:path'
import type { PTYSessionInfo, ReadResult, SearchResult, SpawnOptions } from '../plugin/pty/types.ts'
import type { DaemonStorage } from './storage.ts'
import type { SpawnFailure } from './types.ts'
import {
  type EnvironmentProfile,
  type ExecResult,
  type ExitReason,
  MAX_EXEC_RUNTIME_SECONDS,
  OUTPUT_JOURNAL_VERSION,
  type SessionRecord,
  type StopResult,
  type WaitCondition,
  type WaitResult,
  type WriteResult,
} from './types.ts'
import type { WorkerClient, WorkerSnapshot } from './worker-client.ts'
import { WorkerClient as NativeWorkerClient, WorkerStartError } from './worker-client.ts'

const DEFAULT_MAX_OUTPUT_BYTES = 1000000
const MAX_OUTPUT_BYTES = 64 * 1024 * 64
const MAX_REDACTION_SECRET_BYTES = 4096
const TERMINATION_GRACE_MS = 250
const TERMINATION_HARD_KILL_MS = 1000
const RECOVERY_CONCURRENCY = 4
const EXEC_TERMINAL_WAIT_SECONDS = 5
const SAFE_ENVIRONMENT_KEYS = new Set([
  'PATH',
  'HOME',
  'USERPROFILE',
  'SYSTEMROOT',
  'SYSTEMDRIVE',
  'WINDIR',
  'TEMP',
  'TMP',
  'TERM',
  'LANG',
  'ComSpec',
])
const SENSITIVE_ENVIRONMENT_KEY =
  /(token|secret|password|credential|api[_-]?key|auth|cookie|(?:^|[_-])(?:ssh|tls)?[_-]?private[_-]?key(?:$|[_-])|(?:^|[_-])signing[_-]?key(?:$|[_-]))/i

interface ExecOptions extends SpawnOptions {
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

function lineCount(output: string): number {
  if (!output) return 0
  const lines = output.split('\n')
  return lines.at(-1) === '' ? lines.length - 1 : lines.length
}

function outputLines(
  output: string,
  firstSequence: number
): Array<{ lineNumber: number; sequence: number; text: string }> {
  if (!output) return []
  const parts = output.split('\n')
  const count = output.endsWith('\n') ? parts.length - 1 : parts.length
  let sequence = firstSequence
  return parts.slice(0, count).map((text, index) => {
    const line = { lineNumber: index + 1, sequence, text }
    sequence += Buffer.byteLength(text) + (index < parts.length - 1 ? 1 : 0)
    return line
  })
}

function searchLines(
  output: string,
  pattern: string,
  ignoreCase: boolean,
  firstSequence: number
): Array<{ lineNumber: number; sequence: number; text: string }> {
  const needle = ignoreCase ? pattern.toLowerCase() : pattern
  return outputLines(output, firstSequence).filter(({ text }) => {
    const haystack = ignoreCase ? text.toLowerCase() : text
    return Boolean(text) && haystack.includes(needle)
  })
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
  return record.status === 'starting' || record.status === 'running' || record.status === 'stopping'
}

function containmentDrained(
  record: Pick<SessionRecord, 'containment' | 'terminationConfirmed' | 'directChildExited'>
): boolean {
  return (
    !record.containment ||
    record.containment.status === 'posix_best_effort_empty' ||
    record.containment.status === 'windows_job_empty' ||
    record.containment.status === 'not_applicable'
  )
}

function terminalDirectChild(
  record: Pick<SessionRecord, 'containment' | 'terminationConfirmed' | 'directChildExited'>
): boolean {
  return (
    record.terminationConfirmed &&
    (containmentDrained(record) ||
      (process.platform === 'darwin' && record.directChildExited === true))
  )
}

function canonicalWorkdir(workdir: string | undefined): string {
  return realpathSync(resolve(workdir ?? process.cwd()))
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
  const environment = Object.fromEntries(
    [...Object.entries(base), ...Object.entries(requested ?? {})].filter(([key]) => !isPath(key))
  ) as Record<string, string>
  // ponytail: command lookup gets only the daemon's PATH; callers cannot redirect an allowed bare command.
  if (trustedPath !== undefined) environment.PATH = trustedPath
  return environment
}

export class OutputRedactor {
  private readonly secrets: string[]
  private readonly tailLength: number
  private tail = ''

  constructor(environment: Record<string, string>) {
    this.secrets = Object.entries(environment)
      .filter(([key, value]) => SENSITIVE_ENVIRONMENT_KEY.test(key) && value.length >= 4)
      .map(([, value]) => value)
      .sort((left, right) => right.length - left.length)
    if (this.secrets.some((value) => Buffer.byteLength(value) > MAX_REDACTION_SECRET_BYTES)) {
      throw new Error(
        `Sensitive environment values must not exceed ${MAX_REDACTION_SECRET_BYTES} bytes.`
      )
    }
    this.tailLength = Math.max(0, ...this.secrets.map((value) => [...value].length - 1))
  }

  write(data: string): string {
    const characters = [...(this.tail + data)]
    const end = Math.max(0, characters.length - this.tailLength)
    let index = 0
    let output = ''
    while (index < end) {
      const secret = this.secrets.find((value) => startsWith(characters, index, [...value]))
      if (secret) {
        output += '[REDACTED]'
        index += [...secret].length
      } else {
        output += characters[index]
        index += 1
      }
    }
    this.tail = characters.slice(index).join('')
    return output
  }

  finish(): string {
    let output = this.tail
    for (const secret of this.secrets) output = output.replaceAll(secret, '[REDACTED]')
    this.tail = ''
    return output
  }
}

function startsWith(characters: string[], index: number, prefix: string[]): boolean {
  return prefix.every((character, offset) => characters[index + offset] === character)
}

export class SessionSupervisor {
  private readonly records = new Map<string, SessionRecord>()
  private readonly waits = new Map<string, PendingWait[]>()
  private readonly nativeWorkers = new Map<string, WorkerClient>()
  private readonly nativeVersions = new Map<string, number>()
  private readonly nativePersists = new Map<string, Promise<void>>()
  private readonly nativeFinalizations = new Map<string, Promise<ExecResult | PTYSessionInfo>>()
  private readonly pendingConversationCleanup = new Map<string, Promise<void>>()
  private persistQueue = Promise.resolve()

  constructor(
    private readonly storage: DaemonStorage,
    private readonly maxOutputBytes: number = effectiveMaxOutputBytes(),
    private readonly recoveryAttempts = 30,
    private readonly recoveryRetryMs = 100
  ) {}

  async initialize(reconnect = true): Promise<void> {
    await this.storage.initialize()
    for (const record of await this.storage.loadSessions()) {
      if (record.containment) {
        record.containment.rootIdentityVerified ??= false
        record.containment.observedEscapedDescendants ??= []
      }
      if (record.termination) record.termination.directChildExited ??= record.termination.rootExited
      record.mode ??= 'pty'
      record.ownerProjectDirectory ??= record.workdir
      record.ownerCapabilityHash ??= ''
      record.lifecycle ??= 'conversation'
      record.environment ??= { kind: 'safe', keys: [], fingerprint: '', sensitive: false }
      record.terminationRequested ??= record.status === 'stopping'
      record.terminationConfirmed ??=
        record.status === 'exited' ||
        record.status === 'timed_out' ||
        record.status === 'spawn_failed' ||
        record.status === 'output_limited'
      record.directChildExited ??= record.terminationConfirmed
      record.pendingCleanup ??= false
      this.records.set(record.id, record)
      if (record.worker && record.worker.protocolVersion !== 5) {
        record.status = 'lost'
        record.terminationConfirmed = false
        record.exitReason = {
          kind: 'unknown',
          message: `Native worker protocol v${record.worker.protocolVersion} is incompatible with this daemon; output remains readable but the worker cannot be reconnected or controlled.`,
        }
        record.updatedAt = new Date().toISOString()
        await this.storage.writeSession(record)
      }
    }
    if (reconnect) await this.reconcileWorkers()
  }

  async reconcileWorkers(): Promise<void> {
    const pending = [...this.records.values()].filter(activeStatus)
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
      this.nativeWorkers.set(record.id, worker)
      if (record.pendingCleanup) {
        await this.cleanupConversation(record)
        return
      }
      void this.monitorNative(record, worker)
      return
    }
    const output = await this.storage.readOutput(record.id)
    record.status = 'lost'
    record.exitReason = { kind: 'unknown' }
    record.outputBytes = Buffer.byteLength(output)
    record.lineCount = lineCount(output)
    record.outputHasPartialLine = Boolean(output) && !output.endsWith('\n')
    record.updatedAt = new Date().toISOString()
    await this.storage.writeSession(record)
  }

  async spawn(options: SpawnOptions): Promise<PTYSessionInfo> {
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
      workdir: canonicalWorkdir(options.workdir),
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
    this.records.set(id, record)
    await this.storage.writeSession(record)
    let started: Awaited<ReturnType<typeof NativeWorkerClient.start>>
    try {
      started = await NativeWorkerClient.start({
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
      })
    } catch (error) {
      const cleanup =
        error instanceof WorkerStartError
          ? error.cleanup
          : { requested: false, terminationConfirmed: false, method: 'none' as const }
      record.status = cleanup.terminationConfirmed ? 'spawn_failed' : 'lost'
      record.terminationRequested = cleanup.requested
      record.terminationConfirmed = cleanup.terminationConfirmed
      record.exitReason = {
        kind: 'spawn_error',
        message: error instanceof Error ? error.message : String(error),
        cleanup,
      }
      record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(record)
      throw new ProcessError(
        `Failed to spawn PTY '${id}': ${error instanceof Error ? error.message : String(error)}`,
        { cleanup }
      )
    }
    const initial = await started.client.snapshot()
    record.pid = initial.pid
    record.worker = started.reference
    record.containment = initial.containment
    record.termination = initial.termination
    record.status = 'running'
    record.updatedAt = new Date().toISOString()
    this.nativeWorkers.set(id, started.client)
    await this.storage.writeSession(record)
    void this.monitorNative(record, started.client)
    return this.toInfo(record)
  }

  async write(id: string, data: string): Promise<WriteResult> {
    await this.flush()
    const worker = this.nativeWorkers.get(id)
    const record = this.recordFor(id)
    if (!worker || record.status !== 'running') throw new Error(`PTY session '${id}' is closed.`)
    try {
      await worker.write(data)
      return { acceptedBytes: Buffer.byteLength(data), acceptedCharacters: [...data].length }
    } catch (error) {
      throw new ProcessError(
        `Failed to write to PTY '${id}': ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  async sendWait(
    id: string,
    data: string,
    condition: WaitCondition,
    timeoutSeconds: number
  ): Promise<WaitResult> {
    await this.flush()
    this.validateWait(condition, timeoutSeconds)
    const worker = this.nativeWorkers.get(id)
    const record = this.recordFor(id)
    if (!worker || record.status !== 'running') throw new Error(`PTY session '${id}' is closed.`)
    let afterSequence: number
    try {
      // The worker returns the cursor at the input acceptance boundary. On Windows this is before
      // WriteFile because ConPTY reads block and an immediate echo may be published concurrently.
      afterSequence = (await worker.write(data)).arrivalSequence
    } catch (error) {
      throw new ProcessError(
        `Failed to write to PTY '${id}': ${error instanceof Error ? error.message : String(error)}`
      )
    }
    return this.wait(
      id,
      { ...condition, ...(condition.kind === 'output' ? { afterSequence } : {}) },
      timeoutSeconds
    )
  }

  async resize(id: string, cols: number, rows: number): Promise<{ cols: number; rows: number }> {
    await this.flush()
    const record = this.recordFor(id)
    if (record.mode !== 'pty') throw new Error(`Session '${id}' is not a PTY.`)
    if (record.status !== 'running') throw new Error(`PTY session '${id}' is closed.`)
    const worker = this.nativeWorkers.get(id)
    if (!worker) throw new Error(`PTY session '${id}' is closed.`)
    return worker.resize(cols, rows)
  }

  async wait(id: string, condition: WaitCondition, timeoutSeconds: number): Promise<WaitResult> {
    await this.flush()
    this.validateWait(condition, timeoutSeconds)
    const record = this.recordFor(id)
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

  async exec(options: ExecOptions): Promise<ExecResult> {
    await this.flush()
    if (!options.command) throw new Error('command is required')
    if (
      !options.timeoutSeconds ||
      !Number.isInteger(options.timeoutSeconds) ||
      options.timeoutSeconds <= 0
    ) {
      throw new Error('timeoutSeconds must be a positive integer in seconds for exec')
    }
    const args = options.args ?? []
    const now = new Date().toISOString()
    const id = `exec_${crypto.randomUUID()}`
    const environment = runtimeEnvironment(options.env, options.inheritEnv === true)
    const stdoutRedactor = new OutputRedactor(environment)
    const stderrRedactor = new OutputRedactor(environment)
    const record: SessionRecord = {
      id,
      title: options.title ?? `${options.command} ${args.join(' ')}`.trim(),
      description: options.description,
      command: options.command,
      args,
      mode: 'exec',
      workdir: canonicalWorkdir(options.workdir),
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
    this.records.set(id, record)
    await this.storage.writeSession(record)
    let child: ReturnType<typeof Bun.spawn>
    try {
      child = Bun.spawn({
        cmd: [record.command, ...record.args],
        cwd: record.workdir,
        env: environment,
        stdout: 'pipe',
        stderr: 'pipe',
      })
    } catch (error) {
      record.status = 'spawn_failed'
      record.terminationConfirmed = true
      record.exitReason = { kind: 'spawn_error', message: String(error) }
      record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(record)
      throw new ProcessError(`Failed to spawn exec '${id}': ${String(error)}`)
    }
    record.pid = child.pid
    record.status = 'running'
    record.updatedAt = new Date().toISOString()
    await this.storage.writeSession(record)
    const limit = Math.min(options.maxOutputBytes ?? this.maxOutputBytes, this.maxOutputBytes)
    let termination: Promise<void> | undefined
    const stopReading: Array<() => void> = []
    const terminate = (reason: 'timeout' | 'output_limit') => {
      if (termination) return termination
      record.timedOut ||= reason === 'timeout'
      record.status = reason === 'timeout' ? 'timed_out' : 'output_limited'
      record.exitReason = reason === 'timeout' ? { kind: 'timeout' } : { kind: 'output_limit' }
      record.terminationRequested = true
      record.updatedAt = new Date().toISOString()
      termination = (async () => {
        await this.storage.writeSession(record)
        try {
          child.kill()
        } catch {
          record.exitReason =
            reason === 'timeout'
              ? { kind: 'timeout', message: 'Failed to terminate exec.' }
              : { kind: 'output_limit', message: 'Failed to terminate exec.' }
          await this.storage.writeSession(record)
          return
        }
        await Promise.race([child.exited.then(() => undefined), Bun.sleep(TERMINATION_GRACE_MS)])
        if (child.exitCode === null) {
          try {
            child.kill('SIGKILL')
          } catch {}
          await Promise.race([
            child.exited.then(() => undefined),
            Bun.sleep(TERMINATION_HARD_KILL_MS),
          ])
        }
      })()
      return termination
    }
    const stdout = this.collectExecOutput(
      typeof child.stdout === 'object' ? child.stdout : null,
      limit,
      () => terminate('output_limit'),
      (stop) => {
        stopReading.push(stop)
      },
      stdoutRedactor
    )
    const stderr = this.collectExecOutput(
      typeof child.stderr === 'object' ? child.stderr : null,
      limit,
      () => terminate('output_limit'),
      (stop) => {
        stopReading.push(stop)
      },
      stderrRedactor
    )
    const deadline = setTimeout(() => {
      if (child.exitCode === null) {
        void terminate('timeout')
      }
    }, options.timeoutSeconds * 1000)
    await Promise.race([
      child.exited,
      new Promise<void>((resolve) =>
        setTimeout(
          resolve,
          (options.timeoutSeconds ?? 0) * 1000 + TERMINATION_GRACE_MS + TERMINATION_HARD_KILL_MS
        )
      ),
    ])
    clearTimeout(deadline)
    if (child.exitCode === null)
      stopReading.forEach((stop) => {
        stop()
      })
    const [capturedOut, capturedErr] = await Promise.all([stdout, stderr])
    const out = capturedOut
    const err = capturedErr
    const exitedAt = new Date().toISOString()
    record.exitCode = child.exitCode ?? undefined
    record.exitSignal = child.signalCode ?? undefined
    const stillRunning = child.exitCode === null
    record.status = record.timedOut
      ? 'timed_out'
      : out.limited || err.limited
        ? 'output_limited'
        : 'exited'
    record.exitReason = stillRunning
      ? { kind: 'unknown' }
      : record.timedOut
        ? { kind: 'timeout' }
        : out.limited || err.limited
          ? { kind: 'output_limit' }
          : this.exitReason(child.exitCode, child.signalCode ?? undefined)
    record.outputBytes = out.bytes + err.bytes
    record.outputTruncated = out.limited || err.limited
    record.execOutput = {
      stdout: out.data,
      stderr: err.data,
      stdoutBytes: out.bytes,
      stderrBytes: err.bytes,
      stdoutTruncated: out.limited,
      stderrTruncated: err.limited,
      containment: record.containment,
      termination: record.termination,
    }
    record.terminationConfirmed = !stillRunning
    record.exitedAt = exitedAt
    record.updatedAt = exitedAt
    await this.storage.writeSession(record)
    return {
      session: { id, status: record.status, mode: 'exec', pid: record.pid },
      stdout: out.data,
      stderr: err.data,
      exitCode: record.exitCode,
      exitSignal: record.exitSignal,
      timedOut: record.timedOut,
      outputLimited: record.outputTruncated,
      terminationConfirmed: record.terminationConfirmed,
      containment: record.containment,
      termination: record.termination,
      startedAt: now,
      exitedAt,
    }
  }

  async nativeExec(options: ExecOptions): Promise<ExecResult> {
    const session = await this.nativeExecStart(options)
    return this.nativeExecWait(
      session.id,
      Math.min((options.timeoutSeconds ?? 0) + EXEC_TERMINAL_WAIT_SECONDS, MAX_EXEC_RUNTIME_SECONDS)
    )
  }

  async nativeExecStart(
    options: ExecOptions
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
      id,
      title: options.title ?? `${options.command} ${args.join(' ')}`.trim(),
      description: options.description,
      command: options.command,
      args,
      mode: 'exec',
      workdir: canonicalWorkdir(options.workdir),
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
    this.records.set(id, record)
    await this.storage.writeSession(record)
    const redactionSecrets = Object.entries(environment)
      .filter(([key, value]) => SENSITIVE_ENVIRONMENT_KEY.test(key) && value.length >= 4)
      .map(([, value]) => value)
    let started: Awaited<ReturnType<typeof NativeWorkerClient.start>>
    try {
      started = await NativeWorkerClient.start({
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
      })
    } catch (error) {
      const cleanup =
        error instanceof WorkerStartError
          ? error.cleanup
          : { requested: false, terminationConfirmed: false, method: 'none' as const }
      record.status = cleanup.terminationConfirmed ? 'spawn_failed' : 'lost'
      record.terminationRequested = cleanup.requested
      record.terminationConfirmed = cleanup.terminationConfirmed
      record.exitReason = { kind: 'spawn_error', message: String(error), cleanup }
      record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(record)
      throw new ProcessError(String(error), { cleanup })
    }
    const initial = await started.client.snapshot()
    record.pid = initial.pid
    record.containment = initial.containment
    record.termination = initial.termination
    record.worker = started.reference
    record.status = 'running'
    record.updatedAt = new Date().toISOString()
    this.nativeWorkers.set(id, started.client)
    await this.storage.writeSession(record)
    void this.monitorNative(record, started.client)
    return { id, status: record.status, mode: 'exec', pid: record.pid }
  }

  async nativeExecWait(id: string, timeoutSeconds: number): Promise<ExecResult> {
    if (
      !Number.isInteger(timeoutSeconds) ||
      timeoutSeconds <= 0 ||
      timeoutSeconds > MAX_EXEC_RUNTIME_SECONDS
    )
      throw new Error(
        `timeoutSeconds must be a positive integer up to ${MAX_EXEC_RUNTIME_SECONDS} for exec`
      )
    const record = this.recordFor(id)
    if (record.mode !== 'exec') throw new Error(`Session '${id}' is not an exec session.`)
    const waited = await this.wait(id, { kind: 'exit' }, timeoutSeconds)
    if (waited.reason === 'deadline' && activeStatus(record)) {
      await this.stop(id)
      const stopped = await this.wait(id, { kind: 'exit' }, EXEC_TERMINAL_WAIT_SECONDS)
      if (stopped.reason === 'deadline')
        throw new ProcessError('Exec stop completed without terminal evidence.')
    }
    const current = this.recordFor(id)
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
    return (
      result.terminationConfirmed &&
      result.status !== 'running' &&
      (containmentDrained({
        containment: result.containment,
        terminationConfirmed: result.terminationConfirmed,
        directChildExited: result.directChildExited,
      }) ||
        (process.platform === 'darwin' && result.directChildExited))
    )
  }

  private async rollbackNative(
    record: SessionRecord,
    worker: WorkerClient,
    error: unknown
  ): Promise<void> {
    const version = this.bumpNativeVersion(record.id)
    const cleanup = await worker.rollback().catch((rollbackError) => ({
      requested: false,
      terminationConfirmed: false,
      method: 'none' as const,
      message: String(rollbackError),
    }))
    record.status = 'lost'
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
    await this.storage.removeWorkerDescriptor(record.id)
    this.nativeWorkers.delete(record.id)
  }

  private async finalizeNative(
    record: SessionRecord,
    worker: WorkerClient,
    result: WorkerSnapshot
  ): Promise<ExecResult | PTYSessionInfo> {
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
      () => {
        if (this.nativeFinalizations.get(record.id) === finalization)
          this.nativeFinalizations.delete(record.id)
      }
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
      return await this.finishNative(record, final, version, this.nativeTerminal(final))
    } catch (error) {
      await this.persistNativeFinalizationFailure(record, final, error)
      const failure = new Error(`Native finalization failed: ${String(error)}`)
      Object.assign(failure, { code: 'ESTORAGE' })
      throw failure
    } finally {
      if (this.nativeTerminal(final)) {
        try {
          await worker.shutdown().catch(() => undefined)
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
    record.status =
      result.status === 'lost'
        ? 'lost'
        : result.status === 'running'
          ? 'running'
          : result.exitReason === 'output_limit'
            ? 'output_limited'
            : result.timedOut
              ? 'timed_out'
              : 'exited'
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
    this.resolveOutputWaits(record)
    if (!activeStatus(record)) this.resolveExitWaits(record)
    if (
      (result.storageFailure || result.readerFailure || result.outputIncomplete) &&
      result.terminationConfirmed
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
    record.status = 'lost'
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
    const record = this.recordFor(id)
    const output = await this.outputFor(id)
    const lines = outputLines(output, record.firstRetainedSequence).filter(
      (line) => sequence === undefined || line.sequence >= sequence
    )
    const start = Math.max(0, offset)
    const page = limit === undefined ? lines.slice(start) : lines.slice(start, start + limit)
    return {
      lines: page.map((line) => line.text),
      sequences: page.map((line) => line.sequence),
      totalLines: lines.length,
      offset: start,
      hasMore: start + page.length < lines.length,
      firstRetainedSequence: record.firstRetainedSequence,
      nextSequence: record.nextSequence,
      truncated: record.outputTruncated,
      containment: record.containment,
      termination: record.termination,
    }
  }

  async search(
    id: string,
    pattern: string,
    ignoreCase = false,
    offset = 0,
    limit?: number,
    sequence?: number
  ): Promise<SearchResult> {
    const record = this.recordFor(id)
    const output = await this.outputFor(id)
    const matches = searchLines(output, pattern, ignoreCase, record.firstRetainedSequence).filter(
      (match) => sequence === undefined || match.sequence >= sequence
    )
    const start = Math.max(0, offset)
    const page = limit === undefined ? matches.slice(start) : matches.slice(start, start + limit)
    return {
      matches: page,
      totalMatches: matches.length,
      totalLines: lineCount(output),
      offset: start,
      hasMore: start + page.length < matches.length,
      firstRetainedSequence: record.firstRetainedSequence,
      nextSequence: record.nextSequence,
      truncated: record.outputTruncated,
      containment: record.containment,
      termination: record.termination,
    }
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
    await Promise.all(
      [...this.nativeWorkers.entries()].map(async ([id, worker]) => {
        const record = this.records.get(id)
        if (record?.worker) await this.syncNative(record, worker)
      })
    )
    return [...this.records.values()].map((record) => this.toInfo(record))
  }

  owns(
    id: string,
    parentSessionId: string,
    projectDirectory: string,
    capabilityHash: string
  ): boolean {
    const record = this.records.get(id)
    return Boolean(
      record &&
        record.parentSessionId === parentSessionId &&
        record.ownerProjectDirectory === projectDirectory &&
        record.ownerCapabilityHash === capabilityHash
    )
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
    const raw = await this.storage.readOutput(id)
    return {
      raw,
      byteLength: Buffer.byteLength(raw),
      containment: record.containment,
      termination: record.termination,
    }
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
    const native = this.nativeWorkers.get(id)
    if (native) {
      const record = this.recordFor(id)
      record.terminationRequested = true
      record.status = 'stopping'
      await this.storage.writeSession(record)
      const result = await native.stop()
      await this.finalizeNative(record, native, result)
      return {
        requested: true,
        terminationConfirmed: record.terminationConfirmed,
        directChildExited: record.directChildExited,
        containment: record.containment,
        termination: record.termination,
      }
    }
    const record = this.records.get(id)
    if (!record) throw new Error(`PTY session '${id}' not found.`)
    return {
      requested: false,
      terminationConfirmed: record.terminationConfirmed,
      directChildExited: record.directChildExited,
      containment: record.containment,
      termination: record.termination,
    }
  }

  async cleanup(id: string): Promise<boolean> {
    await this.flush()
    const record = this.records.get(id)
    if (!record) return false
    await this.nativeFinalizations.get(id)
    if (record.status === 'lost') {
      return this.deleteNativeSession(record)
    }
    if (!this.isTerminal(record)) return false
    const worker = this.nativeWorkers.get(id)
    if (worker) {
      try {
        const result = await worker.shutdown()
        if (
          !result.terminationConfirmed ||
          result.status === 'running' ||
          (!containmentDrained({
            containment: result.containment,
            terminationConfirmed: result.terminationConfirmed,
            directChildExited: result.directChildExited,
          }) &&
            !(process.platform === 'darwin' && result.directChildExited))
        )
          return false
      } catch {
        // A completed worker may have already removed its listener; its persisted terminal record is authoritative.
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
            record.lifecycle === 'conversation' &&
            record.status !== 'lost' &&
            (this.nativeWorkers.has(record.id) || record.worker)
        )
        .map((record) => this.cleanupConversation(record))
    )
  }

  private cleanupConversation(record: SessionRecord): Promise<void> {
    const existing = this.pendingConversationCleanup.get(record.id)
    if (existing) return existing
    const cleanup = (async () => {
      record.pendingCleanup = true
      await this.storage.writeSession(record)
      if (record.status === 'lost') return
      if (!activeStatus(record)) {
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

  async shutdown(final = false): Promise<void> {
    if (final) {
      await Promise.all(
        [...this.records.values()].map((record) => this.stop(record.id).catch(() => undefined))
      )
      await Promise.all(
        [...this.nativeWorkers.values()].map((worker) => worker.shutdown().catch(() => undefined))
      )
    }
  }

  private async outputFor(id: string): Promise<string> {
    this.recordFor(id)
    await this.persistQueue
    return this.storage.readOutput(id)
  }

  private enqueuePersist(task: () => Promise<void>): void {
    this.persistQueue = this.persistQueue.then(task, task)
  }

  private nativeVersion(id: string): number {
    return this.nativeVersions.get(id) ?? 0
  }

  private bumpNativeVersion(id: string): number {
    const version = this.nativeVersion(id) + 1
    this.nativeVersions.set(id, version)
    return version
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
    const previous = this.nativePersists.get(id) ?? Promise.resolve()
    const result = previous.then(task, task)
    const settled = result.then(
      () => undefined,
      () => undefined
    )
    this.nativePersists.set(id, settled)
    void settled.then(() => {
      if (this.nativePersists.get(id) === settled) this.nativePersists.delete(id)
    })
    return result
  }

  private deleteNativeSession(record: SessionRecord): Promise<boolean> {
    return this.enqueueNativePersist(record.id, async () => {
      if (this.records.get(record.id) !== record) return false
      this.bumpNativeVersion(record.id)
      this.nativeWorkers.delete(record.id)
      await this.storage.removeWorkerDescriptor(record.id)
      await this.storage.deleteSession(record.id)
      this.records.delete(record.id)
      return true
    })
  }

  private idempotentSession(options: SpawnOptions, args: string[]): SessionRecord | undefined {
    if (!options.idempotencyKey) return undefined
    const existing = [...this.records.values()].find(
      (record) =>
        activeStatus(record) &&
        record.mode === 'pty' &&
        record.parentSessionId === options.parentSessionId &&
        record.workdir === canonicalWorkdir(options.workdir) &&
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
      throw new Error('Output wait literal exceeds the size limit.')
    }
    if (condition.regex) safeRegex(condition.regex)
  }

  private async waitMatch(
    record: SessionRecord,
    condition: WaitCondition
  ): Promise<WaitResult | undefined> {
    if (condition.kind === 'exit') return activeStatus(record) ? undefined : this.exitWait(record)
    const output = await this.outputFor(record.id)
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

  private async collectExecOutput(
    stream: ReadableStream<Uint8Array> | null,
    limit: number,
    terminate: () => Promise<void>,
    registerStop: (stop: () => void) => void,
    redactor: OutputRedactor
  ): Promise<{ data: string; bytes: number; limited: boolean }> {
    if (!stream) return { data: '', bytes: 0, limited: false }
    const reader = stream.getReader()
    const decoder = new TextDecoder()
    let stopped = false
    let stop: (() => void) | undefined
    const stoppedReading = new Promise<void>((resolve) => {
      stop = () => {
        stopped = true
        resolve()
      }
    })
    registerStop(() => stop?.())
    let bytes = 0
    let data = ''
    let limited = false
    try {
      while (true) {
        const read = await Promise.race([
          reader.read(),
          stoppedReading.then(() => ({ done: true })),
        ])
        const { done } = read
        if (done) break
        if (!('value' in read)) break
        const value = read.value
        const redacted = redactor.write(decoder.decode(value, { stream: true }))
        const remaining = limit - bytes
        const kept = this.utf8Prefix(Buffer.from(redacted), Math.max(0, remaining))
        bytes += kept.byteLength
        data += Buffer.from(kept).toString('utf8')
        if (kept.byteLength !== Buffer.byteLength(redacted)) {
          limited = true
          void terminate()
          break
        }
      }
      if (!limited) {
        const redacted = redactor.write(decoder.decode()) + redactor.finish()
        const remaining = limit - bytes
        const kept = this.utf8Prefix(Buffer.from(redacted), Math.max(0, remaining))
        bytes += kept.byteLength
        data += Buffer.from(kept).toString('utf8')
        if (kept.byteLength !== Buffer.byteLength(redacted)) {
          limited = true
          void terminate()
        }
      }
      return { data, bytes, limited }
    } finally {
      if (stopped) await reader.cancel().catch(() => undefined)
      reader.releaseLock()
    }
  }

  private utf8Prefix(value: Uint8Array, limit: number): Uint8Array {
    let end = Math.min(value.byteLength, limit)
    while (end > 0 && ((value[end] ?? 0) & 0xc0) === 0x80) end -= 1
    return value.slice(0, end)
  }

  private exitReason(exitCode: number | null, signal?: number | string): ExitReason {
    if (exitCode !== null) return { kind: 'code', code: exitCode }
    if (signal) return { kind: 'signal', signal: String(signal) }
    return { kind: 'unknown' }
  }

  private redactionSecrets(environment: Record<string, string>): string[] {
    return Object.entries(environment)
      .filter(([key, value]) => SENSITIVE_ENVIRONMENT_KEY.test(key) && value.length >= 4)
      .map(([, value]) => value)
  }

  private recordFor(id: string): SessionRecord {
    const record = this.records.get(id)
    if (!record) throw new Error(`PTY session '${id}' not found.`)
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
