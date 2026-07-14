import { spawn, type IPty } from 'bun-pty'
import { realpathSync } from 'node:fs'
import { resolve } from 'node:path'
import type { PTYSessionInfo, ReadResult, SearchResult, SpawnOptions } from '../plugin/pty/types.ts'
import {
  type ExecResult,
  type EnvironmentProfile,
  OUTPUT_JOURNAL_VERSION,
  type ExitReason,
  type SessionRecord,
  type StopResult,
  type WaitCondition,
  type WaitResult,
  type WriteResult,
} from './types.ts'
import type { DaemonStorage } from './storage.ts'

const configuredOutputLimit = Number.parseInt(process.env.PTY_MAX_OUTPUT_BYTES ?? '1000000', 10)
const DEFAULT_MAX_OUTPUT_BYTES =
  Number.isSafeInteger(configuredOutputLimit) && configuredOutputLimit > 0
    ? configuredOutputLimit
    : 1000000
const OUTPUT_CHUNK_BYTES = 64 * 1024
const TERMINATION_GRACE_MS = 250
const TERMINATION_HARD_KILL_MS = 1000
const SAFE_ENVIRONMENT_KEYS = new Set([
  'PATH',
  'HOME',
  'USERPROFILE',
  'SYSTEMROOT',
  'WINDIR',
  'TEMP',
  'TMP',
  'TERM',
  'LANG',
  'ComSpec',
])
const SENSITIVE_ENVIRONMENT_KEY = /(token|secret|password|credential|api[_-]?key|auth|cookie)/i

interface ActiveSession {
  record: SessionRecord
  process: IPty
  environment: Record<string, string>
  timeout?: ReturnType<typeof setTimeout>
}

interface ExecOptions extends SpawnOptions {
  maxOutputBytes?: number
}

interface PendingWait {
  condition: WaitCondition
  settle: (result: WaitResult) => void
  timer: ReturnType<typeof setTimeout>
  settled: boolean
}

export class ProcessError extends Error {}

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

function outputChunks(data: string, startSequence: number, maxBytes: number) {
  const chunks: Array<{
    startSequence: number
    endSequence: number
    timestamp: string
    data: string
  }> = []
  const chunkBytes = Math.max(1, Math.min(OUTPUT_CHUNK_BYTES, maxBytes))
  let text = ''
  let bytes = 0
  let sequence = startSequence
  const timestamp = new Date().toISOString()
  for (const character of data) {
    const characterBytes = Buffer.byteLength(character)
    if (text && bytes + characterBytes > chunkBytes) {
      chunks.push({ startSequence: sequence, endSequence: sequence + bytes, timestamp, data: text })
      sequence += bytes
      text = ''
      bytes = 0
    }
    text += character
    bytes += characterBytes
  }
  if (text)
    chunks.push({ startSequence: sequence, endSequence: sequence + bytes, timestamp, data: text })
  return chunks
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

function runtimeEnvironment(
  requested: Record<string, string> | undefined,
  inherit: boolean
): Record<string, string> {
  const base = inherit
    ? process.env
    : Object.fromEntries(
        Object.entries(process.env).filter(
          ([key]) => SAFE_ENVIRONMENT_KEYS.has(key) || key.startsWith('LC_')
        )
      )
  return { ...base, ...requested } as Record<string, string>
}

function redactOutput(data: string, environment: Record<string, string>): string {
  let redacted = data
  for (const [key, value] of Object.entries(environment)) {
    if (SENSITIVE_ENVIRONMENT_KEY.test(key) && value.length >= 4) {
      redacted = redacted.replaceAll(value, '[REDACTED]')
    }
  }
  return redacted
}

export class SessionSupervisor {
  private readonly active = new Map<string, ActiveSession>()
  private readonly records = new Map<string, SessionRecord>()
  private readonly waits = new Map<string, PendingWait[]>()
  private persistQueue = Promise.resolve()

  constructor(
    private readonly storage: DaemonStorage,
    private readonly maxOutputBytes: number = DEFAULT_MAX_OUTPUT_BYTES
  ) {}

  async initialize(): Promise<void> {
    await this.storage.initialize()
    for (const record of await this.storage.loadSessions()) {
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
      if (
        record.status === 'starting' ||
        record.status === 'running' ||
        record.status === 'stopping'
      ) {
        const output = await this.storage.readOutput(record.id)
        record.status = 'lost'
        record.exitReason = { kind: 'unknown' }
        record.outputBytes = Buffer.byteLength(output)
        record.lineCount = lineCount(output)
        record.outputHasPartialLine = Boolean(output) && !output.endsWith('\n')
        record.updatedAt = new Date().toISOString()
        await this.storage.writeSession(record)
      }
      this.records.set(record.id, record)
    }
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
    let ptyProcess: IPty
    try {
      ptyProcess = spawn(record.command, record.args, {
        name: 'xterm-256color',
        cols: 120,
        rows: 40,
        cwd: record.workdir,
        env: environment,
      })
    } catch (error) {
      record.status = 'spawn_failed'
      record.terminationConfirmed = true
      record.exitReason = {
        kind: 'spawn_error',
        message: error instanceof Error ? error.message : String(error),
      }
      record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(record)
      throw new ProcessError(
        `Failed to spawn PTY '${id}': ${error instanceof Error ? error.message : String(error)}`
      )
    }
    record.pid = ptyProcess.pid
    record.status = 'running'
    record.updatedAt = new Date().toISOString()
    const active: ActiveSession = { record, process: ptyProcess, environment }
    this.active.set(id, active)
    ptyProcess.onData((data: string) => this.handleOutput(active, redactOutput(data, environment)))
    ptyProcess.onExit(
      ({ exitCode, signal }: { exitCode: number | null; signal?: number | string }) =>
        this.handleExit(active, exitCode, signal)
    )
    if (record.timeoutSeconds) {
      active.timeout = setTimeout(() => void this.timeout(id), record.timeoutSeconds * 1000)
    }
    await this.storage.writeSession(record)
    return this.toInfo(record)
  }

  async write(id: string, data: string): Promise<WriteResult> {
    await this.flush()
    const active = this.active.get(id)
    if (!active || active.record.status !== 'running')
      throw new Error(`PTY session '${id}' is closed.`)
    try {
      active.process.write(data)
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
    const record = this.recordFor(id)
    const afterSequence = record.nextSequence
    await this.write(id, data)
    return this.wait(
      id,
      { ...condition, ...(condition.kind === 'output' ? { afterSequence } : {}) },
      timeoutSeconds
    )
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
      }
    )
    const stderr = this.collectExecOutput(
      typeof child.stderr === 'object' ? child.stderr : null,
      limit,
      () => terminate('output_limit'),
      (stop) => {
        stopReading.push(stop)
      }
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
    const out = { ...capturedOut, data: redactOutput(capturedOut.data, environment) }
    const err = { ...capturedErr, data: redactOutput(capturedErr.data, environment) }
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
      startedAt: now,
      exitedAt,
    }
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
    }
  }

  async get(id: string): Promise<PTYSessionInfo | null> {
    await this.flush()
    const record = this.records.get(id)
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
    const record = this.records.get(id)
    return Boolean(
      record &&
        record.parentSessionId === parentSessionId &&
        record.ownerProjectDirectory === projectDirectory &&
        record.ownerCapabilityHash === capabilityHash
    )
  }

  async rawOutput(id: string): Promise<{ raw: string; byteLength: number } | null> {
    await this.flush()
    const record = this.records.get(id)
    if (!record) return null
    const raw = await this.storage.readOutput(id)
    return { raw, byteLength: Buffer.byteLength(raw) }
  }

  async execOutput(id: string) {
    await this.flush()
    const record = this.records.get(id)
    return record?.execOutput ?? null
  }

  async stop(id: string): Promise<StopResult> {
    await this.flush()
    const active = this.active.get(id)
    if (!active) {
      const record = this.records.get(id)
      if (!record) throw new Error(`PTY session '${id}' not found.`)
      return { requested: false, terminationConfirmed: record.terminationConfirmed }
    }
    if (active.record.terminationRequested) {
      return { requested: true, terminationConfirmed: false }
    }
    active.record.terminationRequested = true
    if (!active.record.timedOut) active.record.status = 'stopping'
    active.record.updatedAt = new Date().toISOString()
    await this.storage.writeSession(active.record)
    try {
      active.process.kill()
    } catch (error) {
      active.record.terminationRequested = false
      if (!active.record.timedOut) active.record.status = 'running'
      active.record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(active.record)
      throw new ProcessError(
        `Failed to stop PTY '${id}': ${error instanceof Error ? error.message : String(error)}`
      )
    }
    return { requested: true, terminationConfirmed: !this.active.has(id) }
  }

  async cleanup(id: string): Promise<boolean> {
    await this.flush()
    const record = this.records.get(id)
    if (!record || !this.isTerminal(record)) return false
    await this.storage.deleteSession(id)
    this.records.delete(id)
    return true
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
            this.active.has(record.id)
        )
        .map((record) => this.stop(record.id))
    )
  }

  async flush(): Promise<void> {
    await this.persistQueue
  }

  private async timeout(id: string): Promise<void> {
    const active = this.active.get(id)
    if (!active || active.record.status !== 'running') return
    active.record.timedOut = true
    active.record.status = 'timed_out'
    active.record.exitReason = { kind: 'timeout' }
    active.record.terminationRequested = true
    active.record.terminationConfirmed = false
    active.record.updatedAt = new Date().toISOString()
    await this.storage.writeSession(active.record)
    try {
      active.process.kill()
    } catch (error) {
      active.record.terminationRequested = false
      active.record.exitReason = {
        kind: 'timeout',
        message: `Failed to stop PTY: ${error instanceof Error ? error.message : String(error)}`,
      }
      active.record.updatedAt = new Date().toISOString()
      await this.storage.writeSession(active.record)
      return
    }
  }

  private handleOutput(active: ActiveSession, data: string): void {
    if (!data) return
    this.enqueuePersist(async () => {
      const next = { ...active.record }
      const byteLength = Buffer.byteLength(data)
      const chunks = outputChunks(data, next.nextSequence, this.maxOutputBytes)
      next.nextSequence += byteLength
      next.outputBytes += byteLength
      const newlines = data.split('\n').length - 1
      if (next.outputHasPartialLine) {
        next.lineCount += newlines - (data.endsWith('\n') ? 1 : 0)
      } else {
        next.lineCount += newlines + (data && !data.endsWith('\n') ? 1 : 0)
      }
      next.outputHasPartialLine = !data.endsWith('\n')
      next.updatedAt = new Date().toISOString()
      await this.storage.appendOutput(next.id, chunks)
      await this.trimOutput(next)
      await this.storage.writeSession(next)
      active.record.nextSequence = next.nextSequence
      active.record.firstRetainedSequence = next.firstRetainedSequence
      active.record.outputBytes = next.outputBytes
      active.record.outputTruncated = next.outputTruncated
      active.record.lineCount = next.lineCount
      active.record.outputHasPartialLine = next.outputHasPartialLine
      active.record.lastOutputAt = next.updatedAt
    })
    void this.persistQueue.then(() => this.resolveOutputWaits(active.record))
  }

  private handleExit(
    active: ActiveSession,
    exitCode: number | null,
    signal?: number | string
  ): void {
    if (active.timeout) clearTimeout(active.timeout)
    this.active.delete(active.record.id)
    if (active.record.timedOut) {
      active.record.status = 'timed_out'
      active.record.exitReason = { kind: 'timeout' }
    } else {
      active.record.status = 'exited'
      active.record.exitReason = this.exitReason(exitCode, signal)
    }
    active.record.exitCode = exitCode ?? undefined
    active.record.exitSignal = signal || undefined
    active.record.terminationConfirmed = true
    active.record.updatedAt = new Date().toISOString()
    active.record.exitedAt = active.record.updatedAt
    this.enqueuePersist(() => this.storage.writeSession(active.record))
    this.resolveExitWaits(active.record)
  }

  private async outputFor(id: string): Promise<string> {
    this.recordFor(id)
    await this.persistQueue
    return this.storage.readOutput(id)
  }

  private async trimOutput(record: SessionRecord): Promise<void> {
    if (record.outputBytes <= this.maxOutputBytes) return
    const retained = await this.storage.retainedOutput(record.id, this.maxOutputBytes)
    record.outputBytes = retained.outputBytes
    record.firstRetainedSequence = retained.firstRetainedSequence
    record.outputTruncated ||= retained.outputTruncated
    await this.storage.writeSession(record)
    await this.storage.trimOutput(record.id, this.maxOutputBytes)
    const output = await this.storage.readOutput(record.id)
    record.lineCount = lineCount(output)
    record.outputHasPartialLine = Boolean(output) && !output.endsWith('\n')
  }

  private enqueuePersist(task: () => Promise<void>): void {
    this.persistQueue = this.persistQueue.then(task, task)
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
    if (
      existing.command !== options.command ||
      JSON.stringify(existing.args) !== JSON.stringify(args) ||
      existing.environment.fingerprint !==
        environmentProfile(
          runtimeEnvironment(options.env, options.inheritEnv === true),
          options.inheritEnv === true
        ).fingerprint ||
      existing.timeoutSeconds !== options.timeoutSeconds
    ) {
      throw new Error(
        'Idempotency key matches an active PTY with a different command or specification.'
      )
    }
    return existing
  }

  private validateWait(condition: WaitCondition, timeoutSeconds: number): void {
    if (!Number.isInteger(timeoutSeconds) || timeoutSeconds <= 0 || timeoutSeconds > 3600) {
      throw new Error('wait timeoutSeconds must be a positive integer up to 3600.')
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
    }
  }

  private waitEnded(record: SessionRecord, condition: WaitCondition): WaitResult {
    const exit = this.exitWait(record)
    return condition.kind === 'exit' ? exit : { ...exit, satisfied: false }
  }

  private async finishWait(record: SessionRecord, result: WaitResult): Promise<WaitResult> {
    record.lastWaitResult = result
    record.updatedAt = new Date().toISOString()
    this.enqueuePersist(() => this.storage.writeSession(record))
    await this.persistQueue
    return result
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
    registerStop: (stop: () => void) => void
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
        const remaining = limit - bytes
        if (remaining <= 0) {
          limited = true
          void terminate()
          continue
        }
        const kept = value.byteLength <= remaining ? value : this.utf8Prefix(value, remaining)
        bytes += kept.byteLength
        data += decoder.decode(kept, { stream: true })
        if (kept.byteLength !== value.byteLength) {
          limited = true
          void terminate()
        }
      }
      data += decoder.decode()
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

  private recordFor(id: string): SessionRecord {
    const record = this.records.get(id)
    if (!record) throw new Error(`PTY session '${id}' not found.`)
    return record
  }

  private isTerminal(record: SessionRecord): boolean {
    return record.terminationConfirmed
  }

  private toInfo(record: SessionRecord): PTYSessionInfo {
    return {
      id: record.id,
      title: record.title,
      description: record.description,
      command: record.command,
      args: record.args,
      mode: record.mode,
      name: record.name,
      idempotencyKey: record.idempotencyKey,
      workdir: record.workdir,
      status: record.status,
      timeoutSeconds: record.timeoutSeconds,
      timedOut: record.timedOut,
      terminationRequested: record.terminationRequested,
      terminationConfirmed: record.terminationConfirmed,
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
      lastWaitResult: record.lastWaitResult,
      execOutput: record.execOutput,
      environment: record.environment,
    }
  }
}
