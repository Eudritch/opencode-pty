import { spawn, type IPty } from 'bun-pty'
import type { PTYSessionInfo, ReadResult, SearchResult, SpawnOptions } from '../plugin/pty/types.ts'
import type { ExitReason, SessionRecord, StopResult, WriteResult } from './types.ts'
import type { DaemonStorage } from './storage.ts'

const configuredOutputLimit = Number.parseInt(process.env.PTY_MAX_OUTPUT_BYTES ?? '1000000', 10)
const DEFAULT_MAX_OUTPUT_BYTES =
  Number.isSafeInteger(configuredOutputLimit) && configuredOutputLimit > 0
    ? configuredOutputLimit
    : 1000000

interface ActiveSession {
  record: SessionRecord
  process: IPty
  timeout?: ReturnType<typeof setTimeout>
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

export class SessionSupervisor {
  private readonly active = new Map<string, ActiveSession>()
  private readonly records = new Map<string, SessionRecord>()
  private persistQueue = Promise.resolve()

  constructor(
    private readonly storage: DaemonStorage,
    private readonly maxOutputBytes: number = DEFAULT_MAX_OUTPUT_BYTES
  ) {}

  async initialize(): Promise<void> {
    await this.storage.initialize()
    for (const record of await this.storage.loadSessions()) {
      record.terminationRequested ??= record.status === 'stopping'
      record.terminationConfirmed ??=
        record.status === 'exited' ||
        record.status === 'timed_out' ||
        record.status === 'spawn_failed'
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
    const id = `pty_${crypto.randomUUID()}`
    const args = options.args ?? []
    const now = new Date().toISOString()
    const record: SessionRecord = {
      id,
      title:
        options.title ??
        (`${options.command} ${args.join(' ')}`.trim() || `Terminal ${id.slice(-8)}`),
      description: options.description,
      command: options.command,
      args,
      workdir: options.workdir ?? process.cwd(),
      env: options.env,
      status: 'starting',
      pid: 0,
      createdAt: now,
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
        env: { ...process.env, ...record.env } as Record<string, string>,
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
    const active: ActiveSession = { record, process: ptyProcess }
    this.active.set(id, active)
    ptyProcess.onData((data: string) => this.handleOutput(active, data))
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

  async read(id: string, offset = 0, limit?: number): Promise<ReadResult> {
    const record = this.recordFor(id)
    const output = await this.outputFor(id)
    const lines = outputLines(output, record.firstRetainedSequence)
    const start = Math.max(0, offset)
    const page = limit === undefined ? lines.slice(start) : lines.slice(start, start + limit)
    return {
      lines: page.map((line) => line.text),
      sequences: page.map((line) => line.sequence),
      totalLines: lines.length,
      offset: start,
      hasMore: start + page.length < lines.length,
    }
  }

  async search(
    id: string,
    pattern: string,
    ignoreCase = false,
    offset = 0,
    limit?: number
  ): Promise<SearchResult> {
    const record = this.recordFor(id)
    const output = await this.outputFor(id)
    const matches = searchLines(output, pattern, ignoreCase, record.firstRetainedSequence)
    const start = Math.max(0, offset)
    const page = limit === undefined ? matches.slice(start) : matches.slice(start, start + limit)
    return {
      matches: page,
      totalMatches: matches.length,
      totalLines: lineCount(output),
      offset: start,
      hasMore: start + page.length < matches.length,
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

  async rawOutput(id: string): Promise<{ raw: string; byteLength: number } | null> {
    await this.flush()
    const record = this.records.get(id)
    if (!record) return null
    const raw = await this.storage.readOutput(id)
    return { raw, byteLength: Buffer.byteLength(raw) }
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

  async cleanupByParentSession(parentSessionId: string): Promise<void> {
    await Promise.all(
      [...this.records.values()]
        .filter(
          (record) => record.parentSessionId === parentSessionId && this.active.has(record.id)
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
      await this.storage.appendOutput(next.id, data)
      await this.trimOutput(next)
      await this.storage.writeSession(next)
      active.record.nextSequence = next.nextSequence
      active.record.firstRetainedSequence = next.firstRetainedSequence
      active.record.outputBytes = next.outputBytes
      active.record.outputTruncated = next.outputTruncated
      active.record.lineCount = next.lineCount
      active.record.outputHasPartialLine = next.outputHasPartialLine
    })
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
    this.enqueuePersist(() => this.storage.writeSession(active.record))
  }

  private async outputFor(id: string): Promise<string> {
    this.recordFor(id)
    await this.persistQueue
    return this.storage.readOutput(id)
  }

  private async trimOutput(record: SessionRecord): Promise<void> {
    if (record.outputBytes <= this.maxOutputBytes) return
    // ponytail: one output file; use segmented journals when retention needs to avoid rewrite cost.
    const output = await this.storage.readOutput(record.id)
    const bytes = Buffer.from(output)
    let start = Math.max(0, bytes.length - this.maxOutputBytes)
    while (start < bytes.length) {
      const byte = bytes[start]
      if (byte === undefined || (byte & 0xc0) !== 0x80) break
      start += 1
    }
    const retained = bytes.subarray(start).toString('utf8')
    record.outputBytes = Buffer.byteLength(retained)
    record.lineCount = lineCount(retained)
    record.outputHasPartialLine = Boolean(retained) && !retained.endsWith('\n')
    record.firstRetainedSequence = record.nextSequence - record.outputBytes
    record.outputTruncated = true
    await this.storage.replaceOutput(record.id, retained)
  }

  private enqueuePersist(task: () => Promise<void>): void {
    this.persistQueue = this.persistQueue.then(task, task)
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
      lineCount: record.lineCount,
      outputSequence: record.nextSequence,
      firstRetainedSequence: record.firstRetainedSequence,
      outputTruncated: record.outputTruncated,
    }
  }
}
