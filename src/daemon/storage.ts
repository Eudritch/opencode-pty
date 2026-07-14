import { chmod, mkdir, open, readdir, readFile, rename, rm, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import {
  type DaemonDescriptor,
  type ExitReason,
  OUTPUT_JOURNAL_VERSION,
  type OutputChunk,
  type SessionRecord,
} from './types.ts'

const DESCRIPTOR_FILE = 'daemon.json'
const OWNERSHIP_SECRET_FILE = 'ownership-secret'
const SESSIONS_DIRECTORY = 'sessions'
const METADATA_FILE = 'session.json'
const LEGACY_OUTPUT_FILE = 'output.log'
const OUTPUT_DIRECTORY = 'output'
const START_LOCK_FILE = 'daemon-start.lock'
const STALE_START_LOCK_MS = 10000
const QUARANTINE_DIRECTORY = 'quarantine'
const OUTPUT_SEGMENT_BYTES = 64 * 1024

class InvalidSessionError extends Error {}
class InvalidJournalError extends InvalidSessionError {}

const SESSION_STATUSES = new Set([
  'starting',
  'running',
  'stopping',
  'exited',
  'timed_out',
  'lost',
  'spawn_failed',
  'output_limited',
])

function validText(value: unknown): value is string {
  if (typeof value !== 'string') return false
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code < 0xd800 || code > 0xdfff) continue
    if (code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1)
      if (next >= 0xdc00 && next <= 0xdfff) {
        index += 1
        continue
      }
    }
    return false
  }
  return true
}

function validTimestamp(value: unknown): value is string {
  return validText(value) && Number.isFinite(Date.parse(value))
}

function validNonnegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

export function daemonDataDirectory(): string {
  if (process.env.PTY_DAEMON_DIR) return process.env.PTY_DAEMON_DIR
  const base = process.env.APPDATA ?? process.env.XDG_STATE_HOME ?? process.env.HOME
  if (!base) throw new Error('Unable to determine a per-user daemon data directory.')
  return join(base, 'opencode-pty')
}

export class DaemonStorage {
  private readonly outputTails = new Map<string, OutputChunk>()
  private readonly writes = new Map<string, Promise<void>>()
  private windowsUserSid: Promise<string> | undefined
  private windowsRootProtected = false

  constructor(private readonly root: string = daemonDataDirectory()) {}

  get rootDirectory(): string {
    return this.root
  }

  get descriptorPath(): string {
    return join(this.root, DESCRIPTOR_FILE)
  }

  private get ownershipSecretPath(): string {
    return join(this.root, OWNERSHIP_SECRET_FILE)
  }

  private get startLockPath(): string {
    return join(this.root, START_LOCK_FILE)
  }

  private sessionDirectory(id: string): string {
    return join(this.root, SESSIONS_DIRECTORY, id)
  }

  private metadataPath(id: string): string {
    return join(this.sessionDirectory(id), METADATA_FILE)
  }

  private outputDirectory(id: string): string {
    return join(this.sessionDirectory(id), OUTPUT_DIRECTORY)
  }

  private legacyOutputPath(id: string): string {
    return join(this.sessionDirectory(id), LEGACY_OUTPUT_FILE)
  }

  async initialize(): Promise<void> {
    if (process.platform === 'win32') {
      await mkdir(this.root, { recursive: true, mode: 0o700 })
      if (!this.windowsRootProtected) {
        await this.protectWindowsPath(this.root, true)
        this.windowsRootProtected = true
      }
      await Promise.all([
        mkdir(join(this.root, SESSIONS_DIRECTORY), { recursive: true, mode: 0o700 }),
        mkdir(join(this.root, QUARANTINE_DIRECTORY), { recursive: true, mode: 0o700 }),
      ])
      return
    }
    await this.privateDirectory(this.root)
    await this.privateDirectory(join(this.root, SESSIONS_DIRECTORY))
    await this.privateDirectory(join(this.root, QUARANTINE_DIRECTORY))
  }

  async readDescriptor(): Promise<DaemonDescriptor | null> {
    try {
      return JSON.parse(await readFile(this.descriptorPath, 'utf8')) as DaemonDescriptor
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw error
    }
  }

  async writeDescriptor(descriptor: DaemonDescriptor): Promise<void> {
    await this.writeAtomic(this.descriptorPath, JSON.stringify(descriptor))
  }

  async removeDescriptor(): Promise<void> {
    await rm(this.descriptorPath, { force: true })
  }

  async ownershipSecret(): Promise<string> {
    await this.initialize()
    try {
      const secret = (await readFile(this.ownershipSecretPath, 'utf8')).trim()
      if (/^[a-f0-9]{64}$/.test(secret)) return secret
      throw new Error('Daemon ownership secret is invalid.')
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
    const secret = crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '')
    try {
      const handle = await open(this.ownershipSecretPath, 'wx', 0o600)
      try {
        await handle.writeFile(secret, 'utf8')
        await handle.sync()
      } finally {
        await handle.close()
      }
      await this.privateFile(this.ownershipSecretPath)
      await this.syncDirectory(this.root)
      return secret
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      return this.ownershipSecret()
    }
  }

  async acquireStartLock(): Promise<boolean> {
    await this.initialize()
    try {
      const handle = await open(this.startLockPath, 'wx', 0o600)
      await handle.close()
      await this.privateFile(this.startLockPath)
      return true
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      let lock: Awaited<ReturnType<typeof stat>>
      try {
        lock = await stat(this.startLockPath)
      } catch (statError) {
        if ((statError as NodeJS.ErrnoException).code === 'ENOENT') return this.acquireStartLock()
        throw statError
      }
      if (Date.now() - lock.mtimeMs < STALE_START_LOCK_MS) return false
      await rm(this.startLockPath, { force: true })
      return this.acquireStartLock()
    }
  }

  async releaseStartLock(): Promise<void> {
    await rm(this.startLockPath, { force: true })
  }

  async writeSession(record: SessionRecord): Promise<void> {
    if (!this.validSession(record, record.id))
      throw new Error('Refusing to persist invalid PTY session.')
    const directory = this.sessionDirectory(record.id)
    await this.privateDirectory(directory)
    await this.writeAtomic(this.metadataPath(record.id), JSON.stringify(record))
  }

  async appendOutput(id: string, chunks: OutputChunk[]): Promise<void> {
    if (chunks.length === 0) return
    const directory = this.outputDirectory(id)
    await this.privateDirectory(directory)
    for (const chunk of chunks) {
      const previous = this.outputTails.get(id)
      if (
        previous &&
        previous.endSequence === chunk.startSequence &&
        previous.endSequence - previous.startSequence + (chunk.endSequence - chunk.startSequence) <=
          OUTPUT_SEGMENT_BYTES
      ) {
        previous.endSequence = chunk.endSequence
        previous.data += chunk.data
        await this.writeAtomic(
          join(directory, `${previous.startSequence.toString().padStart(20, '0')}.json`),
          JSON.stringify(previous)
        )
        continue
      }
      await this.writeAtomic(
        join(directory, `${chunk.startSequence.toString().padStart(20, '0')}.json`),
        JSON.stringify(chunk)
      )
      if (!previous || chunk.endSequence > previous.endSequence)
        this.outputTails.set(id, { ...chunk })
    }
  }

  async readOutputChunks(id: string): Promise<OutputChunk[]> {
    try {
      const directory = this.outputDirectory(id)
      const entries = await readdir(directory)
      const chunks = await Promise.all(
        entries
          .filter((entry) => entry.endsWith('.json'))
          .sort()
          .map(async (entry) => this.readOutputChunk(join(directory, entry), entry))
      )
      chunks.sort((left, right) => left.startSequence - right.startSequence)
      for (let index = 1; index < chunks.length; index += 1) {
        if (chunks[index - 1]?.endSequence !== chunks[index]?.startSequence) {
          throw new InvalidJournalError('chunk sequence is discontinuous')
        }
      }
      return chunks
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw error
    }
  }

  async readOutput(id: string): Promise<string> {
    return (await this.readOutputChunks(id)).map((chunk) => chunk.data).join('')
  }

  async trimOutput(
    id: string,
    maxBytes: number
  ): Promise<{
    outputBytes: number
    firstRetainedSequence: number
    outputTruncated: boolean
  }> {
    const { chunks, ...retained } = await this.retainedOutput(id, maxBytes)
    for (const chunk of chunks) {
      await rm(
        join(this.outputDirectory(id), `${chunk.startSequence.toString().padStart(20, '0')}.json`)
      )
    }
    if (chunks.length > 0) await this.syncDirectory(this.outputDirectory(id))
    this.outputTails.delete(id)
    return retained
  }

  async retainedOutput(
    id: string,
    maxBytes: number
  ): Promise<{
    chunks: OutputChunk[]
    outputBytes: number
    firstRetainedSequence: number
    outputTruncated: boolean
  }> {
    const allChunks = await this.readOutputChunks(id)
    let retainedBytes = allChunks.reduce(
      (total, chunk) => total + chunk.endSequence - chunk.startSequence,
      0
    )
    let first = 0
    let firstRetainedSequence = allChunks[0]?.startSequence ?? 0
    while (retainedBytes > maxBytes && first < allChunks.length) {
      const chunk = allChunks[first]
      if (!chunk) break
      retainedBytes -= chunk.endSequence - chunk.startSequence
      firstRetainedSequence = chunk.endSequence
      first += 1
    }
    const retained = allChunks.slice(first)
    firstRetainedSequence = retained[0]?.startSequence ?? firstRetainedSequence
    return {
      chunks: allChunks.slice(0, first),
      outputBytes: retainedBytes,
      firstRetainedSequence,
      outputTruncated: first > 0,
    }
  }

  async deleteSession(id: string): Promise<void> {
    this.outputTails.delete(id)
    await rm(this.sessionDirectory(id), { recursive: true, force: true })
  }

  async removeWorkerDescriptor(id: string): Promise<void> {
    await rm(join(this.sessionDirectory(id), 'worker.json'), { force: true })
  }

  async loadSessions(): Promise<SessionRecord[]> {
    try {
      const entries = await readdir(join(this.root, SESSIONS_DIRECTORY), { withFileTypes: true })
      const records = await Promise.all(
        entries.filter((entry) => entry.isDirectory()).map((entry) => this.readSession(entry.name))
      )
      return records.filter((record): record is SessionRecord => record !== null)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw error
    }
  }

  private async readSession(id: string): Promise<SessionRecord | null> {
    try {
      let record: unknown
      try {
        record = JSON.parse(await readFile(this.metadataPath(id), 'utf8'))
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
        throw new InvalidSessionError()
      }
      if (!this.validSession(record, id)) throw new InvalidSessionError()
      return await this.migrateSession(record)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      if (error instanceof InvalidSessionError) {
        await this.quarantineSession(
          id,
          error instanceof InvalidJournalError
            ? `corrupt output journal: ${error.message}`
            : 'malformed metadata'
        )
        return null
      }
      throw error
    }
  }

  private validSession(record: unknown, id: string): record is SessionRecord {
    if (!record || typeof record !== 'object') return false
    const value = record as Partial<SessionRecord>
    const validOptionalText = (item: unknown) => item === undefined || validText(item)
    const validOptionalTimestamp = (item: unknown) => item === undefined || validTimestamp(item)
    const validOptionalInteger = (item: unknown) =>
      item === undefined || validNonnegativeInteger(item)
    const validExitReason = (reason: unknown): boolean => {
      if (reason === undefined) return true
      if (!reason || typeof reason !== 'object' || !validText((reason as ExitReason).kind))
        return false
      const value = reason as ExitReason
      return (
        (value.kind === 'code' && validNonnegativeInteger(value.code)) ||
        (value.kind === 'signal' && validText(value.signal)) ||
        ((value.kind === 'timeout' || value.kind === 'output_limit') &&
          (value.message === undefined || validText(value.message))) ||
        value.kind === 'stopped' ||
        (value.kind === 'spawn_error' &&
          validText(value.message) &&
          (value.cleanup === undefined ||
            (typeof value.cleanup === 'object' &&
              value.cleanup !== null &&
              typeof value.cleanup.requested === 'boolean' &&
              typeof value.cleanup.terminationConfirmed === 'boolean' &&
              ['shutdown', 'rollback', 'kill', 'none'].includes(value.cleanup.method) &&
              (value.cleanup.directChildPid === undefined ||
                validNonnegativeInteger(value.cleanup.directChildPid)) &&
              (value.cleanup.message === undefined || validText(value.cleanup.message))))) ||
        (value.kind === 'unknown' && (value.message === undefined || validText(value.message)))
      )
    }
    const validEnvironment = (environment: unknown): boolean => {
      if (environment === undefined) return true
      if (!environment || typeof environment !== 'object') return false
      const value = environment as SessionRecord['environment']
      return (
        (value.kind === 'safe' || value.kind === 'inherit') &&
        Array.isArray(value.keys) &&
        value.keys.every(validText) &&
        validText(value.fingerprint) &&
        typeof value.sensitive === 'boolean'
      )
    }
    const validExecOutput = (output: unknown): boolean => {
      if (output === undefined) return true
      if (!output || typeof output !== 'object') return false
      const value = output as Record<string, unknown>
      return (
        validText(value.stdout) &&
        validText(value.stderr) &&
        validNonnegativeInteger(value.stdoutBytes) &&
        validNonnegativeInteger(value.stderrBytes) &&
        value.stdoutBytes >= Buffer.byteLength(value.stdout) &&
        value.stderrBytes >= Buffer.byteLength(value.stderr) &&
        typeof value.stdoutTruncated === 'boolean' &&
        typeof value.stderrTruncated === 'boolean'
      )
    }
    const validWait = (wait: unknown): boolean => {
      if (wait === undefined) return true
      if (!wait || typeof wait !== 'object') return false
      const value = wait as Record<string, unknown>
      return (
        typeof value.satisfied === 'boolean' &&
        (value.reason === 'output' || value.reason === 'exit' || value.reason === 'deadline') &&
        validTimestamp(value.observedAt) &&
        validOptionalText(value.matched) &&
        validOptionalInteger(value.exitCode) &&
        (value.exitSignal === undefined ||
          validNonnegativeInteger(value.exitSignal) ||
          validText(value.exitSignal)) &&
        typeof value.outputTruncated === 'boolean'
      )
    }
    const validWorker = (worker: unknown): boolean => {
      if (worker === undefined) return true
      if (!worker || typeof worker !== 'object') return false
      const value = worker as Record<string, unknown>
      return (
        validNonnegativeInteger(value.pid) &&
        value.pid > 0 &&
        validText(value.startIdentity) &&
        validText(value.processIdentity) &&
        validText(value.endpoint) &&
        value.protocolVersion === 1
      )
    }
    if (
      value.id !== id ||
      !validText(value.title) ||
      !validText(value.command) ||
      !Array.isArray(value.args) ||
      !value.args.every(validText) ||
      !validOptionalText(value.description) ||
      !validOptionalText(value.name) ||
      !validOptionalText(value.idempotencyKey) ||
      !validText(value.workdir) ||
      !validOptionalText(value.ownerProjectDirectory) ||
      !validOptionalText(value.ownerCapabilityHash) ||
      !validOptionalText(value.parentSessionId) ||
      !validOptionalText(value.parentAgent) ||
      !SESSION_STATUSES.has(value.status ?? '') ||
      !validNonnegativeInteger(value.pid) ||
      !validTimestamp(value.createdAt) ||
      !validTimestamp(value.updatedAt) ||
      !validOptionalTimestamp(value.startedAt) ||
      !validOptionalTimestamp(value.exitedAt) ||
      !validOptionalTimestamp(value.lastOutputAt) ||
      !validOptionalInteger(value.timeoutSeconds) ||
      (value.timeoutSeconds !== undefined && value.timeoutSeconds === 0) ||
      typeof value.timedOut !== 'boolean' ||
      (value.terminationRequested !== undefined &&
        typeof value.terminationRequested !== 'boolean') ||
      (value.terminationConfirmed !== undefined &&
        typeof value.terminationConfirmed !== 'boolean') ||
      !validOptionalInteger(value.exitCode) ||
      (value.exitSignal !== undefined &&
        !validNonnegativeInteger(value.exitSignal) &&
        !validText(value.exitSignal)) ||
      !validExitReason(value.exitReason) ||
      !validNonnegativeInteger(value.nextSequence) ||
      !validNonnegativeInteger(value.firstRetainedSequence) ||
      !validNonnegativeInteger(value.outputBytes) ||
      typeof value.outputTruncated !== 'boolean' ||
      !validNonnegativeInteger(value.lineCount) ||
      typeof value.outputHasPartialLine !== 'boolean' ||
      (value.outputJournalVersion !== undefined &&
        value.outputJournalVersion !== OUTPUT_JOURNAL_VERSION) ||
      (value.mode !== undefined && value.mode !== 'pty' && value.mode !== 'exec') ||
      (value.lifecycle !== undefined &&
        value.lifecycle !== 'conversation' &&
        value.lifecycle !== 'persistent') ||
      !validEnvironment(value.environment) ||
      !validExecOutput(value.execOutput) ||
      !validWorker(value.worker) ||
      !validOptionalText(value.storageFailure) ||
      !validWait(value.lastWaitResult)
    ) {
      return false
    }
    if (
      Date.parse(value.createdAt) > Date.parse(value.updatedAt) ||
      (value.startedAt !== undefined &&
        Date.parse(value.startedAt) < Date.parse(value.createdAt)) ||
      (value.exitedAt !== undefined && Date.parse(value.exitedAt) < Date.parse(value.createdAt)) ||
      value.firstRetainedSequence > value.nextSequence ||
      (!value.outputTruncated && value.firstRetainedSequence !== 0)
    ) {
      return false
    }
    if (value.mode === 'exec') {
      return (
        (value.worker !== undefined ||
          (value.firstRetainedSequence === 0 && value.nextSequence === 0)) &&
        (value.execOutput === undefined ||
          value.outputBytes === value.execOutput.stdoutBytes + value.execOutput.stderrBytes)
      )
    }
    return value.outputBytes <= value.nextSequence - value.firstRetainedSequence
  }

  private async quarantineSession(id: string, reason: string): Promise<void> {
    try {
      await rename(
        this.sessionDirectory(id),
        join(this.root, QUARANTINE_DIRECTORY, `${id}-${Date.now()}-${crypto.randomUUID()}`)
      )
      console.warn(`Skipped PTY session ${JSON.stringify(id)}: ${reason}.`)
    } catch {
      console.warn(`Skipped PTY session ${JSON.stringify(id)}: ${reason}; quarantine failed.`)
    }
  }

  private async migrateSession(record: SessionRecord): Promise<SessionRecord> {
    let chunks = await this.readOutputChunks(record.id)
    if (record.outputJournalVersion !== OUTPUT_JOURNAL_VERSION && chunks.length === 0) {
      let legacyOutput = ''
      try {
        legacyOutput = await readFile(this.legacyOutputPath(record.id), 'utf8')
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
      }
      if (legacyOutput) {
        const startSequence = record.firstRetainedSequence ?? 0
        await this.appendOutput(record.id, [
          {
            startSequence,
            endSequence: startSequence + Buffer.byteLength(legacyOutput),
            timestamp: record.updatedAt,
            data: legacyOutput,
          },
        ])
        chunks = await this.readOutputChunks(record.id)
      }
    }
    if (
      record.mode !== 'exec' &&
      chunks.length > 0 &&
      chunks.at(-1)?.endSequence !== record.nextSequence
    ) {
      throw new InvalidJournalError('chunk cursor does not match session cursor')
    }
    if (record.outputJournalVersion === OUTPUT_JOURNAL_VERSION && record.outputTruncated) {
      await this.discardOutputBefore(record.id, record.firstRetainedSequence)
      chunks = await this.readOutputChunks(record.id)
    }
    if (
      record.mode !== 'exec' &&
      chunks.length > 0 &&
      chunks.at(-1)?.endSequence !== record.nextSequence
    ) {
      throw new InvalidJournalError('retained chunk cursor does not match session cursor')
    }
    const migrated = this.reconcileSession(record, chunks)
    if (
      record.outputJournalVersion !== OUTPUT_JOURNAL_VERSION ||
      !this.sameJournalState(record, migrated)
    ) {
      await this.writeSession(migrated)
    }
    if (record.outputJournalVersion !== OUTPUT_JOURNAL_VERSION) {
      // The v1 source is disposable only after its journal and metadata are durable.
      await rm(this.legacyOutputPath(record.id), { force: true })
    }
    return migrated
  }

  private reconcileSession(record: SessionRecord, chunks: OutputChunk[]): SessionRecord {
    if (record.mode === 'exec') {
      return { ...record, outputJournalVersion: OUTPUT_JOURNAL_VERSION }
    }
    const output = chunks.map((chunk) => chunk.data).join('')
    const firstRetainedSequence = chunks[0]?.startSequence ?? record.nextSequence ?? 0
    const nextSequence = Math.max(
      record.nextSequence ?? 0,
      chunks.at(-1)?.endSequence ?? firstRetainedSequence
    )
    return {
      ...record,
      nextSequence,
      firstRetainedSequence,
      outputBytes: Buffer.byteLength(output),
      outputTruncated: firstRetainedSequence > 0,
      lineCount: output ? output.split('\n').length - Number(output.endsWith('\n')) : 0,
      outputHasPartialLine: Boolean(output) && !output.endsWith('\n'),
      outputJournalVersion: OUTPUT_JOURNAL_VERSION,
    }
  }

  private sameJournalState(left: SessionRecord, right: SessionRecord): boolean {
    return (
      left.nextSequence === right.nextSequence &&
      left.firstRetainedSequence === right.firstRetainedSequence &&
      left.outputBytes === right.outputBytes &&
      left.outputTruncated === right.outputTruncated &&
      left.lineCount === right.lineCount &&
      left.outputHasPartialLine === right.outputHasPartialLine &&
      left.outputJournalVersion === right.outputJournalVersion
    )
  }

  private async readOutputChunk(path: string, entry: string): Promise<OutputChunk> {
    if (!/^\d{20}\.json$/.test(entry)) throw new InvalidJournalError('chunk filename is invalid')
    let value: unknown
    try {
      value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await readFile(path)))
    } catch {
      throw new InvalidJournalError('chunk is not valid UTF-8 JSON')
    }
    if (!value || typeof value !== 'object')
      throw new InvalidJournalError('chunk schema is invalid')
    const chunk = value as Partial<OutputChunk>
    if (
      !validNonnegativeInteger(chunk.startSequence) ||
      !validNonnegativeInteger(chunk.endSequence) ||
      chunk.endSequence < chunk.startSequence ||
      !validTimestamp(chunk.timestamp) ||
      !validText(chunk.data) ||
      chunk.data.length === 0 ||
      chunk.endSequence - chunk.startSequence !== Buffer.byteLength(chunk.data) ||
      entry !== `${chunk.startSequence.toString().padStart(20, '0')}.json`
    ) {
      throw new InvalidJournalError('chunk schema or sequence is invalid')
    }
    return chunk as OutputChunk
  }

  private async writeAtomic(path: string, contents: string): Promise<void> {
    const previous = this.writes.get(path) ?? Promise.resolve()
    const write = previous.catch(() => undefined).then(() => this.writeAtomicNow(path, contents))
    this.writes.set(path, write)
    try {
      await write
    } finally {
      if (this.writes.get(path) === write) this.writes.delete(path)
    }
  }

  private async writeAtomicNow(path: string, contents: string): Promise<void> {
    const temporaryPath = `${path}.${crypto.randomUUID()}.tmp`
    const handle = await open(temporaryPath, 'w', 0o600)
    try {
      await handle.writeFile(contents, 'utf8')
      await handle.sync()
    } finally {
      await handle.close()
    }
    await rename(temporaryPath, path)
    await this.privateFile(path)
    await this.syncDirectory(dirname(path))
  }

  private async syncDirectory(path: string): Promise<void> {
    if (process.platform === 'win32') return
    const handle = await open(path, 'r')
    try {
      await handle.sync()
    } finally {
      await handle.close()
    }
  }

  private async discardOutputBefore(id: string, sequence: number): Promise<void> {
    const chunks = (await this.readOutputChunks(id)).filter(
      (chunk) => chunk.endSequence <= sequence
    )
    for (const chunk of chunks) {
      await rm(
        join(this.outputDirectory(id), `${chunk.startSequence.toString().padStart(20, '0')}.json`)
      )
    }
    if (chunks.length > 0) await this.syncDirectory(this.outputDirectory(id))
  }

  private async privateDirectory(path: string): Promise<void> {
    if (process.platform === 'win32') {
      await this.initialize()
      await mkdir(path, { recursive: true, mode: 0o700 })
      return
    }
    await mkdir(path, { recursive: true, mode: 0o700 })
    await chmod(path, 0o700)
  }

  private async privateFile(path: string): Promise<void> {
    // ponytail: files inherit the verified root DACL; per-write ACL subprocesses would block output persistence.
    if (process.platform !== 'win32') await chmod(path, 0o600)
  }

  private async protectWindowsPath(path: string, recursive: boolean): Promise<void> {
    const sid = await this.currentWindowsUserSid()
    const child = Bun.spawn({
      cmd: [
        'powershell.exe',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `$ErrorActionPreference = 'Stop'
$path = $env:PTY_DAEMON_ACL_PATH
$user = [System.Security.Principal.SecurityIdentifier]::new($env:PTY_DAEMON_ACL_USER_SID)
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
function Set-PrivateDacl($item) {
  $isDirectory = $item.PSIsContainer
  $security = if ($isDirectory) {
    [System.Security.AccessControl.DirectorySecurity]::new()
  } else {
    [System.Security.AccessControl.FileSecurity]::new()
  }
  $inheritance = if ($isDirectory) {
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  } else {
    [System.Security.AccessControl.InheritanceFlags]::None
  }
  $security.SetAccessRuleProtection($true, $false)
  foreach ($identity in @($user, $system)) {
    [void]$security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identity, $fullControl, $inheritance, $none, $allow))
  }
  $item.SetAccessControl($security)
}
function Test-PrivateDacl($item) {
  $security = $item.GetAccessControl()
  $inheritance = if ($item.PSIsContainer) {
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  } else {
    [System.Security.AccessControl.InheritanceFlags]::None
  }
  $rules = @($security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if (-not $security.AreAccessRulesProtected -or $rules.Count -ne 2) { throw 'DACL was not replaced.' }
  foreach ($rule in $rules) {
    if (($rule.IdentityReference.Value -ne $user.Value -and $rule.IdentityReference.Value -ne $system.Value) -or $rule.AccessControlType -ne $allow -or $rule.FileSystemRights -ne $fullControl -or $rule.InheritanceFlags -ne $inheritance -or $rule.PropagationFlags -ne $none) { throw 'DACL contains an unexpected ACE.' }
  }
}
$items = @(Get-Item -LiteralPath $path -Force)
if (${recursive ? '$true' : '$false'}) { $items += @(Get-ChildItem -LiteralPath $path -Force -Recurse) }
foreach ($item in $items) { Set-PrivateDacl $item }
foreach ($item in $items) { Test-PrivateDacl $item }`,
      ],
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        ...process.env,
        PTY_DAEMON_ACL_PATH: path,
        PTY_DAEMON_ACL_USER_SID: sid,
      },
    })
    const exitCode = await child.exited
    if (exitCode === 0) return
    const error =
      `${await new Response(child.stdout).text()}${await new Response(child.stderr).text()}`.trim()
    throw new Error(
      `Unable to protect daemon storage with a Windows DACL${error ? `: ${error}` : '.'}`
    )
  }

  private async currentWindowsUserSid(): Promise<string> {
    this.windowsUserSid ??= (async () => {
      const process = Bun.spawn({
        cmd: [
          'powershell.exe',
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
        ],
        stdout: 'pipe',
        stderr: 'ignore',
      })
      const sid = (await new Response(process.stdout).text()).trim()
      if ((await process.exited) !== 0 || !/^S-\d+(?:-\d+)+$/.test(sid)) {
        throw new Error(
          'Unable to identify the current Windows user for daemon storage protection.'
        )
      }
      return sid
    })()
    try {
      return await this.windowsUserSid
    } catch (error) {
      this.windowsUserSid = undefined
      throw error
    }
  }
}
