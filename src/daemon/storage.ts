import { chmod, mkdir, open, readFile, readdir, rename, rm, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import {
  OUTPUT_JOURNAL_VERSION,
  type DaemonDescriptor,
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

export function daemonDataDirectory(): string {
  if (process.env.PTY_DAEMON_DIR) return process.env.PTY_DAEMON_DIR
  const base = process.env.APPDATA ?? process.env.XDG_STATE_HOME ?? process.env.HOME
  if (!base) throw new Error('Unable to determine a per-user daemon data directory.')
  return join(base, 'opencode-pty')
}

export class DaemonStorage {
  private readonly outputTails = new Map<string, OutputChunk>()

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
          .map(
            async (entry) =>
              JSON.parse(await readFile(join(directory, entry), 'utf8')) as OutputChunk
          )
      )
      return chunks.sort((left, right) => left.startSequence - right.startSequence)
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
      return this.migrateSession(record)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      if (error instanceof InvalidSessionError) {
        await this.quarantineSession(id)
        return null
      }
      throw error
    }
  }

  private validSession(record: unknown, id: string): record is SessionRecord {
    return (
      Boolean(record) &&
      typeof record === 'object' &&
      (record as { id?: unknown }).id === id &&
      typeof (record as { title?: unknown }).title === 'string' &&
      typeof (record as { command?: unknown }).command === 'string' &&
      Array.isArray((record as { args?: unknown }).args) &&
      (record as { args: unknown[] }).args.every((arg) => typeof arg === 'string') &&
      [
        'starting',
        'running',
        'stopping',
        'exited',
        'timed_out',
        'lost',
        'spawn_failed',
        'output_limited',
      ].includes((record as { status?: unknown }).status as string) &&
      typeof (record as { workdir?: unknown }).workdir === 'string' &&
      typeof (record as { pid?: unknown }).pid === 'number' &&
      typeof (record as { createdAt?: unknown }).createdAt === 'string' &&
      typeof (record as { updatedAt?: unknown }).updatedAt === 'string' &&
      typeof (record as { parentSessionId?: unknown }).parentSessionId === 'string' &&
      typeof (record as { timedOut?: unknown }).timedOut === 'boolean'
    )
  }

  private async quarantineSession(id: string): Promise<void> {
    try {
      await rename(
        this.sessionDirectory(id),
        join(this.root, QUARANTINE_DIRECTORY, `${id}-${Date.now()}-${crypto.randomUUID()}`)
      )
      console.warn(`Skipped malformed PTY session ${JSON.stringify(id)}.`)
    } catch {
      console.warn(`Skipped malformed PTY session ${JSON.stringify(id)}; quarantine failed.`)
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
    if (record.outputJournalVersion === OUTPUT_JOURNAL_VERSION && record.outputTruncated) {
      await this.discardOutputBefore(record.id, record.firstRetainedSequence)
      chunks = await this.readOutputChunks(record.id)
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

  private async writeAtomic(path: string, contents: string): Promise<void> {
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
    await mkdir(path, { recursive: true, mode: 0o700 })
    if (process.platform !== 'win32') await chmod(path, 0o700)
  }

  private async privateFile(path: string): Promise<void> {
    if (process.platform !== 'win32') await chmod(path, 0o600)
  }
}
