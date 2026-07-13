import {
  appendFile,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
  chmod,
} from 'node:fs/promises'
import { join } from 'node:path'
import type { DaemonDescriptor, SessionRecord } from './types.ts'

const DESCRIPTOR_FILE = 'daemon.json'
const SESSIONS_DIRECTORY = 'sessions'
const METADATA_FILE = 'session.json'
const OUTPUT_FILE = 'output.log'
const START_LOCK_FILE = 'daemon-start.lock'
const STALE_START_LOCK_MS = 10000

export function daemonDataDirectory(): string {
  if (process.env.PTY_DAEMON_DIR) return process.env.PTY_DAEMON_DIR
  const base = process.env.APPDATA ?? process.env.XDG_STATE_HOME ?? process.env.HOME
  if (!base) throw new Error('Unable to determine a per-user daemon data directory.')
  return join(base, 'opencode-pty')
}

export class DaemonStorage {
  constructor(private readonly root: string = daemonDataDirectory()) {}

  get rootDirectory(): string {
    return this.root
  }

  get descriptorPath(): string {
    return join(this.root, DESCRIPTOR_FILE)
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

  private outputPath(id: string): string {
    return join(this.sessionDirectory(id), OUTPUT_FILE)
  }

  async initialize(): Promise<void> {
    await this.privateDirectory(this.root)
    await this.privateDirectory(join(this.root, SESSIONS_DIRECTORY))
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

  async appendOutput(id: string, data: string): Promise<void> {
    const path = this.outputPath(id)
    await appendFile(path, data, { encoding: 'utf8', mode: 0o600 })
    await this.privateFile(path)
  }

  async replaceOutput(id: string, data: string): Promise<void> {
    const path = this.outputPath(id)
    await writeFile(path, data, { encoding: 'utf8', mode: 0o600 })
    await this.privateFile(path)
  }

  async readOutput(id: string): Promise<string> {
    try {
      return await readFile(this.outputPath(id), 'utf8')
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return ''
      throw error
    }
  }

  async deleteSession(id: string): Promise<void> {
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
      return JSON.parse(await readFile(this.metadataPath(id), 'utf8')) as SessionRecord
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw error
    }
  }

  private async writeAtomic(path: string, contents: string): Promise<void> {
    const temporaryPath = `${path}.${crypto.randomUUID()}.tmp`
    await writeFile(temporaryPath, contents, { encoding: 'utf8', mode: 0o600 })
    await rename(temporaryPath, path)
    await this.privateFile(path)
  }

  private async privateDirectory(path: string): Promise<void> {
    await mkdir(path, { recursive: true, mode: 0o700 })
    if (process.platform !== 'win32') await chmod(path, 0o700)
  }

  private async privateFile(path: string): Promise<void> {
    if (process.platform !== 'win32') await chmod(path, 0o600)
  }
}
