import { chmod, link, mkdir, open, readdir, readFile, rename, rm, unlink } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import {
  type DaemonDescriptor,
  type ApprovalLedger,
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
const START_LOCK_RECOVERY_FILE = 'daemon-start-recovery.lock'
const QUARANTINE_DIRECTORY = 'quarantine'
const APPROVALS_FILE = 'approvals.json'
const OUTPUT_SEGMENT_BYTES = 64 * 1024
const WINDOWS_PROBE_TIMEOUT_MS = 5000
const WINDOWS_RENAME_RETRIES = 3
const WINDOWS_RENAME_RETRY_MS = 10

class InvalidSessionError extends Error {}
class InvalidJournalError extends InvalidSessionError {}

interface StartLock {
  token: string
  handoffToken: string | null
  pid: number
  processIdentity: string | null
}

interface StartLockLease {
  token: string
  handoffToken: string
}

export async function processStartIdentity(
  pid: number,
  deadline = Date.now() + 5000
): Promise<string | null> {
  if (!Number.isSafeInteger(pid) || pid < 1) return null
  if (Date.now() >= deadline) return null
  if (process.platform !== 'win32' && process.platform !== 'darwin') {
    try {
      const stat = await readFile(`/proc/${pid}/stat`, 'utf8')
      const fields = stat
        .slice(stat.lastIndexOf(')') + 1)
        .trim()
        .split(/\s+/)
      return fields[19] ? `posix:${pid}:${fields[19]}` : null
    } catch {
      return null
    }
  }
  if (process.platform === 'win32') {
    const command = windowsProcessIdentityCommand(pid)
    if (!command) return null
    return parseWindowsProcessIdentity(pid, await processIdentityProbe(command, deadline))
  }
  const output = (
    await processIdentityProbe(['ps', '-p', String(pid), '-o', 'lstart='], deadline)
  )?.trim()
  return output ? `darwin:${pid}:${output}` : null
}

export function parseWindowsProcessIdentity(pid: number, output: string | null): string | null {
  if (!output) return null
  const identity = output.trim()
  const match = /^windows:(\d+):([1-9]\d*)$/.exec(identity)
  const observedPid = match?.[1]
  const creationTime = match?.[2]
  return observedPid && creationTime && Number(observedPid) === pid ? identity : null
}

export function windowsProcessIdentityCommand(pid: number, systemRoot?: string): string[] | null {
  const root =
    systemRoot === undefined ? (process.env.SystemRoot ?? process.env.WINDIR) : systemRoot
  if (!root) return null
  return [
    resolve(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    `$process = Get-Process -Id ${pid} -ErrorAction SilentlyContinue; if ($process) { [Console]::Write("windows:${pid}:$($process.StartTime.ToFileTimeUtc())") }`,
  ]
}

export async function processIdentityProbe(
  command: string[],
  deadline: number
): Promise<string | null> {
  if (Date.now() >= deadline) return null
  try {
    const child = Bun.spawn({ cmd: command, stdout: 'pipe', stderr: 'ignore' })
    const output = new Response(child.stdout).text()
    let timeout: ReturnType<typeof setTimeout> | undefined
    try {
      const completed = await Promise.race([
        child.exited.then((exitCode) => ({ exitCode })),
        new Promise<{ timedOut: true }>((resolve) => {
          timeout = setTimeout(resolve, Math.max(0, deadline - Date.now()), { timedOut: true })
        }),
      ])
      if ('timedOut' in completed) {
        child.kill(9)
        await child.exited.catch(() => undefined)
        return null
      }
      return completed.exitCode === 0 ? await output : null
    } finally {
      if (timeout) clearTimeout(timeout)
    }
  } catch {
    return null
  }
}

export async function renameWithWindowsRetry(
  source: string,
  destination: string,
  renameFile: typeof rename = rename,
  windows = process.platform === 'win32'
): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await renameFile(source, destination)
      return
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (!windows || !['EPERM', 'EBUSY'].includes(code ?? '') || attempt >= WINDOWS_RENAME_RETRIES)
        throw error
      await Bun.sleep(WINDOWS_RENAME_RETRY_MS)
    }
  }
}

export async function requiredProcessStartIdentity(
  pid: number,
  deadline?: number
): Promise<string> {
  const identity = await processStartIdentity(pid, deadline)
  if (identity) return identity
  const probe =
    process.platform === 'win32'
      ? 'Windows process creation-time probe'
      : 'process start-time probe'
  throw new Error(`Unable to verify daemon process identity: ${probe} failed.`)
}

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
  private static readonly initializingRoots = new Map<string, Promise<void>>()
  private static readonly currentProcessIdentities = new Map<
    string,
    { pid: number; identity: string }
  >()
  private readonly outputTails = new Map<string, OutputChunk>()
  private readonly writes = new Map<string, Promise<void>>()
  private windowsUserSid: Promise<string> | undefined
  private windowsRootProtected = false
  private currentProcessIdentity: string | undefined

  constructor(private readonly root: string = resolve(daemonDataDirectory())) {}

  get rootDirectory(): string {
    return this.root
  }

  get descriptorPath(): string {
    return join(this.root, DESCRIPTOR_FILE)
  }

  private get ownershipSecretPath(): string {
    return join(this.root, OWNERSHIP_SECRET_FILE)
  }

  private get approvalsPath(): string {
    return join(this.root, APPROVALS_FILE)
  }

  private get startLockPath(): string {
    return join(this.root, START_LOCK_FILE)
  }

  private get startLockRecoveryPath(): string {
    return join(this.root, START_LOCK_RECOVERY_FILE)
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
    if (this.windowsRootProtected) return
    let initializing = DaemonStorage.initializingRoots.get(this.root)
    if (!initializing) {
      initializing = this.initializeRoot()
      DaemonStorage.initializingRoots.set(this.root, initializing)
    }
    try {
      await initializing
      this.windowsRootProtected = true
    } catch (error) {
      if (DaemonStorage.initializingRoots.get(this.root) === initializing)
        DaemonStorage.initializingRoots.delete(this.root)
      throw error
    }
  }

  private async initializeRoot(): Promise<void> {
    if (process.platform === 'win32') {
      await mkdir(this.root, { recursive: true, mode: 0o700 })
      await this.protectWindowsPath(this.root, true)
      await Promise.all([
        mkdir(join(this.root, SESSIONS_DIRECTORY), { recursive: true, mode: 0o700 }),
        mkdir(join(this.root, QUARANTINE_DIRECTORY), { recursive: true, mode: 0o700 }),
      ])
      return
    }
    for (const path of [
      this.root,
      join(this.root, SESSIONS_DIRECTORY),
      join(this.root, QUARANTINE_DIRECTORY),
    ]) {
      await mkdir(path, { recursive: true, mode: 0o700 })
      await chmod(path, 0o700)
    }
  }

  async requiredCurrentProcessStartIdentity(deadline?: number): Promise<string> {
    const cached =
      this.currentProcessIdentity ??
      (DaemonStorage.currentProcessIdentities.get(this.root)?.pid === process.pid
        ? DaemonStorage.currentProcessIdentities.get(this.root)?.identity
        : undefined)
    if (cached) return cached
    const identity = await processStartIdentity(process.pid, deadline)
    if (identity) {
      this.currentProcessIdentity = identity
      DaemonStorage.currentProcessIdentities.set(this.root, { pid: process.pid, identity })
      return identity
    }
    const probe =
      process.platform === 'win32'
        ? 'Windows process creation-time probe'
        : 'process start-time probe'
    throw new Error(`Unable to verify daemon process identity: ${probe} failed.`)
  }

  async readDescriptor(): Promise<DaemonDescriptor | null> {
    try {
      return JSON.parse(await readFile(this.descriptorPath, 'utf8')) as DaemonDescriptor
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      return null
    }
  }

  async writeDescriptor(descriptor: DaemonDescriptor): Promise<void> {
    await this.writeAtomic(this.descriptorPath, JSON.stringify(descriptor))
  }

  async removeDescriptor(token: string, processIdentity: string): Promise<void> {
    const startLock = await this.acquireStartLock()
    if (!startLock) return
    try {
      const descriptor = await this.readDescriptor()
      if (descriptor?.token === token && descriptor.processIdentity === processIdentity)
        await rm(this.descriptorPath, { force: true })
    } finally {
      await this.releaseStartLock(startLock.token)
    }
  }

  async descriptorOwnerAlive(deadline?: number): Promise<boolean> {
    const descriptor = await this.readDescriptor()
    if (!descriptor || !this.validDescriptor(descriptor)) return false
    const identity = await processStartIdentity(descriptor.pid, deadline)
    return identity
      ? identity === descriptor.processIdentity
      : this.processExists(descriptor.pid) ||
          this.authenticatedDescriptorHealthy(descriptor, deadline)
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

  async readApprovals(): Promise<ApprovalLedger> {
    await this.initialize()
    try {
      const ledger = JSON.parse(await readFile(this.approvalsPath, 'utf8')) as ApprovalLedger
      if (
        !ledger ||
        !Array.isArray(ledger.requests) ||
        !Array.isArray(ledger.grants) ||
        ![...ledger.requests, ...ledger.grants].every(
          (entry) =>
            entry &&
            typeof entry === 'object' &&
            [
              'id',
              'parentSessionId',
              'projectDirectory',
              'digest',
              'capability',
              'workdir',
              'createdAt',
            ].every((key) => validText((entry as unknown as Record<string, unknown>)[key]))
        ) ||
        !ledger.requests.every(
          (entry) =>
            (entry.reason === undefined || validText(entry.reason)) &&
            validText(entry.command) &&
            validText(entry.updatedAt) &&
            validText(entry.expiresAt) &&
            [
              'pending',
              'claimed',
              'native_fallback',
              'approved_once',
              'approved_session',
              'rejected',
              'cancelled',
              'expired',
              'consumed',
            ].includes(entry.status) &&
            (entry.claimExpiresAt === undefined || validTimestamp(entry.claimExpiresAt))
        ) ||
        !ledger.grants.every((entry) => validTimestamp(entry.expiresAt))
      ) {
        throw new Error('Approval ledger is invalid.')
      }
      return ledger
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { requests: [], grants: [] }
      throw error
    }
  }

  async writeApprovals(ledger: ApprovalLedger): Promise<void> {
    await this.writeAtomic(this.approvalsPath, JSON.stringify(ledger))
  }

  async acquireStartLock(deadline?: number): Promise<StartLockLease | null> {
    await this.initialize()
    const lock = await this.newStartLock(deadline)
    if (await this.writeExclusiveLock(this.startLockPath, lock)) {
      return { token: lock.token, handoffToken: lock.handoffToken }
    }
    const current = await this.readStartLock()
    if (current && (await this.startLockOwnerAlive(current, deadline))) return null
    if (!(await this.acquireStartLockRecovery(deadline))) return null
    try {
      const replacement = await this.readStartLock()
      if (replacement && (await this.startLockOwnerAlive(replacement, deadline))) return null
      await rm(this.startLockPath, { force: true })
      await this.syncDirectory(this.root)
      const recoveredLock = await this.newStartLock(deadline)
      if (await this.writeExclusiveLock(this.startLockPath, recoveredLock))
        return { token: recoveredLock.token, handoffToken: recoveredLock.handoffToken }
      return null
    } finally {
      await rm(this.startLockRecoveryPath, { force: true })
    }
  }

  private async newStartLock(deadline?: number): Promise<StartLock & { handoffToken: string }> {
    const processIdentity = await this.requiredCurrentProcessStartIdentity(deadline)
    return {
      token: crypto.randomUUID(),
      handoffToken: crypto.randomUUID(),
      pid: process.pid,
      processIdentity,
    }
  }

  async claimStartLock(handoffToken: string, deadline?: number): Promise<string | null> {
    if (!(await this.acquireStartLockRecovery(deadline))) return null
    try {
      const lock = await this.readStartLock()
      if (!lock || lock.handoffToken !== handoffToken) return null
      const processIdentity = await this.requiredCurrentProcessStartIdentity(deadline).catch(
        () => null
      )
      if (!processIdentity) return null
      const token = crypto.randomUUID()
      await this.writeStartLock({
        token,
        handoffToken: null,
        pid: process.pid,
        processIdentity,
      })
      return token
    } finally {
      await rm(this.startLockRecoveryPath, { force: true })
    }
  }

  async releaseStartLock(token: string, deadline?: number): Promise<void> {
    const lock = await this.readStartLock()
    const processIdentity = await this.requiredCurrentProcessStartIdentity(deadline).catch(
      () => null
    )
    if (
      lock?.token === token &&
      lock.pid === process.pid &&
      processIdentity !== null &&
      (lock.processIdentity === null || lock.processIdentity === processIdentity)
    ) {
      await rm(this.startLockPath, { force: true })
      await this.syncDirectory(this.root)
    }
  }

  private async readStartLock(path = this.startLockPath): Promise<StartLock | null> {
    try {
      const value = JSON.parse(await readFile(path, 'utf8')) as Partial<StartLock>
      const { token, handoffToken, pid, processIdentity } = value
      return typeof token === 'string' &&
        token &&
        (handoffToken === null || (typeof handoffToken === 'string' && handoffToken)) &&
        typeof pid === 'number' &&
        Number.isSafeInteger(pid) &&
        pid > 0 &&
        (processIdentity === null || (typeof processIdentity === 'string' && processIdentity))
        ? (value as StartLock)
        : null
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      if (error instanceof SyntaxError) return null
      throw error
    }
  }

  private async writeStartLock(lock: StartLock): Promise<void> {
    await this.writeAtomic(this.startLockPath, JSON.stringify(lock))
  }

  private async acquireStartLockRecovery(deadline?: number): Promise<boolean> {
    const lock: StartLock = {
      token: crypto.randomUUID(),
      handoffToken: null,
      pid: process.pid,
      processIdentity: await this.requiredCurrentProcessStartIdentity(deadline),
    }
    if (await this.writeExclusiveLock(this.startLockRecoveryPath, lock)) {
      return true
    }
    const recovery = await this.readStartLock(this.startLockRecoveryPath)
    if (recovery && (await this.startLockOwnerAlive(recovery, deadline))) return false
    const quarantine = join(this.root, `.${START_LOCK_RECOVERY_FILE}.${crypto.randomUUID()}`)
    try {
      await rename(this.startLockRecoveryPath, quarantine)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT')
        return this.acquireStartLockRecovery(deadline)
      throw error
    }
    const quarantined = await this.readStartLock(quarantine)
    if (!recovery || quarantined?.token !== recovery.token) {
      try {
        await link(quarantine, this.startLockRecoveryPath)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
      await rm(quarantine, { force: true })
      return false
    }
    await rm(quarantine, { force: true })
    return this.acquireStartLockRecovery(deadline)
  }

  private async writeExclusiveLock(path: string, lock: StartLock): Promise<boolean> {
    const temporary = join(this.root, `.${START_LOCK_FILE}.${crypto.randomUUID()}`)
    const handle = await open(temporary, 'wx', 0o600)
    try {
      await handle.writeFile(JSON.stringify(lock), 'utf8')
      await handle.sync()
    } finally {
      await handle.close()
    }
    try {
      await this.privateFile(temporary)
      await link(temporary, path)
      await this.syncDirectory(this.root)
      return true
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false
      throw error
    } finally {
      await unlink(temporary).catch(() => undefined)
    }
  }

  private async startLockOwnerAlive(lock: StartLock, deadline?: number): Promise<boolean> {
    if (!lock.processIdentity) return false
    const identity = await processStartIdentity(lock.pid, deadline)
    return identity === lock.processIdentity
  }

  private processExists(pid: number): boolean {
    try {
      process.kill(pid, 0)
      return true
    } catch (error) {
      return (error as NodeJS.ErrnoException).code !== 'ESRCH'
    }
  }
  private validDescriptor(value: DaemonDescriptor): boolean {
    return (
      Number.isSafeInteger(value.pid) &&
      value.pid > 0 &&
      typeof value.processIdentity === 'string' &&
      Boolean(value.processIdentity) &&
      typeof value.endpoint === 'string' &&
      typeof value.token === 'string' &&
      Boolean(value.token)
    )
  }

  private async authenticatedDescriptorHealthy(
    descriptor: DaemonDescriptor,
    deadline?: number
  ): Promise<boolean> {
    try {
      const timeout = Math.min(
        250,
        deadline === undefined ? 250 : Math.max(0, deadline - Date.now())
      )
      if (timeout === 0) return false
      const response = await fetch(`${descriptor.endpoint}/rpc`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${descriptor.token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          id: crypto.randomUUID(),
          version: descriptor.protocolVersion,
          operation: 'health',
        }),
        signal: AbortSignal.timeout(timeout),
      })
      const result = (await response.json()) as {
        ok?: boolean
        result?: { pid?: unknown; processIdentity?: unknown }
      }
      return (
        result.ok === true &&
        result.result?.pid === descriptor.pid &&
        result.result.processIdentity === descriptor.processIdentity
      )
    } catch {
      return false
    }
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
        validNonnegativeInteger(value.protocolVersion) &&
        value.protocolVersion >= 1 &&
        value.protocolVersion <= 5 &&
        (value.tokenFingerprint === undefined || validText(value.tokenFingerprint))
      )
    }
    const validContainment = (containment: unknown): boolean => {
      if (containment === undefined) return true
      if (!containment || typeof containment !== 'object') return false
      const value = containment as Record<string, unknown>
      return (
        ['linux_proc', 'windows_job', 'posix_verification_unavailable', 'not_applicable'].includes(
          String(value.platform)
        ) &&
        [
          'posix_best_effort_empty',
          'posix_processes_remaining',
          'posix_escape_observed',
          'posix_containment_unknown',
          'windows_job_empty',
          'windows_job_processes_remaining',
          'windows_job_unknown',
          'not_applicable',
        ].includes(String(value.status)) &&
        validNonnegativeInteger(value.rootPid) &&
        (value.processGroupId === null || validOptionalInteger(value.processGroupId)) &&
        (value.sessionId === null || validOptionalInteger(value.sessionId)) &&
        validText(value.rootStartIdentity) &&
        (value.rootIdentityVerified === undefined ||
          typeof value.rootIdentityVerified === 'boolean') &&
        [
          value.observedGroupPids,
          value.observedSessionPids,
          value.observedEscapedDescendantPids,
        ].every((pids) => Array.isArray(pids) && pids.every(validNonnegativeInteger)) &&
        (value.observedEscapedDescendants === undefined ||
          (Array.isArray(value.observedEscapedDescendants) &&
            value.observedEscapedDescendants.every(
              (descendant) =>
                descendant &&
                typeof descendant === 'object' &&
                validNonnegativeInteger((descendant as Record<string, unknown>).pid) &&
                validText((descendant as Record<string, unknown>).startIdentity)
            ))) &&
        validTimestamp(value.verifiedAt)
      )
    }
    const validTermination = (termination: unknown): boolean => {
      if (termination === undefined || termination === null) return true
      if (!termination || typeof termination !== 'object') return false
      const value = termination as Record<string, unknown>
      return (
        typeof value.requested === 'boolean' &&
        typeof value.termSignalSent === 'boolean' &&
        typeof value.killSignalSent === 'boolean' &&
        typeof value.rootExited === 'boolean' &&
        (value.directChildExited === undefined || typeof value.directChildExited === 'boolean') &&
        validContainment(value.containment)
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
      (value.pendingCleanup !== undefined && typeof value.pendingCleanup !== 'boolean') ||
      (value.directChildExited !== undefined && typeof value.directChildExited !== 'boolean') ||
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
      !validContainment(value.containment) ||
      !validTermination(value.termination) ||
      !validOptionalText(value.storageFailure) ||
      (value.diagnostics !== undefined &&
        (!Array.isArray(value.diagnostics) ||
          value.diagnostics.length > 4 ||
          !value.diagnostics.every(
            (diagnostic) => validText(diagnostic) && [...diagnostic].length <= 512
          ))) ||
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
    try {
      const handle = await open(temporaryPath, 'w', 0o600)
      try {
        await handle.writeFile(contents, 'utf8')
        await handle.sync()
      } finally {
        await handle.close()
      }
      await renameWithWindowsRetry(temporaryPath, path)
      await this.privateFile(path)
      await this.syncDirectory(dirname(path))
    } finally {
      await rm(temporaryPath, { force: true }).catch(() => undefined)
    }
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
    const command = windowsProcessIdentityCommand(process.pid)
    if (!command)
      throw new Error('Unable to locate Windows PowerShell for daemon storage protection.')
    const [powershell] = command
    if (!powershell)
      throw new Error('Unable to locate Windows PowerShell for daemon storage protection.')
    const child = Bun.spawn({
      cmd: [
        powershell,
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
    const exitCode = await this.waitForWindowsPowerShell(
      child,
      Date.now() + WINDOWS_PROBE_TIMEOUT_MS
    )
    if (exitCode === 0) return
    const error =
      exitCode === null
        ? 'Windows PowerShell DACL probe timed out.'
        : `${await new Response(child.stdout).text()}${await new Response(child.stderr).text()}`.trim()
    throw new Error(
      `Unable to protect daemon storage with a Windows DACL${error ? `: ${error}` : '.'}`
    )
  }

  private async currentWindowsUserSid(): Promise<string> {
    this.windowsUserSid ??= (async () => {
      const command = windowsProcessIdentityCommand(globalThis.process.pid)
      if (!command)
        throw new Error('Unable to locate Windows PowerShell for daemon storage protection.')
      const [powershell] = command
      if (!powershell)
        throw new Error('Unable to locate Windows PowerShell for daemon storage protection.')
      const process = Bun.spawn({
        cmd: [
          powershell,
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
        ],
        stdout: 'pipe',
        stderr: 'ignore',
      })
      const output = new Response(process.stdout).text()
      if (
        (await this.waitForWindowsPowerShell(process, Date.now() + WINDOWS_PROBE_TIMEOUT_MS)) !==
          0 ||
        !/^S-\d+(?:-\d+)+$/.test((await output).trim())
      ) {
        throw new Error(
          'Unable to identify the current Windows user for daemon storage protection.'
        )
      }
      return (await output).trim()
    })()
    try {
      return await this.windowsUserSid
    } catch (error) {
      this.windowsUserSid = undefined
      throw error
    }
  }

  private async waitForWindowsPowerShell(
    child: ReturnType<typeof Bun.spawn>,
    deadline: number
  ): Promise<number | null> {
    let timeout: ReturnType<typeof setTimeout> | undefined
    try {
      const result = await Promise.race([
        child.exited.then((exitCode) => ({ exitCode })),
        new Promise<{ timedOut: true }>((resolve) => {
          timeout = setTimeout(resolve, Math.max(0, deadline - Date.now()), { timedOut: true })
        }),
      ])
      if ('timedOut' in result) {
        child.kill(9)
        await child.exited.catch(() => undefined)
        return null
      }
      return result.exitCode
    } finally {
      if (timeout) clearTimeout(timeout)
    }
  }
}
