import type { ReadResult, SearchResult, SpawnOptions, PTYSessionInfo } from './types.ts'
import {
  DAEMON_PROTOCOL_VERSION,
  type DaemonDescriptor,
  type ApprovalGrant,
  type ApprovalClaim,
  type ApprovalRequest,
  type ExecResult,
  type RpcResponse,
  type StopResult,
  type WaitCondition,
  type WaitResult,
  type WriteResult,
} from '../../daemon/types.ts'
import { DaemonStorage } from '../../daemon/storage.ts'
import { fileURLToPath } from 'node:url'
import { realpathSync } from 'node:fs'

const RPC_TIMEOUT_MS = 5000
const DAEMON_START_TIMEOUT_MS = 20_000
const STARTUP_STDERR_TAIL_CHARS = 4096

export function resolveDaemonLauncher(which: (command: string) => string | null): string {
  const launcher = which('bun')
  if (!launcher)
    throw new Error('PTY daemon requires the Bun executable, but Bun was not found on PATH.')
  return launcher
}

export function daemonLaunchCommand(
  which: (command: string) => string | null,
  entryPath: string,
  launchOptions: string
): string[] {
  return [resolveDaemonLauncher(which), entryPath, launchOptions]
}

export function daemonLaunchOptions(
  which: (command: string) => string | null,
  entryPath: string,
  launchOptions: string
) {
  return {
    cmd: daemonLaunchCommand(which, entryPath, launchOptions),
    detached: true,
    stdin: 'ignore' as const,
    stdout: 'ignore' as const,
    stderr: 'pipe' as const,
  }
}

export function daemonReadinessDeadline(startedAt: number): number {
  return startedAt + DAEMON_START_TIMEOUT_MS
}

function retainStartupStderrTail(tail: string, chunk: string): string {
  return `${tail}${chunk}`.slice(-STARTUP_STDERR_TAIL_CHARS)
}

async function captureStartupStderr(
  stream: ReadableStream<Uint8Array>,
  onTail: (tail: string) => void
): Promise<void> {
  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let tail = ''
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      tail = retainStartupStderrTail(tail, decoder.decode(value, { stream: true }))
      onTail(tail)
    }
    onTail(retainStartupStderrTail(tail, decoder.decode()))
  } finally {
    reader.releaseLock()
  }
}

export function safeStartupStderrTail(..._values: string[]): null {
  return null
}

function isSafeDescriptor(value: unknown): value is DaemonDescriptor {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const descriptor = value as Partial<DaemonDescriptor>
  const { pid, processIdentity, protocolVersion, token, endpoint } = descriptor
  if (
    typeof pid !== 'number' ||
    !Number.isSafeInteger(pid) ||
    pid < 1 ||
    typeof processIdentity !== 'string' ||
    !processIdentity ||
    typeof protocolVersion !== 'number' ||
    !Number.isSafeInteger(protocolVersion) ||
    protocolVersion < 1 ||
    typeof token !== 'string' ||
    !token ||
    token.length > 256 ||
    typeof endpoint !== 'string'
  ) {
    return false
  }
  try {
    const url = new URL(endpoint)
    return (
      url.protocol === 'http:' &&
      url.origin === endpoint &&
      Boolean(url.port) &&
      (url.hostname === '127.0.0.1' || url.hostname === '[::1]')
    )
  } catch {
    return false
  }
}

export class DaemonClient {
  private readonly storage = new DaemonStorage()
  private descriptor: DaemonDescriptor | null = null

  async spawn(options: SpawnOptions, owner?: OwnerContext): Promise<PTYSessionInfo> {
    return this.call('spawn', options, RPC_TIMEOUT_MS, owner)
  }

  async exec(
    options: SpawnOptions & { maxOutputBytes?: number },
    owner?: OwnerContext
  ): Promise<ExecResult> {
    return this.call('exec', options, requestTimeout(options.timeoutSeconds ?? 0), owner)
  }

  async wait(
    id: string,
    condition: WaitCondition,
    timeoutSeconds: number,
    owner?: OwnerContext
  ): Promise<WaitResult> {
    return this.call(
      'wait',
      { id, condition, timeoutSeconds },
      requestTimeout(timeoutSeconds),
      owner
    )
  }

  async sendWait(
    id: string,
    data: string,
    condition: WaitCondition,
    timeoutSeconds: number,
    owner: OwnerContext
  ): Promise<WaitResult> {
    return this.call(
      'sendWait',
      { id, data, condition, timeoutSeconds },
      requestTimeout(timeoutSeconds),
      owner
    )
  }

  async write(id: string, data: string, owner: OwnerContext): Promise<WriteResult> {
    return this.call('write', { id, data }, RPC_TIMEOUT_MS, owner)
  }

  async resize(
    id: string,
    cols: number,
    rows: number,
    owner: OwnerContext
  ): Promise<{ cols: number; rows: number }> {
    return this.call('resize', { id, cols, rows }, RPC_TIMEOUT_MS, owner)
  }

  async read(
    id: string,
    offset?: number,
    limit?: number,
    sequence?: number,
    owner?: OwnerContext
  ): Promise<ReadResult> {
    return this.call('read', { id, offset, limit, sequence }, RPC_TIMEOUT_MS, owner)
  }

  async search(
    id: string,
    pattern: string,
    ignoreCase = false,
    offset: number | undefined,
    limit: number | undefined,
    sequence: number | undefined,
    owner: OwnerContext
  ): Promise<SearchResult> {
    return this.call(
      'search',
      { id, pattern, ignoreCase, offset, limit, sequence },
      RPC_TIMEOUT_MS,
      owner
    )
  }

  async list(owner?: OwnerContext): Promise<PTYSessionInfo[]> {
    return this.call('list', {}, RPC_TIMEOUT_MS, owner)
  }

  async get(id: string, owner?: OwnerContext): Promise<PTYSessionInfo | null> {
    return this.call('get', { id }, RPC_TIMEOUT_MS, owner)
  }

  async getRawBuffer(
    id: string,
    owner?: OwnerContext
  ): Promise<{
    raw: string
    byteLength: number
    containment?: import('../../daemon/types.ts').ContainmentReport
    termination?: import('../../daemon/types.ts').TerminationResult
  } | null> {
    return this.call('rawOutput', { id }, RPC_TIMEOUT_MS, owner)
  }

  async getExecOutput(id: string, owner?: OwnerContext) {
    return this.call('execOutput', { id }, RPC_TIMEOUT_MS, owner)
  }

  async stop(id: string, owner?: OwnerContext): Promise<StopResult> {
    return this.call('stop', { id }, RPC_TIMEOUT_MS, owner)
  }

  async cleanup(id: string, owner?: OwnerContext): Promise<boolean> {
    return this.call('cleanup', { id }, RPC_TIMEOUT_MS, owner)
  }

  async cleanupBySession(owner?: OwnerContext): Promise<void> {
    await Promise.all([
      this.call(
        'cleanupByParentSession',
        { parentSessionId: owner?.parentSessionId },
        RPC_TIMEOUT_MS,
        owner
      ),
      this.call(
        'approvalCleanupByParentSession',
        { parentSessionId: owner?.parentSessionId },
        RPC_TIMEOUT_MS,
        owner,
        true
      ),
    ])
  }

  async createApproval(
    request: Omit<
      ApprovalRequest,
      | 'id'
      | 'parentSessionId'
      | 'projectDirectory'
      | 'status'
      | 'createdAt'
      | 'updatedAt'
      | 'expiresAt'
      | 'digest'
    > & {
      expirySeconds: number
    },
    owner: OwnerContext
  ): Promise<ApprovalRequest> {
    return this.call('approvalCreate', request, RPC_TIMEOUT_MS, owner, true)
  }

  async claimApproval(id: string, owner: OwnerContext): Promise<ApprovalRequest | ApprovalClaim> {
    return this.call('approvalClaim', { id }, RPC_TIMEOUT_MS, owner, true)
  }

  async decideApproval(
    id: string,
    decision: 'approve_once' | 'approve_session' | 'reject',
    claimToken: string,
    owner: OwnerContext
  ): Promise<ApprovalRequest> {
    return this.call('approvalDecide', { id, decision, claimToken }, RPC_TIMEOUT_MS, owner, true)
  }

  async waitForApproval(
    id: string,
    timeoutSeconds: number,
    owner: OwnerContext
  ): Promise<ApprovalRequest> {
    return this.call(
      'approvalWait',
      { id, timeoutSeconds },
      requestTimeout(timeoutSeconds),
      owner,
      true
    )
  }

  async consumeApproval(
    id: string,
    details: Pick<ApprovalRequest, 'command' | 'reason' | 'capability' | 'workdir'>,
    owner: OwnerContext
  ): Promise<ApprovalRequest> {
    return this.call('approvalConsume', { id, ...details }, RPC_TIMEOUT_MS, owner, true)
  }

  async listApprovalGrants(owner: OwnerContext): Promise<ApprovalGrant[]> {
    return this.call('approvalListGrants', {}, RPC_TIMEOUT_MS, owner, true)
  }

  async revokeApprovalGrant(id: string, owner: OwnerContext): Promise<boolean> {
    return this.call('approvalRevokeGrant', { id }, RPC_TIMEOUT_MS, owner, true)
  }

  async cancelApproval(id: string, owner: OwnerContext): Promise<ApprovalRequest> {
    return this.call('approvalCancel', { id }, RPC_TIMEOUT_MS, owner, true)
  }

  private async call<T>(
    operation: string,
    payload?: unknown,
    timeout = RPC_TIMEOUT_MS,
    owner?: OwnerContext,
    approval = false
  ): Promise<T> {
    const descriptor = await this.ensureDaemon()
    const response = await fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${descriptor.token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation,
        owner: owner && {
          ...owner,
          capability: this.capability(await this.storage.ownershipSecret(), owner),
        },
        approvalCapability:
          approval && owner
            ? this.approvalCapability(await this.storage.ownershipSecret(), owner)
            : undefined,
        payload,
      }),
      signal: AbortSignal.timeout(timeout),
    })
    const result = (await response.json()) as RpcResponse<T>
    if (!result.ok) throw new Error(result.error.message)
    return result.result
  }

  private async ensureDaemon(): Promise<DaemonDescriptor> {
    const deadline = daemonReadinessDeadline(Date.now())
    if (this.descriptor && isSafeDescriptor(this.descriptor)) {
      const state = await this.probe(this.descriptor, deadline)
      if (state === 'healthy') return this.descriptor
      if (state === 'incompatible') throw this.incompatibleProtocol(this.descriptor)
    }
    this.descriptor = null
    let startLock: { token: string; handoffToken: string } | null = null
    let started = false
    let startupStderr = ''
    let startupToken = ''
    let startupOptions = ''
    let startupExitCode: number | undefined
    let startupStderrDone: Promise<void> | undefined
    try {
      while (Date.now() < deadline) {
        let descriptor: unknown = null
        try {
          descriptor = await this.storage.readDescriptor()
        } catch {
          // Invalid descriptor data is only replaced by the lock owner.
        }
        if (isSafeDescriptor(descriptor)) {
          const state = await this.probe(descriptor, deadline)
          if (state === 'healthy') {
            this.descriptor = descriptor
            return descriptor
          }
          if (state === 'incompatible') throw this.incompatibleProtocol(descriptor)
          if (await this.storage.descriptorOwnerAlive(deadline)) {
            await Bun.sleep(25)
            continue
          }
        }
        if (!startLock) {
          startLock = await this.storage.acquireStartLock(deadline)
          if (startLock) continue
        }
        if (startLock && !started) {
          let lockedDescriptor: unknown = null
          try {
            lockedDescriptor = await this.storage.readDescriptor()
          } catch {
            // This lock owner may replace an unreadable descriptor.
          }
          if (isSafeDescriptor(lockedDescriptor)) {
            const state = await this.probe(lockedDescriptor, deadline)
            if (state === 'healthy') {
              this.descriptor = lockedDescriptor
              return lockedDescriptor
            }
            if (state === 'incompatible') throw this.incompatibleProtocol(lockedDescriptor)
          }
          const extension = import.meta.url.endsWith('.ts') ? 'ts' : 'js'
          const token = crypto.randomUUID()
          startupToken = token
          const launchOptions = Buffer.from(
            JSON.stringify({
              dataDirectory: this.storage.rootDirectory,
              token,
              startLockHandoffToken: startLock.handoffToken,
            })
          ).toString('base64url')
          startupOptions = launchOptions
          let child: ReturnType<typeof Bun.spawn>
          try {
            child = Bun.spawn({
              ...daemonLaunchOptions(
                Bun.which,
                fileURLToPath(new URL(`../../daemon/main.${extension}`, import.meta.url)),
                launchOptions
              ),
              env: process.env as Record<string, string>,
            })
          } catch {
            throw new Error('PTY daemon could not be launched.')
          }
          if (!(child.stderr instanceof ReadableStream)) {
            throw new Error('PTY daemon stderr could not be captured.')
          }
          startupStderrDone = captureStartupStderr(child.stderr, (tail) => {
            startupStderr = tail
          }).catch(() => undefined)
          void child.exited.then((exitCode) => {
            startupExitCode = exitCode
          })
          started = true
          continue
        }
        if (started && startupExitCode !== undefined) {
          await startupStderrDone
          const diagnostic = safeStartupStderrTail(startupStderr, startupToken, startupOptions)
          throw new Error(
            `PTY daemon exited before publishing its descriptor (exit code ${startupExitCode}).${diagnostic ? ` Startup stderr: ${diagnostic}` : ''}`
          )
        }
        await Bun.sleep(25)
      }
    } finally {
      if (startLock) await this.storage.releaseStartLock(startLock.token, deadline)
    }
    const diagnostic = safeStartupStderrTail(startupStderr, startupToken, startupOptions)
    throw new Error(
      `PTY daemon did not start within 20 seconds.${diagnostic ? ` Startup stderr: ${diagnostic}` : ''}`
    )
  }

  private async probe(
    descriptor: DaemonDescriptor,
    deadline?: number
  ): Promise<'healthy' | 'incompatible' | 'unreachable'> {
    try {
      const timeout = Math.min(
        250,
        deadline === undefined ? 250 : Math.max(0, deadline - Date.now())
      )
      if (timeout === 0) return 'unreachable'
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
      const result = (await response.json()) as RpcResponse<{
        protocolVersion: number
        pid: number
        processIdentity: string
      }>
      if (!result.ok) return result.error.code === 'protocol' ? 'incompatible' : 'unreachable'
      if (result.result.protocolVersion !== descriptor.protocolVersion) return 'incompatible'
      if (
        result.result.pid !== descriptor.pid ||
        result.result.processIdentity !== descriptor.processIdentity
      )
        return 'unreachable'
      return descriptor.protocolVersion === DAEMON_PROTOCOL_VERSION ? 'healthy' : 'incompatible'
    } catch {
      return 'unreachable'
    }
  }

  private incompatibleProtocol(descriptor: DaemonDescriptor): Error {
    return new Error(
      `PTY daemon protocol ${descriptor.protocolVersion} is incompatible with client protocol ${DAEMON_PROTOCOL_VERSION}.`
    )
  }

  private capability(secret: string, owner: Omit<OwnerContext, 'capability'>): string {
    return new Bun.CryptoHasher('sha256')
      .update(`${secret}\0${owner.parentSessionId}\0${owner.projectDirectory}`)
      .digest('hex')
  }

  private approvalCapability(secret: string, owner: Omit<OwnerContext, 'capability'>): string {
    return new Bun.CryptoHasher('sha256')
      .update(`approval\0${secret}\0${owner.parentSessionId}\0${owner.projectDirectory}`)
      .digest('hex')
  }
}

export interface OwnerContext {
  parentSessionId: string
  projectDirectory: string
  capability: string
}

export function ownerContext(parentSessionId: string, projectDirectory: string): OwnerContext {
  return {
    parentSessionId,
    projectDirectory: realpathSync(projectDirectory),
    capability: '',
  }
}

function requestTimeout(timeoutSeconds: number): number {
  return timeoutSeconds * 1000 + RPC_TIMEOUT_MS
}
