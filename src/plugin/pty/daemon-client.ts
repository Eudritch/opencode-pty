import type { ReadResult, SearchResult, SpawnOptions, PTYSessionInfo } from './types.ts'
import {
  DAEMON_PROTOCOL_VERSION,
  type DaemonDescriptor,
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

const START_TIMEOUT_MS = 5000
const STARTUP_STDERR_TAIL_CHARS = 4096
const UNSAFE_STARTUP_STDERR =
  /\b(?:token|secret|password|passwd|api[_-]?key|authorization|bearer)\b|(?:^|\s)[A-Za-z_][A-Za-z0-9_]*=/i

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

export function daemonReadinessDeadline(startedAt: number): number {
  return startedAt + START_TIMEOUT_MS
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

function safeStartupStderrTail(
  stderr: string,
  launchToken: string,
  launchOptions: string
): string | null {
  const tail = stderr.trim()
  if (
    !tail ||
    UNSAFE_STARTUP_STDERR.test(tail) ||
    tail.includes(launchToken) ||
    tail.includes(launchOptions) ||
    Object.values(process.env).some((value) => value && value.length > 3 && tail.includes(value))
  ) {
    return null
  }
  return tail
}

function isSafeDescriptor(value: unknown): value is DaemonDescriptor {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const descriptor = value as Partial<DaemonDescriptor>
  const { pid, protocolVersion, token, endpoint } = descriptor
  if (
    typeof pid !== 'number' ||
    !Number.isSafeInteger(pid) ||
    pid < 1 ||
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
    return this.call('spawn', options, START_TIMEOUT_MS, owner)
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
    return this.call('write', { id, data }, START_TIMEOUT_MS, owner)
  }

  async resize(
    id: string,
    cols: number,
    rows: number,
    owner: OwnerContext
  ): Promise<{ cols: number; rows: number }> {
    return this.call('resize', { id, cols, rows }, START_TIMEOUT_MS, owner)
  }

  async read(
    id: string,
    offset?: number,
    limit?: number,
    sequence?: number,
    owner?: OwnerContext
  ): Promise<ReadResult> {
    return this.call('read', { id, offset, limit, sequence }, START_TIMEOUT_MS, owner)
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
      START_TIMEOUT_MS,
      owner
    )
  }

  async list(owner?: OwnerContext): Promise<PTYSessionInfo[]> {
    return this.call('list', {}, START_TIMEOUT_MS, owner)
  }

  async get(id: string, owner?: OwnerContext): Promise<PTYSessionInfo | null> {
    return this.call('get', { id }, START_TIMEOUT_MS, owner)
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
    return this.call('rawOutput', { id }, START_TIMEOUT_MS, owner)
  }

  async getExecOutput(id: string, owner?: OwnerContext) {
    return this.call('execOutput', { id }, START_TIMEOUT_MS, owner)
  }

  async stop(id: string, owner?: OwnerContext): Promise<StopResult> {
    return this.call('stop', { id }, START_TIMEOUT_MS, owner)
  }

  async cleanup(id: string, owner?: OwnerContext): Promise<boolean> {
    return this.call('cleanup', { id }, START_TIMEOUT_MS, owner)
  }

  async cleanupBySession(owner?: OwnerContext): Promise<void> {
    await this.call(
      'cleanupByParentSession',
      { parentSessionId: owner?.parentSessionId },
      START_TIMEOUT_MS,
      owner
    )
  }

  private async call<T>(
    operation: string,
    payload?: unknown,
    timeout = START_TIMEOUT_MS,
    owner?: OwnerContext
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
        payload,
      }),
      signal: AbortSignal.timeout(timeout),
    })
    const result = (await response.json()) as RpcResponse<T>
    if (!result.ok) throw new Error(result.error.message)
    return result.result
  }

  private async ensureDaemon(): Promise<DaemonDescriptor> {
    if (this.descriptor && isSafeDescriptor(this.descriptor)) {
      const state = await this.probe(this.descriptor)
      if (state === 'healthy') return this.descriptor
      if (state === 'incompatible') throw this.incompatibleProtocol(this.descriptor)
    }
    this.descriptor = null
    let deadline: number | undefined
    let ownsStartLock = false
    let started = false
    let startupStderr = ''
    let startupToken = ''
    let startupOptions = ''
    try {
      while (deadline === undefined || Date.now() < deadline) {
        let descriptor: unknown = null
        try {
          descriptor = await this.storage.readDescriptor()
        } catch {
          // Invalid descriptor data is only replaced by the lock owner.
        }
        if (isSafeDescriptor(descriptor)) {
          const state = await this.probe(descriptor)
          if (state === 'healthy') {
            this.descriptor = descriptor
            return descriptor
          }
          if (state === 'incompatible') throw this.incompatibleProtocol(descriptor)
        }
        if (!ownsStartLock && (await this.storage.acquireStartLock())) {
          ownsStartLock = true
          continue
        }
        if (ownsStartLock && !started) {
          let lockedDescriptor: unknown = null
          try {
            lockedDescriptor = await this.storage.readDescriptor()
          } catch {
            // This lock owner may replace an unreadable descriptor.
          }
          if (isSafeDescriptor(lockedDescriptor)) {
            const state = await this.probe(lockedDescriptor)
            if (state === 'healthy') {
              this.descriptor = lockedDescriptor
              return lockedDescriptor
            }
            if (state === 'incompatible') throw this.incompatibleProtocol(lockedDescriptor)
          }
          await this.storage.removeDescriptor()
          const extension = import.meta.url.endsWith('.ts') ? 'ts' : 'js'
          const token = crypto.randomUUID()
          startupToken = token
          const launchOptions = Buffer.from(
            JSON.stringify({
              dataDirectory: this.storage.rootDirectory,
              token,
            })
          ).toString('base64url')
          startupOptions = launchOptions
          let child: ReturnType<typeof Bun.spawn>
          try {
            child = Bun.spawn({
              cmd: daemonLaunchCommand(
                Bun.which,
                fileURLToPath(new URL(`../../daemon/main.${extension}`, import.meta.url)),
                launchOptions
              ),
              stdin: 'ignore',
              stdout: 'ignore',
              stderr: 'pipe',
              env: process.env as Record<string, string>,
            })
          } catch {
            throw new Error('PTY daemon could not be launched.')
          }
          if (!(child.stderr instanceof ReadableStream)) {
            throw new Error('PTY daemon stderr could not be captured.')
          }
          void captureStartupStderr(child.stderr, (tail) => {
            startupStderr = tail
          }).catch(() => undefined)
          started = true
          deadline = daemonReadinessDeadline(Date.now())
          continue
        }
        await Bun.sleep(25)
      }
    } finally {
      if (ownsStartLock) await this.storage.releaseStartLock()
    }
    const diagnostic = safeStartupStderrTail(startupStderr, startupToken, startupOptions)
    throw new Error(
      `PTY daemon did not start within 5 seconds.${diagnostic ? ` Startup stderr: ${diagnostic}` : ''}`
    )
  }

  private async probe(
    descriptor: DaemonDescriptor
  ): Promise<'healthy' | 'incompatible' | 'unreachable'> {
    try {
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
        signal: AbortSignal.timeout(250),
      })
      const result = (await response.json()) as RpcResponse<{ protocolVersion: number }>
      if (!result.ok) return result.error.code === 'protocol' ? 'incompatible' : 'unreachable'
      if (result.result.protocolVersion !== descriptor.protocolVersion) return 'incompatible'
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
  return timeoutSeconds * 1000 + START_TIMEOUT_MS
}
