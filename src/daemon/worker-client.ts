import { access, readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import {
  NATIVE_WORKER_PROTOCOL_VERSION,
  nativeWorkerPackageName,
  nativeWorkerTarget,
} from '../shared/native-worker-targets.ts'
import { processStartIdentity } from './storage.ts'
import type {
  ContainmentReport,
  SpawnCleanup,
  TerminationResult,
  WorkerPrestartAuthority,
} from './types.ts'

function readyTimeout(value: string | undefined): number {
  const timeout = Number(value ?? 5000)
  return Number.isFinite(timeout) && timeout > 0 ? timeout : 5000
}

const MAX_READY_FRAME_BYTES = 1024 * 1024
const ORPHAN_SHUTDOWN_TIMEOUT_MS = 2000
const TOKEN_FINGERPRINT = /^[a-f0-9]{64}$/
// Daemon-controlled fault/readiness injection knobs; they are stripped from session environments
// and honored only from the daemon's own process environment.
const NATIVE_WORKER_KNOB = /^OPENCODE_PTY_NATIVE_WORKER_/

export interface WorkerDescriptor {
  pid: number
  startIdentity: string
  processIdentity: string
  endpoint: string
  token: string
  protocolVersion: number
}

export interface WorkerReference {
  pid: number
  startIdentity: string
  processIdentity: string
  endpoint: string
  tokenFingerprint?: string
  protocolVersion: number
  executable?: string
}

export interface PreparedWorker {
  client: WorkerClient
  reference: WorkerReference
}

export interface WorkerBootstrap {
  command: string
  args: string[]
  workdir: string
  env: Record<string, string>
  redactionSecrets: string[]
  sessionDirectory: string
  workerControlToken: string
  workerId: string
  // PTYs deliberately have no worker deadline unless the caller supplied one.
  timeoutSeconds?: number
  maxOutputBytes: number
  mode: 'exec' | 'pty'
  cols?: number
  rows?: number
  fault?: string
}

export class WorkerStartError extends Error {
  constructor(
    message: string,
    readonly cleanup: SpawnCleanup,
    // Present only after the ready descriptor was authenticated but before any start frame.
    readonly prestartReference?: WorkerReference,
    // Set only for a handled failure before Bun.spawn could create a worker process.
    readonly noWorkerSpawned = false
  ) {
    super(message)
  }
}

function validDescriptor(value: unknown): value is WorkerDescriptor {
  if (!value || typeof value !== 'object') return false
  const descriptor = value as Partial<WorkerDescriptor>
  return (
    Number.isSafeInteger(descriptor.pid) &&
    (descriptor.pid ?? 0) > 0 &&
    typeof descriptor.startIdentity === 'string' &&
    typeof descriptor.processIdentity === 'string' &&
    typeof descriptor.endpoint === 'string' &&
    typeof descriptor.token === 'string' &&
    descriptor.token.length >= 16 &&
    descriptor.protocolVersion === NATIVE_WORKER_PROTOCOL_VERSION
  )
}

function tokenFingerprint(token: string): string {
  return new Bun.CryptoHasher('sha256').update(token).digest('hex')
}

function workerReference(descriptor: WorkerDescriptor, executable?: string): WorkerReference {
  return {
    pid: descriptor.pid,
    startIdentity: descriptor.startIdentity,
    processIdentity: descriptor.processIdentity,
    endpoint: descriptor.endpoint,
    tokenFingerprint: tokenFingerprint(descriptor.token),
    protocolVersion: descriptor.protocolVersion,
    ...(executable ? { executable } : {}),
  }
}

function descriptorMatchesReference(
  descriptor: WorkerDescriptor,
  reference: WorkerReference
): boolean {
  return (
    reference.protocolVersion === NATIVE_WORKER_PROTOCOL_VERSION &&
    typeof reference.tokenFingerprint === 'string' &&
    TOKEN_FINGERPRINT.test(reference.tokenFingerprint) &&
    descriptor.pid === reference.pid &&
    descriptor.startIdentity === reference.startIdentity &&
    descriptor.processIdentity === reference.processIdentity &&
    descriptor.endpoint === reference.endpoint &&
    tokenFingerprint(descriptor.token) === reference.tokenFingerprint
  )
}

function verifiedPrestartNoChildReceipt(
  value: unknown,
  authority: WorkerReference | WorkerPrestartAuthority
): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const receipt = value as Record<string, unknown>
  const fields = [
    'receiptVersion',
    'kind',
    'workerId',
    'workerPid',
    'workerProcessIdentity',
    'workerEndpoint',
    'workerProtocolVersion',
    'workerControlToken',
  ]
  if (Object.keys(receipt).length !== fields.length || !fields.every((field) => field in receipt))
    return false
  const workerId = 'workerId' in authority ? authority.workerId : authority.startIdentity
  const fingerprint = authority.tokenFingerprint
  const common =
    receipt.receiptVersion === 1 &&
    receipt.kind === 'prestart_no_child' &&
    receipt.workerId === workerId &&
    receipt.workerProtocolVersion === NATIVE_WORKER_PROTOCOL_VERSION &&
    authority.protocolVersion === NATIVE_WORKER_PROTOCOL_VERSION &&
    typeof fingerprint === 'string' &&
    TOKEN_FINGERPRINT.test(fingerprint) &&
    typeof receipt.workerControlToken === 'string' &&
    tokenFingerprint(receipt.workerControlToken) === fingerprint
  if (!common || 'workerId' in authority) return common
  return (
    receipt.workerPid === authority.pid &&
    receipt.workerProcessIdentity === authority.processIdentity &&
    receipt.workerEndpoint === authority.endpoint
  )
}

function workerCommand(): string[] {
  if (process.env.PTY_NATIVE_WORKER_PATH) return [process.env.PTY_NATIVE_WORKER_PATH]
  if (process.env.PTY_NATIVE_WORKER_DEV === '1') {
    return [
      'cargo',
      'run',
      '--quiet',
      '--manifest-path',
      join(process.cwd(), 'worker', 'Cargo.toml'),
      '--',
    ]
  }
  const target = nativeWorkerTarget(process.platform, process.arch)
  const workerPackage =
    process.platform === 'linux' && target
      ? linuxWorkerPackage(target as 'linux-x64-gnu' | 'linux-arm64-gnu')
      : target && nativeWorkerPackageName(target)
  if (workerPackage) {
    try {
      const require = createRequire(import.meta.url)
      return [
        require.resolve(
          `${workerPackage}/bin/opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
        ),
      ]
    } catch {
      try {
        // ponytail: source-loaded plugins resolve from OpenCode, so use the project dependency tree.
        const require = createRequire(join(process.cwd(), 'package.json'))
        return [
          require.resolve(
            `${workerPackage}/bin/opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
          ),
        ]
      } catch {}
    }
  }
  throw new Error(
    `native_worker_unavailable: install the matching optional worker package for ${process.platform}-${process.arch}, or set PTY_NATIVE_WORKER_PATH.`
  )
}

export function workerLaunchOptions(command: string[]) {
  return {
    cmd: command,
    // Workers must survive signals delivered to the daemon's process group (for example Ctrl+C to
    // the plugin host) on every platform; durability is the whole point of the worker.
    detached: true,
    windowsHide: true,
    stdin: 'pipe' as const,
    stdout: 'pipe' as const,
    stderr: 'inherit' as const,
  }
}

function linuxWorkerPackage(target: 'linux-x64-gnu' | 'linux-arm64-gnu'): string {
  const probe = Bun.spawnSync({ cmd: ['ldd', '--version'], stdout: 'pipe', stderr: 'pipe' })
  const output = `${Buffer.from(probe.stdout)}${Buffer.from(probe.stderr)}`.toLowerCase()
  if (output.includes('musl'))
    throw new Error(
      `native_worker_unavailable: ${target} worker requires glibc; Alpine/musl is unsupported. Set PTY_NATIVE_WORKER_PATH to a compatible worker.`
    )
  if (!output.includes('glibc') && !output.includes('gnu libc'))
    throw new Error(
      'native_worker_unavailable: could not verify a glibc Linux runtime. Set PTY_NATIVE_WORKER_PATH to a compatible worker.'
    )
  return nativeWorkerPackageName(target)
}

async function processIdentity(pid: number): Promise<string | null> {
  if (process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW === '1')
    throw new Error('injected worker identity probe failure')
  if (process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_FAIL === '1') return null
  // macOS worker identity is deliberately unused: Bun owns the fresh child handle (see exited()).
  if (process.platform === 'darwin') return null
  // storage.ts resolves the absolute %SystemRoot% PowerShell path and enforces a 5s budget.
  return processStartIdentity(pid)
}

async function exited(
  child: ReturnType<typeof Bun.spawn>,
  identity: string | null
): Promise<boolean> {
  const exited = await Promise.race([
    child.exited.then(() => true),
    Bun.sleep(2000).then(() => false),
  ])
  if (exited) return true // Bun owns this handle, so its exit promise is stronger than a PID probe.
  if (!identity) return false
  const current = await processIdentity(child.pid)
  return current !== null && current !== identity
}

function frame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), 'utf8')
  return Buffer.concat([Buffer.from(Uint32Array.of(payload.byteLength).buffer).swap32(), payload])
}

type WorkerStdout = {
  reader: ReadableStreamDefaultReader<Uint8Array>
  buffered: Buffer
}

async function readReady(stdout: WorkerStdout, timeoutMs: number): Promise<boolean> {
  let buffered = stdout.buffered
  stdout.buffered = Buffer.alloc(0)
  const deadline = Date.now() + timeoutMs
  while (buffered.byteLength <= MAX_READY_FRAME_BYTES) {
    const newline = buffered.indexOf(0x0a)
    if (newline >= 0) {
      stdout.buffered = buffered.subarray(newline + 1)
      try {
        const record: unknown = JSON.parse(buffered.subarray(0, newline).toString('utf8'))
        return (
          !!record &&
          typeof record === 'object' &&
          Object.keys(record).length === 1 &&
          (record as { ready?: unknown }).ready === true
        )
      } catch {
        return false
      }
    }
    const remaining = deadline - Date.now()
    if (remaining <= 0) return false
    const next = await Promise.race([
      stdout.reader.read(),
      Bun.sleep(remaining).then(() => ({ done: true }) as ReadableStreamReadResult<Uint8Array>),
    ])
    if (next.done) return false
    buffered = Buffer.concat([buffered, next.value])
  }
  return false
}

async function readStdout(stdout: WorkerStdout): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (stdout.buffered.byteLength) {
    const value = stdout.buffered
    stdout.buffered = Buffer.alloc(0)
    return { done: false, value }
  }
  return (await stdout.reader.read()) as ReadableStreamReadResult<Uint8Array>
}

export class WorkerClient {
  private constructor(
    private readonly descriptor: WorkerDescriptor,
    private readonly owned?: {
      child: ReturnType<typeof Bun.spawn>
      stdout: WorkerStdout
      token: string
      sessionDirectory: string
    }
  ) {}

  private async control(operation: 'start' | 'rollback'): Promise<void> {
    if (!this.owned) throw new Error('Worker control channel is not owned by this daemon.')
    const input = this.owned.child.stdin
    if (!input || typeof input === 'number') throw new Error('Worker control pipe is unavailable.')
    await input.write(frame({ operation, token: this.owned.token }))
  }

  static async prepare(
    bootstrap: Omit<WorkerBootstrap, 'workerControlToken' | 'workerId'>,
    persistPrestart?: (authority: WorkerPrestartAuthority) => Promise<void>
  ): Promise<PreparedWorker> {
    const workerControlToken =
      crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '')
    const workerId = crypto.randomUUID()
    // Fault and readiness knobs come exclusively from the daemon's own environment; session
    // environments are stripped of every native worker knob so callers can never inject faults.
    const readyDelay = process.env.OPENCODE_PTY_NATIVE_WORKER_READY_DELAY_MS
    let payload: Buffer
    let command: string[]
    let child: ReturnType<typeof Bun.spawn>
    try {
      payload = Buffer.from(
        JSON.stringify({
          ...bootstrap,
          env: {
            ...Object.fromEntries(
              Object.entries(bootstrap.env).filter(([key]) => !NATIVE_WORKER_KNOB.test(key))
            ),
            // The worker consumes the ready delay from its bootstrap environment.
            ...(readyDelay === undefined
              ? {}
              : { OPENCODE_PTY_NATIVE_WORKER_READY_DELAY_MS: readyDelay }),
          },
          fault: process.env.OPENCODE_PTY_NATIVE_WORKER_FAULT,
          workerControlToken,
          workerId,
        }),
        'utf8'
      )
      if (payload.byteLength > 1024 * 1024)
        throw new Error('native_worker_unavailable: bootstrap too large.')
      command = workerCommand()
      await persistPrestart?.({
        workerId,
        tokenFingerprint: tokenFingerprint(workerControlToken),
        protocolVersion: NATIVE_WORKER_PROTOCOL_VERSION,
      })
      child = Bun.spawn({
        ...workerLaunchOptions(command),
      })
    } catch (error) {
      if (error instanceof WorkerStartError) throw error
      throw new WorkerStartError(
        error instanceof Error ? error.message : String(error),
        {
          requested: false,
          terminationConfirmed: true,
          method: 'none',
          directChildStarted: false,
        },
        undefined,
        true
      )
    }
    let identity: string | null = null
    let client: WorkerClient | undefined
    let prestartReference: WorkerReference | undefined
    const cleanup = async (): Promise<SpawnCleanup> => {
      try {
        const receipt = JSON.parse(
          await readFile(join(bootstrap.sessionDirectory, 'spawn-failure.json'), 'utf8')
        ) as {
          workerId?: unknown
          workerPid?: unknown
          workerProcessIdentity?: unknown
          workerControlToken?: unknown
          directChildStarted?: unknown
          directChildPid?: unknown
          terminationConfirmed?: unknown
          message?: unknown
        }
        if (
          receipt.workerId === workerId &&
          receipt.workerPid === child.pid &&
          receipt.workerProcessIdentity === identity &&
          Object.keys(receipt).length === 8 &&
          [
            'workerId',
            'workerPid',
            'workerProcessIdentity',
            'workerControlToken',
            'directChildStarted',
            'directChildPid',
            'terminationConfirmed',
            'message',
          ].every((field) => field in receipt) &&
          receipt.workerControlToken === workerControlToken &&
          typeof receipt.directChildStarted === 'boolean' &&
          (receipt.directChildStarted
            ? Number.isSafeInteger(receipt.directChildPid) && (receipt.directChildPid as number) > 0
            : receipt.directChildPid === null) &&
          typeof receipt.terminationConfirmed === 'boolean' &&
          typeof receipt.message === 'string'
        )
          return {
            requested: receipt.directChildStarted,
            terminationConfirmed: receipt.terminationConfirmed,
            method: receipt.directChildStarted ? 'rollback' : 'none',
            directChildStarted: receipt.directChildStarted,
            ...(receipt.directChildStarted &&
            Number.isSafeInteger(receipt.directChildPid) &&
            (receipt.directChildPid as number) > 0
              ? { directChildPid: receipt.directChildPid as number }
              : {}),
            message: receipt.message,
          }
      } catch {
        // No authenticated spawn-failure receipt exists; that is the normal path for most
        // failures, so fall through to the descriptor- and handle-based strategies.
      }
      if (client) return client.rollback()
      try {
        const descriptor = await WorkerClient.read(join(bootstrap.sessionDirectory, 'worker.json'))
        if (
          descriptor.pid === child.pid &&
          descriptor.token === workerControlToken &&
          descriptor.startIdentity === workerId &&
          (identity === null || descriptor.processIdentity === identity)
        ) {
          // The command is not eligible to spawn before the authenticated start frame.
          const input = child.stdin
          if (input && typeof input !== 'number') await input.end()
          return {
            requested: true,
            terminationConfirmed: await exited(child, identity),
            method: 'rollback',
          }
        }
      } catch {
        // worker.json may legitimately be absent or unverified this early; the descriptor is only
        // one optional cleanup route, so its failure carries no evidence worth reporting.
      }
      try {
        const input = child.stdin
        if (input && typeof input !== 'number') await input.end()
      } catch {
        // Closing the bootstrap pipe of an already-dead worker fails; the pipe being gone is the
        // outcome this close was after.
      }
      if (!identity) {
        let terminationConfirmed = await exited(child, null)
        let killFailure: string | undefined
        if (!terminationConfirmed) {
          try {
            child.kill()
          } catch (error) {
            killFailure = String(error)
          }
          terminationConfirmed = await exited(child, null)
        }
        return {
          requested: true,
          terminationConfirmed,
          method: 'rollback',
          message: `Worker identity could not be verified; bootstrap was closed before command start.${
            killFailure ? ` Kill failed: ${killFailure}` : ''
          }`,
        }
      }
      try {
        // Fresh Bun handles are owned by this daemon; do not require /proc/mac identity to reap them.
        child.kill()
      } catch (error) {
        return {
          requested: false,
          terminationConfirmed: false,
          method: 'none',
          message: String(error),
        }
      }
      return {
        requested: true,
        terminationConfirmed: await exited(child, identity),
        method: 'kill',
      }
    }
    try {
      identity = await processIdentity(child.pid)
      if (!identity && process.platform !== 'darwin')
        throw new Error('native_worker_unavailable: worker identity verification failed.')
      const input = child.stdin
      if (!input || typeof input === 'number')
        throw new Error('native_worker_unavailable: worker input unavailable.')
      await input.write(frame(JSON.parse(payload.toString('utf8'))))
      const output = child.stdout
      if (!output || typeof output === 'number')
        throw new Error('native_worker_unavailable: worker output unavailable.')
      const stdout = { reader: output.getReader(), buffered: Buffer.alloc(0) }
      const ready = await readReady(
        stdout,
        readyTimeout(process.env.OPENCODE_PTY_NATIVE_WORKER_READY_TIMEOUT_MS)
      )
      if (ready) {
        const descriptor = await WorkerClient.read(join(bootstrap.sessionDirectory, 'worker.json'))
        if (
          descriptor.pid !== child.pid ||
          descriptor.token !== workerControlToken ||
          descriptor.startIdentity !== workerId ||
          (identity !== null && descriptor.processIdentity !== identity)
        ) {
          throw new Error('native_worker_unavailable: worker descriptor verification failed.')
        }
        client = new WorkerClient(descriptor, {
          child,
          stdout,
          token: workerControlToken,
          sessionDirectory: bootstrap.sessionDirectory,
        })
        return {
          client,
          reference: workerReference(descriptor, command[0]),
        }
      }
      let descriptor: WorkerDescriptor | null = null
      for (let attempt = 0; attempt < 40 && !descriptor; attempt += 1) {
        descriptor = await WorkerClient.read(join(bootstrap.sessionDirectory, 'worker.json')).catch(
          () => null
        )
        if (!descriptor) await Bun.sleep(25)
      }
      if (!descriptor)
        throw new Error('native_worker_unavailable: worker descriptor is unavailable.')
      if (
        descriptor.pid !== child.pid ||
        descriptor.token !== workerControlToken ||
        descriptor.startIdentity !== workerId ||
        (identity !== null && descriptor.processIdentity !== identity)
      ) {
        throw new Error('native_worker_unavailable: worker descriptor verification failed.')
      }
      prestartReference = workerReference(descriptor, command[0])
      throw new Error('native_worker_unavailable: worker did not become ready.')
    } catch (error) {
      if (error instanceof WorkerStartError) throw error
      const outcome = await cleanup()
      throw new WorkerStartError(
        `${error instanceof Error ? error.message : String(error)}; cleanup=${JSON.stringify(outcome)}`,
        outcome,
        prestartReference
      )
    }
  }

  static async start(
    bootstrap: Omit<WorkerBootstrap, 'workerControlToken' | 'workerId'>
  ): Promise<PreparedWorker> {
    let prepared: PreparedWorker | undefined
    try {
      prepared = await WorkerClient.prepare(bootstrap)
      await prepared.client.start()
      return prepared
    } catch (error) {
      if (error instanceof WorkerStartError) throw error
      if (!prepared) throw error
      const cleanup = await prepared.client.rollback().catch((rollbackError) => ({
        requested: false,
        terminationConfirmed: false,
        method: 'none' as const,
        message: String(rollbackError),
      }))
      throw new WorkerStartError(
        `${error instanceof Error ? error.message : String(error)}; cleanup=${JSON.stringify(cleanup)}`,
        cleanup
      )
    }
  }

  static async reconnect(
    sessionDirectory: string,
    reference: WorkerReference
  ): Promise<WorkerClient | null> {
    if (reference.protocolVersion !== NATIVE_WORKER_PROTOCOL_VERSION) return null
    try {
      const descriptor = await WorkerClient.read(join(sessionDirectory, 'worker.json'))
      if (
        descriptor.pid !== reference.pid ||
        descriptor.startIdentity !== reference.startIdentity ||
        descriptor.processIdentity !== reference.processIdentity ||
        descriptor.endpoint !== reference.endpoint ||
        !reference.tokenFingerprint ||
        tokenFingerprint(descriptor.token) !== reference.tokenFingerprint
      )
        return null
      const client = new WorkerClient(descriptor)
      const health = await client.health()
      if (
        health.protocolVersion !== descriptor.protocolVersion ||
        health.pid !== reference.pid ||
        health.processIdentity !== reference.processIdentity
      )
        return null
      return client
    } catch {
      return null
    }
  }

  static async hasVerifiedPrestartNoChildReceipt(
    sessionDirectory: string,
    authority: WorkerReference | WorkerPrestartAuthority
  ): Promise<boolean> {
    try {
      return verifiedPrestartNoChildReceipt(
        JSON.parse(await readFile(join(sessionDirectory, 'prestart-no-child.json'), 'utf8')),
        authority
      )
    } catch {
      return false
    }
  }

  static async hasVerifiedNoChildSpawnFailureReceipt(
    sessionDirectory: string,
    reference: WorkerReference
  ): Promise<boolean> {
    if (reference.protocolVersion !== NATIVE_WORKER_PROTOCOL_VERSION) return false
    try {
      const descriptor = await WorkerClient.read(join(sessionDirectory, 'worker.json'))
      if (!descriptorMatchesReference(descriptor, reference)) return false
      const receipt = JSON.parse(
        await readFile(join(sessionDirectory, 'spawn-failure.json'), 'utf8')
      ) as unknown
      if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return false
      const fields = [
        'workerId',
        'workerPid',
        'workerProcessIdentity',
        'workerControlToken',
        'directChildStarted',
        'directChildPid',
        'terminationConfirmed',
        'message',
      ]
      const value = receipt as Record<string, unknown>
      return (
        Object.keys(value).length === fields.length &&
        fields.every((field) => field in value) &&
        value.workerId === reference.startIdentity &&
        value.workerPid === reference.pid &&
        value.workerProcessIdentity === reference.processIdentity &&
        typeof value.workerControlToken === 'string' &&
        tokenFingerprint(value.workerControlToken) === reference.tokenFingerprint &&
        value.directChildStarted === false &&
        value.directChildPid === null &&
        value.terminationConfirmed === true &&
        typeof value.message === 'string'
      )
    } catch {
      return false
    }
  }

  async snapshot(): Promise<WorkerSnapshot> {
    return this.call('snapshot')
  }

  async start(): Promise<WorkerSnapshot> {
    try {
      await this.control('start')
      const health = await this.health()
      if (
        health.protocolVersion !== this.descriptor.protocolVersion ||
        health.pid !== this.descriptor.pid ||
        health.processIdentity !== this.descriptor.processIdentity
      )
        throw new Error(
          'native_worker_unavailable: authenticated worker identity verification failed.'
        )
      for (let attempt = 0; attempt < 50; attempt += 1) {
        try {
          return await this.snapshot()
        } catch {
          await Bun.sleep(20)
        }
      }
      throw new Error('native_worker_unavailable: worker command did not start.')
    } catch (error) {
      let cleanup = await this.spawnFailureCleanup()
      if (!cleanup) {
        const rollback = await this.rollback()
        for (let attempt = 0; attempt < 10 && !cleanup; attempt += 1) {
          await Bun.sleep(20)
          cleanup = await this.spawnFailureCleanup()
        }
        cleanup ??= rollback
      }
      throw new WorkerStartError(
        `${error instanceof Error ? error.message : String(error)}; cleanup=${JSON.stringify(cleanup)}`,
        cleanup
      )
    }
  }

  private async spawnFailureCleanup(): Promise<SpawnCleanup | null> {
    if (!this.owned) return null
    try {
      const receipt = JSON.parse(
        await readFile(join(this.owned.sessionDirectory, 'spawn-failure.json'), 'utf8')
      ) as {
        workerId?: unknown
        workerPid?: unknown
        workerProcessIdentity?: unknown
        workerControlToken?: unknown
        directChildStarted?: unknown
        directChildPid?: unknown
        terminationConfirmed?: unknown
        message?: unknown
      }
      if (
        Object.keys(receipt).length !== 8 ||
        ![
          'workerId',
          'workerPid',
          'workerProcessIdentity',
          'workerControlToken',
          'directChildStarted',
          'directChildPid',
          'terminationConfirmed',
          'message',
        ].every((field) => field in receipt) ||
        receipt.workerId !== this.descriptor.startIdentity ||
        receipt.workerPid !== this.descriptor.pid ||
        receipt.workerProcessIdentity !== this.descriptor.processIdentity ||
        receipt.workerControlToken !== this.owned.token ||
        typeof receipt.directChildStarted !== 'boolean' ||
        (receipt.directChildStarted
          ? !Number.isSafeInteger(receipt.directChildPid) || (receipt.directChildPid as number) <= 0
          : receipt.directChildPid !== null) ||
        typeof receipt.terminationConfirmed !== 'boolean' ||
        typeof receipt.message !== 'string'
      )
        return null
      return {
        requested: receipt.directChildStarted,
        terminationConfirmed: receipt.terminationConfirmed,
        method: receipt.directChildStarted ? 'rollback' : 'none',
        directChildStarted: receipt.directChildStarted,
        ...(receipt.directChildStarted ? { directChildPid: receipt.directChildPid as number } : {}),
        message: receipt.message,
      }
    } catch {
      return null
    }
  }

  async finalSnapshot(): Promise<WorkerSnapshot> {
    return this.call('finalSnapshot', {}, 10_000)
  }

  private async health(): Promise<{
    protocolVersion: number
    pid: number
    processIdentity: string
  }> {
    return this.call('health')
  }

  async wait(timeoutMs: number): Promise<WorkerSnapshot> {
    return this.call('wait', { timeoutMs }, timeoutMs + 5000)
  }

  async write(data: string): Promise<{ acceptedBytes: number; arrivalSequence: number }> {
    return this.call('write', { data })
  }

  async resize(cols: number, rows: number): Promise<{ cols: number; rows: number }> {
    return this.call('resize', { cols, rows })
  }

  async stop(): Promise<WorkerSnapshot> {
    return this.call('stop')
  }

  async shutdown(): Promise<WorkerSnapshot> {
    const result = await this.call<WorkerSnapshot>('shutdown', {}, 10_000)
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        await this.call('health', {}, 100)
        await Bun.sleep(20)
      } catch {
        return result
      }
    }
    throw new Error('Native worker did not exit after shutdown.')
  }

  async rollback(): Promise<SpawnCleanup> {
    if (!this.owned) {
      return {
        requested: false,
        terminationConfirmed: false,
        method: 'none',
        message: 'Worker rollback channel is not owned by this daemon.',
      }
    }
    let controlFailure: string | undefined
    try {
      await this.control('rollback')
      const input = this.owned.child.stdin
      if (input && typeof input !== 'number') await input.end()
    } catch (error) {
      // A failed rollback frame means no receipt can arrive; keep draining stdout for a receipt
      // already in flight, but surface the control failure in the unconfirmed outcome below.
      controlFailure = String(error)
    }
    let output = ''
    const deadline = Date.now() + 5000
    while (Date.now() < deadline) {
      const next = await Promise.race([
        readStdout(this.owned.stdout),
        Bun.sleep(deadline - Date.now()).then(
          () => ({ done: true }) as ReadableStreamReadResult<Uint8Array>
        ),
      ])
      if (next.done) break
      output += new TextDecoder().decode(next.value)
      if (output.includes(`"rollback":true,"token":"${this.owned.token}"`)) {
        const pid = Number(/"pid":(\d+)/.exec(output)?.[1])
        return {
          requested: true,
          terminationConfirmed: Number.isSafeInteger(pid) && pid > 0,
          method: 'rollback',
          ...(Number.isSafeInteger(pid) && pid > 0 ? { directChildPid: pid } : {}),
        }
      }
    }
    const reference: WorkerReference = {
      pid: this.descriptor.pid,
      startIdentity: this.descriptor.startIdentity,
      processIdentity: this.descriptor.processIdentity,
      endpoint: this.descriptor.endpoint,
      tokenFingerprint: tokenFingerprint(this.descriptor.token),
      protocolVersion: this.descriptor.protocolVersion,
    }
    if (
      await WorkerClient.hasVerifiedPrestartNoChildReceipt(this.owned.sessionDirectory, reference)
    ) {
      return {
        requested: false,
        terminationConfirmed: true,
        method: 'none',
        directChildStarted: false,
        message: 'Worker confirmed that no start frame created a child.',
      }
    }
    return {
      requested: true,
      terminationConfirmed: false,
      method: 'rollback',
      message: controlFailure
        ? `Worker rollback control failed: ${controlFailure}`
        : 'Worker exited without an authenticated direct-child rollback receipt.',
    }
  }

  /**
   * Best-effort termination of a worker that can no longer be reconnected. Prefers an
   * authenticated shutdown RPC against the persisted descriptor; falls back to killing the
   * descriptor's pid only after its start identity is re-verified. Returns a diagnostic detail
   * instead of throwing wherever the outcome is merely unconfirmed.
   */
  static async terminateOrphan(
    sessionDirectory: string
  ): Promise<{ outcome: 'shutdown' | 'killed' | 'skipped'; detail?: string }> {
    let descriptor: WorkerDescriptor
    try {
      descriptor = await WorkerClient.read(join(sessionDirectory, 'worker.json'))
    } catch {
      // Without a readable descriptor there is no authenticated endpoint and no verified pid to
      // act on; nothing further can be attempted safely.
      return { outcome: 'skipped' }
    }
    let shutdownFailure: string
    try {
      await new WorkerClient(descriptor).call('shutdown', {}, ORPHAN_SHUTDOWN_TIMEOUT_MS)
      return { outcome: 'shutdown' }
    } catch (error) {
      shutdownFailure = String(error)
    }
    const identity = await processStartIdentity(descriptor.pid).catch(() => null)
    if (identity === null || identity !== descriptor.processIdentity)
      return {
        outcome: 'skipped',
        detail: `shutdown RPC failed (${shutdownFailure}) and pid ${descriptor.pid} did not match the descriptor identity`,
      }
    try {
      process.kill(descriptor.pid, 'SIGKILL')
    } catch (error) {
      return {
        outcome: 'skipped',
        detail: `shutdown RPC failed (${shutdownFailure}); kill failed: ${String(error)}`,
      }
    }
    return {
      outcome: 'killed',
      detail: `shutdown RPC failed (${shutdownFailure}); killed identity-verified pid ${descriptor.pid}`,
    }
  }

  private async call<T>(
    operation: string,
    payload: Record<string, unknown> = {},
    timeoutMs = 5000
  ): Promise<T> {
    const response = await fetch(`${this.descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.descriptor.token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ operation, ...payload }),
      signal: AbortSignal.timeout(timeoutMs),
    })
    const body = (await response.json()) as { ok: boolean; result?: T; error?: { message: string } }
    if (!body.ok || body.result === undefined)
      throw new Error(body.error?.message ?? 'Worker RPC failed.')
    return body.result
  }

  private static async read(path: string): Promise<WorkerDescriptor> {
    await access(path)
    const descriptor = JSON.parse(await readFile(path, 'utf8')) as unknown
    if (!validDescriptor(descriptor)) throw new Error('Invalid worker descriptor.')
    return descriptor
  }
}

export interface WorkerSnapshot {
  status: 'running' | 'exited' | 'lost'
  pid: number
  mode: 'exec' | 'pty'
  stdout?: string
  stderr?: string
  stdoutBytes: number
  stderrBytes: number
  stdoutTruncated: boolean
  stderrTruncated: boolean
  nextSequence: number
  firstRetainedSequence: number
  outputTruncated: boolean
  outputLineCount: number
  outputHasPartialLine: boolean
  exitCode?: number | null
  exitSignal?: string | null
  exitReason?:
    | 'code'
    | `signal:${string}`
    | 'timeout'
    | 'output_limit'
    | 'stopped'
    | 'storage_failure'
  startedAt: string
  exitedAt?: string
  timedOut: boolean
  terminationRequested: boolean
  terminationConfirmed: boolean
  directChildExited: boolean
  storageFailure?: string
  stdoutEof: boolean
  stderrEof: boolean
  outputComplete: boolean
  outputIncomplete: boolean
  readerFailure?: string
  diagnostics?: string[]
  containment: ContainmentReport
  termination?: TerminationResult
}
