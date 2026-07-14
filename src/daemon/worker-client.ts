import { access, readFile, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import type { ContainmentReport, SpawnCleanup, TerminationResult } from './types.ts'

function readyTimeout(value: string | undefined): number {
  const timeout = Number(value ?? 5000)
  return Number.isFinite(timeout) && timeout > 0 ? timeout : 5000
}

const MAX_READY_FRAME_BYTES = 1024 * 1024

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
  protocolVersion: number
  executable?: string
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
    readonly cleanup: SpawnCleanup
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
    descriptor.protocolVersion === 3
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
  const workerPackage =
    process.platform === 'linux' && process.arch === 'x64'
      ? linuxWorkerPackage()
      : process.platform === 'win32' && process.arch === 'x64'
        ? '@eudritch/opencode-pty-worker-win32-x64'
        : process.platform === 'darwin' && process.arch === 'arm64'
          ? '@eudritch/opencode-pty-worker-darwin-arm64'
          : undefined
  if (workerPackage) {
    try {
      const require = createRequire(import.meta.url)
      return [
        require.resolve(
          `${workerPackage}/bin/opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
        ),
      ]
    } catch {}
  }
  throw new Error(
    `native_worker_unavailable: install the matching optional worker package for ${process.platform}-${process.arch}, or set PTY_NATIVE_WORKER_PATH.`
  )
}

function linuxWorkerPackage(): string {
  const probe = Bun.spawnSync({ cmd: ['ldd', '--version'], stdout: 'pipe', stderr: 'pipe' })
  const output = `${Buffer.from(probe.stdout)}${Buffer.from(probe.stderr)}`.toLowerCase()
  if (output.includes('musl'))
    throw new Error(
      'native_worker_unavailable: linux-x64-gnu worker requires glibc; Alpine/musl is unsupported. Set PTY_NATIVE_WORKER_PATH to a compatible worker.'
    )
  if (!output.includes('glibc') && !output.includes('gnu libc'))
    throw new Error(
      'native_worker_unavailable: could not verify a glibc Linux runtime. Set PTY_NATIVE_WORKER_PATH to a compatible worker.'
    )
  return '@eudritch/opencode-pty-worker-linux-x64-gnu'
}

async function processIdentity(pid: number): Promise<string | null> {
  if (process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW === '1')
    throw new Error('injected worker identity probe failure')
  if (process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_FAIL === '1') return null
  if (process.platform === 'darwin') {
    try {
      process.kill(pid, 0)
      return `posix:${pid}:unavailable`
    } catch {
      return null
    }
  }
  if (process.platform !== 'win32') {
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
  const probe = Bun.spawn({
    cmd: [
      'powershell.exe',
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `$process = Get-Process -Id ${pid} -ErrorAction SilentlyContinue; if ($process) { [Console]::Write("windows:${pid}:$($process.StartTime.ToFileTimeUtc())") }`,
    ],
    stdout: 'pipe',
    stderr: 'ignore',
  })
  const output = (await new Response(probe.stdout).text()).trim()
  await probe.exited
  return output || null
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
    }
  ) {}

  private async control(operation: 'start' | 'rollback'): Promise<void> {
    if (!this.owned) throw new Error('Worker control channel is not owned by this daemon.')
    const input = this.owned.child.stdin
    if (!input || typeof input === 'number') throw new Error('Worker control pipe is unavailable.')
    await input.write(frame({ operation, token: this.owned.token }))
  }

  static async start(bootstrap: Omit<WorkerBootstrap, 'workerControlToken' | 'workerId'>): Promise<{
    client: WorkerClient
    reference: WorkerReference
  }> {
    const workerControlToken =
      crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '')
    const workerId = crypto.randomUUID()
    const payload = Buffer.from(
      JSON.stringify({
        ...bootstrap,
        fault: bootstrap.env.OPENCODE_PTY_NATIVE_WORKER_FAULT,
        workerControlToken,
        workerId,
      }),
      'utf8'
    )
    if (payload.byteLength > 1024 * 1024)
      throw new Error('native_worker_unavailable: bootstrap too large.')
    const command = workerCommand()
    const child = Bun.spawn({
      cmd: command,
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'inherit',
    })
    let identity: string | null = null
    let client: WorkerClient | undefined
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
          receipt.workerControlToken === workerControlToken &&
          typeof receipt.directChildStarted === 'boolean' &&
          (receipt.directChildStarted
            ? Number.isSafeInteger(receipt.directChildPid) && (receipt.directChildPid as number) > 0
            : receipt.directChildPid === null || receipt.directChildPid === undefined) &&
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
      } catch {}
      if (client) return client.rollback()
      try {
        const descriptor = await WorkerClient.read(join(bootstrap.sessionDirectory, 'worker.json'))
        if (
          descriptor.pid === child.pid &&
          descriptor.token === workerControlToken &&
          descriptor.startIdentity === workerId &&
          identity !== null &&
          descriptor.processIdentity === identity
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
      } catch {}
      try {
        const input = child.stdin
        if (input && typeof input !== 'number') await input.end()
      } catch {}
      if (!identity) {
        let terminationConfirmed = await exited(child, null)
        if (!terminationConfirmed) {
          try {
            child.kill()
          } catch {}
          terminationConfirmed = await exited(child, null)
        }
        return {
          requested: true,
          terminationConfirmed,
          method: 'rollback',
          message:
            'Worker identity could not be verified; bootstrap was closed before command start.',
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
      if (!identity)
        throw new Error('native_worker_unavailable: worker identity verification failed.')
      const input = child.stdin
      if (!input || typeof input === 'number')
        throw new Error('native_worker_unavailable: worker input unavailable.')
      await input.write(frame(JSON.parse(payload.toString('utf8'))))
      const stdout = { reader: child.stdout.getReader(), buffered: Buffer.alloc(0) }
      const ready = await readReady(
        stdout,
        readyTimeout(bootstrap.env.OPENCODE_PTY_NATIVE_WORKER_READY_TIMEOUT_MS)
      )
      if (ready) {
        const descriptor = await WorkerClient.read(join(bootstrap.sessionDirectory, 'worker.json'))
        if (
          descriptor.pid !== child.pid ||
          descriptor.token !== workerControlToken ||
          descriptor.startIdentity !== workerId ||
          descriptor.processIdentity !== identity
        ) {
          throw new Error('native_worker_unavailable: worker descriptor verification failed.')
        }
        client = new WorkerClient(descriptor, { child, stdout, token: workerControlToken })
        await client.control('start')
        for (let attempt = 0; attempt < 50; attempt += 1) {
          try {
            await client.snapshot()
            return {
              client,
              reference: {
                pid: descriptor.pid,
                startIdentity: descriptor.startIdentity,
                processIdentity: descriptor.processIdentity,
                endpoint: descriptor.endpoint,
                protocolVersion: descriptor.protocolVersion,
                executable: command[0],
              },
            }
          } catch {
            await Bun.sleep(20)
          }
        }
        throw new Error('native_worker_unavailable: worker command did not start.')
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
      throw new Error('native_worker_unavailable: worker did not become ready.')
    } catch (error) {
      const outcome = await cleanup()
      await rm(join(bootstrap.sessionDirectory, 'worker.json'), { force: true }).catch(
        () => undefined
      )
      await rm(join(bootstrap.sessionDirectory, 'spawn-failure.json'), { force: true }).catch(
        () => undefined
      )
      throw new WorkerStartError(
        `${error instanceof Error ? error.message : String(error)}; cleanup=${JSON.stringify(outcome)}`,
        outcome
      )
    }
  }

  static async reconnect(
    sessionDirectory: string,
    reference: WorkerReference
  ): Promise<WorkerClient | null> {
    try {
      const descriptor = await WorkerClient.read(join(sessionDirectory, 'worker.json'))
      if (
        descriptor.pid !== reference.pid ||
        descriptor.startIdentity !== reference.startIdentity ||
        descriptor.processIdentity !== reference.processIdentity ||
        descriptor.endpoint !== reference.endpoint
      )
        return null
      if ((await processIdentity(descriptor.pid)) !== descriptor.processIdentity) return null
      const client = new WorkerClient(descriptor)
      await client.call('health')
      return client
    } catch {
      return null
    }
  }

  async snapshot(): Promise<WorkerSnapshot> {
    return this.call('snapshot')
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
    try {
      await this.control('rollback')
      const input = this.owned.child.stdin
      if (input && typeof input !== 'number') await input.end()
    } catch {}
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
    return {
      requested: true,
      terminationConfirmed: false,
      method: 'rollback',
      message: 'Worker exited without an authenticated direct-child rollback receipt.',
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
  stdout: string
  stderr: string
  stdoutBytes: number
  stderrBytes: number
  stdoutTruncated: boolean
  stderrTruncated: boolean
  nextSequence: number
  firstRetainedSequence: number
  outputTruncated: boolean
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
  storageFailure?: string
  stdoutEof: boolean
  stderrEof: boolean
  outputComplete: boolean
  outputIncomplete: boolean
  readerFailure?: string
  containment: ContainmentReport
  termination?: TerminationResult
}
