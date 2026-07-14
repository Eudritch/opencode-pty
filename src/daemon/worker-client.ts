import { access, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import type { SpawnCleanup } from './types.ts'

function readyTimeout(value: string | undefined): number {
  const timeout = Number(value ?? 5000)
  return Number.isFinite(timeout) && timeout > 0 ? timeout : 5000
}

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
  timeoutSeconds: number
  maxOutputBytes: number
  mode: 'exec'
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
    descriptor.protocolVersion === 1
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
  throw new Error(
    'native_worker_unavailable: set PTY_NATIVE_WORKER_PATH to the built worker binary.'
  )
}

async function processIdentity(pid: number): Promise<string | null> {
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

async function exited(child: ReturnType<typeof Bun.spawn>, identity: string): Promise<boolean> {
  await Promise.race([child.exited, Bun.sleep(2000)])
  return (await processIdentity(child.pid)) !== identity
}

export class WorkerClient {
  private constructor(private readonly descriptor: WorkerDescriptor) {}

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
    const child = Bun.spawn({
      cmd: workerCommand(),
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'inherit',
    })
    const identity = await processIdentity(child.pid)
    const cleanup = async (): Promise<SpawnCleanup> => {
      try {
        const descriptor = await WorkerClient.read(join(bootstrap.sessionDirectory, 'worker.json'))
        if (
          descriptor.pid === child.pid &&
          descriptor.token === workerControlToken &&
          descriptor.startIdentity === workerId &&
          identity !== null &&
          descriptor.processIdentity === identity
        ) {
          const client = new WorkerClient(descriptor)
          const directChildPid = (await client.snapshot()).pid
          await client.shutdown()
          return {
            requested: true,
            terminationConfirmed: await exited(child, identity),
            method: 'shutdown',
            directChildPid,
          }
        }
      } catch {}
      if (!identity) {
        return {
          requested: false,
          terminationConfirmed: child.exitCode !== null,
          method: 'none',
          message: 'Worker identity could not be verified.',
        }
      }
      const current = await processIdentity(child.pid)
      if (current !== identity) {
        return { requested: false, terminationConfirmed: true, method: 'none' }
      }
      try {
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
      if (!identity)
        throw new Error('native_worker_unavailable: worker identity verification failed.')
      await child.stdin.write(
        Buffer.concat([Buffer.from(Uint32Array.of(payload.byteLength).buffer).swap32(), payload])
      )
      await child.stdin.end()
      const reader = child.stdout.getReader()
      const ready = await Promise.race([
        reader
          .read()
          .then(({ value }) => new TextDecoder().decode(value).includes('{"ready":true}')),
        Bun.sleep(readyTimeout(bootstrap.env.OPENCODE_PTY_NATIVE_WORKER_READY_TIMEOUT_MS)).then(
          () => false
        ),
      ])
      if (!ready) await reader.cancel().catch(() => undefined)
      reader.releaseLock()
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
        return {
          client: new WorkerClient(descriptor),
          reference: {
            pid: descriptor.pid,
            startIdentity: descriptor.startIdentity,
            processIdentity: descriptor.processIdentity,
            endpoint: descriptor.endpoint,
            protocolVersion: descriptor.protocolVersion,
          },
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
      throw new Error('native_worker_unavailable: worker did not become ready.')
    } catch (error) {
      const outcome = await cleanup()
      await rm(join(bootstrap.sessionDirectory, 'worker.json'), { force: true }).catch(
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

  async write(data: string): Promise<{ acceptedBytes: number }> {
    return this.call('write', { data })
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
}
