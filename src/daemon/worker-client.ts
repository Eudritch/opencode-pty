import { access, readFile } from 'node:fs/promises'
import { join } from 'node:path'

const READY_TIMEOUT_MS = 5000

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

export class WorkerClient {
  private constructor(private readonly descriptor: WorkerDescriptor) {}

  static async start(bootstrap: Omit<WorkerBootstrap, 'workerControlToken' | 'workerId'>): Promise<{
    client: WorkerClient
    reference: WorkerReference
  }> {
    const workerControlToken =
      crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '')
    const workerId = crypto.randomUUID()
    const child = Bun.spawn({
      cmd: workerCommand(),
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'inherit',
    })
    const payload = Buffer.from(
      JSON.stringify({ ...bootstrap, workerControlToken, workerId }),
      'utf8'
    )
    if (payload.byteLength > 1024 * 1024)
      throw new Error('native_worker_unavailable: bootstrap too large.')
    await child.stdin.write(
      Buffer.concat([Buffer.from(Uint32Array.of(payload.byteLength).buffer).swap32(), payload])
    )
    await child.stdin.end()
    const reader = child.stdout.getReader()
    const ready = await Promise.race([
      reader.read().then(({ value }) => new TextDecoder().decode(value).includes('{"ready":true}')),
      Bun.sleep(READY_TIMEOUT_MS).then(() => false),
    ])
    reader.releaseLock()
    if (!ready) throw new Error('native_worker_unavailable: worker did not become ready.')
    const descriptor = await WorkerClient.read(join(bootstrap.sessionDirectory, 'worker.json'))
    if (descriptor.token !== workerControlToken || descriptor.startIdentity !== workerId) {
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
