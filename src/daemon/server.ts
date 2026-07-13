import {
  DAEMON_PROTOCOL_VERSION,
  type DaemonDescriptor,
  type RpcFailure,
  type RpcRequest,
  type RpcResponse,
} from './types.ts'
import type { DaemonStorage } from './storage.ts'
import { ProcessError, type SessionSupervisor } from './supervisor.ts'

const MAX_REQUEST_BYTES = 1024 * 1024
const MAX_ID_LENGTH = 128
const MAX_STRING_LENGTH = 16 * 1024
const MAX_COMMAND_LENGTH = 4096
const MAX_ARGUMENTS = 256
const MAX_ENVIRONMENT_ENTRIES = 128
const MAX_PAGE_SIZE = 10_000

class ValidationError extends Error {}

export class DaemonServer implements Disposable {
  private server: ReturnType<typeof Bun.serve> | null = null

  constructor(
    private readonly storage: DaemonStorage,
    private readonly supervisor: SessionSupervisor,
    private readonly token: string = crypto.randomUUID().replaceAll('-', '')
  ) {}

  async start(): Promise<DaemonDescriptor> {
    await this.supervisor.initialize()
    this.server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch: (request) => this.handle(request),
    })
    const descriptor = {
      pid: process.pid,
      endpoint: this.server.url.origin,
      protocolVersion: DAEMON_PROTOCOL_VERSION,
      token: this.token,
    }
    await this.storage.writeDescriptor(descriptor)
    return descriptor
  }

  async stop(): Promise<void> {
    this.server?.stop(true)
    await this.supervisor.flush()
    await this.storage.removeDescriptor()
  }

  [Symbol.dispose](): void {
    this.server?.stop(true)
  }

  private async handle(request: Request): Promise<Response> {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/rpc') {
      return new Response('Not found', { status: 404 })
    }
    if (request.headers.get('authorization') !== `Bearer ${this.token}`) {
      return this.failure('', 'authentication', 'Invalid daemon credential.', 401)
    }
    let rpcRequest: RpcRequest
    try {
      const body = await request.text()
      if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) {
        return this.failure('', 'validation', 'Request body is too large.', 413)
      }
      rpcRequest = JSON.parse(body) as RpcRequest
    } catch {
      return this.failure('', 'validation', 'Request body must be JSON.', 400)
    }
    if (!rpcRequest || typeof rpcRequest !== 'object' || Array.isArray(rpcRequest)) {
      return this.failure('', 'validation', 'RPC request must be an object.', 400)
    }
    if (
      typeof rpcRequest.id !== 'string' ||
      !rpcRequest.id ||
      rpcRequest.id.length > MAX_ID_LENGTH ||
      typeof rpcRequest.version !== 'number' ||
      typeof rpcRequest.operation !== 'string' ||
      !rpcRequest.operation ||
      rpcRequest.operation.length > 64
    ) {
      return this.failure('', 'validation', 'Invalid RPC request.', 400)
    }
    if (rpcRequest.version !== DAEMON_PROTOCOL_VERSION) {
      return this.failure(rpcRequest.id, 'protocol', 'Invalid RPC protocol version.', 400)
    }
    try {
      const result = await this.dispatch(rpcRequest)
      return Response.json({ id: rpcRequest.id, ok: true, result } satisfies RpcResponse<unknown>)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      const code =
        error instanceof ValidationError
          ? 'validation'
          : this.isStorageError(error)
            ? 'storage'
            : error instanceof ProcessError
              ? 'process'
              : message.includes('not found')
                ? 'not_found'
                : message.includes('closed')
                  ? 'session_closed'
                  : 'internal'
      return this.failure(rpcRequest.id, code, message, code === 'not_found' ? 404 : 400)
    }
  }

  private async dispatch(request: RpcRequest): Promise<unknown> {
    switch (request.operation) {
      case 'health':
        this.onlyFields(this.objectPayload(request.payload ?? {}), [])
        return { protocolVersion: DAEMON_PROTOCOL_VERSION, pid: process.pid }
      case 'spawn':
        return this.supervisor.spawn(this.spawnPayload(request.payload))
      case 'write': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'data'])
        const id = this.requiredString(payload, 'id')
        const data = this.requiredString(payload, 'data')
        return this.supervisor.write(id, data)
      }
      case 'read': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'offset', 'limit'])
        return this.supervisor.read(
          this.requiredString(payload, 'id'),
          this.optionalNonnegativeInteger(payload, 'offset'),
          this.optionalNonnegativeInteger(payload, 'limit')
        )
      }
      case 'search': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'pattern', 'ignoreCase', 'offset', 'limit'])
        return this.supervisor.search(
          this.requiredString(payload, 'id'),
          this.requiredString(payload, 'pattern'),
          this.optionalBoolean(payload, 'ignoreCase') ?? false,
          this.optionalNonnegativeInteger(payload, 'offset'),
          this.optionalNonnegativeInteger(payload, 'limit')
        )
      }
      case 'list':
        return this.supervisor.list()
      case 'get':
        return this.get(request.payload)
      case 'rawOutput':
        return this.rawOutput(request.payload)
      case 'stop':
        return this.stopSession(request.payload)
      case 'cleanup':
        return this.cleanup(request.payload)
      case 'cleanupByParentSession':
        return this.cleanupByParentSession(request.payload)
      default:
        throw new ValidationError(`Unsupported RPC operation '${request.operation}'.`)
    }
  }

  private objectPayload(payload: unknown): Record<string, unknown> {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new ValidationError('RPC payload must be an object.')
    }
    return payload as Record<string, unknown>
  }

  private onlyFields(payload: Record<string, unknown>, names: string[]): void {
    if (Object.keys(payload).some((key) => !names.includes(key))) {
      throw new ValidationError(
        `RPC field '${Object.keys(payload).find((key) => !names.includes(key))}' is not supported.`
      )
    }
  }

  private get(payload: unknown) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    return this.supervisor.get(this.requiredString(value, 'id'))
  }

  private rawOutput(payload: unknown) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    return this.supervisor.rawOutput(this.requiredString(value, 'id'))
  }

  private stopSession(payload: unknown) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    return this.supervisor.stop(this.requiredString(value, 'id'))
  }

  private cleanup(payload: unknown) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    return this.supervisor.cleanup(this.requiredString(value, 'id'))
  }

  private cleanupByParentSession(payload: unknown) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['parentSessionId'])
    return this.supervisor.cleanupByParentSession(this.requiredString(value, 'parentSessionId'))
  }

  private requiredString(payload: Record<string, unknown>, key: string): string {
    const value = payload[key]
    if (typeof value !== 'string' || !value || value.length > MAX_STRING_LENGTH)
      throw new ValidationError(
        `RPC field '${key}' must be a non-empty string within the size limit.`
      )
    return value
  }

  private optionalString(payload: Record<string, unknown>, key: string): string | undefined {
    const value = payload[key]
    if (value === undefined) return undefined
    if (typeof value !== 'string' || value.length > MAX_STRING_LENGTH)
      throw new ValidationError(`RPC field '${key}' must be a string within the size limit.`)
    return value
  }

  private optionalNonnegativeInteger(
    payload: Record<string, unknown>,
    key: string
  ): number | undefined {
    const value = payload[key]
    if (value === undefined) return undefined
    if (!Number.isInteger(value) || (value as number) < 0) {
      throw new ValidationError(`RPC field '${key}' must be a non-negative integer.`)
    }
    if ((value as number) > MAX_PAGE_SIZE) {
      throw new ValidationError(`RPC field '${key}' exceeds the size limit.`)
    }
    return value as number
  }

  private optionalBoolean(payload: Record<string, unknown>, key: string): boolean | undefined {
    const value = payload[key]
    if (value === undefined) return undefined
    if (typeof value !== 'boolean')
      throw new ValidationError(`RPC field '${key}' must be a boolean.`)
    return value
  }

  private spawnPayload(payload: unknown): Parameters<SessionSupervisor['spawn']>[0] {
    const value = this.objectPayload(payload)
    this.onlyFields(value, [
      'command',
      'args',
      'description',
      'workdir',
      'env',
      'title',
      'parentSessionId',
      'parentAgent',
      'timeoutSeconds',
    ])
    const args = value.args
    if (
      args !== undefined &&
      (!Array.isArray(args) || args.some((argument) => typeof argument !== 'string'))
    ) {
      throw new ValidationError("RPC field 'args' must be an array of strings.")
    }
    if (
      args &&
      (args.length > MAX_ARGUMENTS || args.some((argument) => argument.length > MAX_STRING_LENGTH))
    ) {
      throw new ValidationError("RPC field 'args' exceeds the size limit.")
    }
    const env = value.env
    if (
      env !== undefined &&
      (!env ||
        typeof env !== 'object' ||
        Array.isArray(env) ||
        Object.values(env).some((entry) => typeof entry !== 'string'))
    ) {
      throw new ValidationError("RPC field 'env' must be a string map.")
    }
    if (
      env &&
      (Object.keys(env).length > MAX_ENVIRONMENT_ENTRIES ||
        Object.entries(env).some(
          ([key, entry]) => key.length > 256 || entry.length > MAX_STRING_LENGTH
        ))
    ) {
      throw new ValidationError("RPC field 'env' exceeds the size limit.")
    }
    const timeoutSeconds = this.optionalNonnegativeInteger(value, 'timeoutSeconds')
    if (timeoutSeconds === 0)
      throw new ValidationError("RPC field 'timeoutSeconds' must be positive.")
    const command = this.requiredString(value, 'command')
    if (command.length > MAX_COMMAND_LENGTH) {
      throw new ValidationError("RPC field 'command' exceeds the size limit.")
    }
    return {
      command,
      args: args as string[] | undefined,
      description: this.optionalString(value, 'description'),
      workdir: this.optionalString(value, 'workdir'),
      env: env as Record<string, string> | undefined,
      title: this.optionalString(value, 'title'),
      parentSessionId: this.requiredString(value, 'parentSessionId'),
      parentAgent: this.optionalString(value, 'parentAgent'),
      timeoutSeconds,
    }
  }

  private isStorageError(error: unknown): boolean {
    return (
      error instanceof Error &&
      'code' in error &&
      typeof error.code === 'string' &&
      /^E[A-Z]+$/.test(error.code)
    )
  }

  private failure(
    id: string,
    code: RpcFailure['error']['code'],
    message: string,
    status: number
  ): Response {
    return Response.json({ id, ok: false, error: { code, message } } satisfies RpcFailure, {
      status,
    })
  }
}
