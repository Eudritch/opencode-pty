import {
  DAEMON_PROTOCOL_VERSION,
  type DaemonDescriptor,
  type DaemonDiagnostics,
  type OwnerContext,
  type RpcFailure,
  type RpcRequest,
  type RpcResponse,
} from './types.ts'
import { processStartIdentity, type DaemonStorage } from './storage.ts'
import { ProcessError, type SessionSupervisor } from './supervisor.ts'
import { effectiveMaxOutputBytes } from './supervisor.ts'
import { realpathSync } from 'node:fs'
import { resolve } from 'node:path'

const MAX_REQUEST_BYTES = 1024 * 1024
const MAX_ID_LENGTH = 128
const MAX_STRING_LENGTH = 16 * 1024
const MAX_COMMAND_LENGTH = 4096
const MAX_ARGUMENTS = 256
const MAX_ENVIRONMENT_ENTRIES = 128
const MAX_PAGE_SIZE = 10_000
const MAX_INPUT_BYTES = 64 * 1024
const MAX_INPUT_BYTES_PER_MINUTE = 256 * 1024
const DEFAULT_MAX_SESSIONS_PER_OWNER = 32
const MAX_EXEC_RUNTIME_SECONDS = 3600

class ValidationError extends Error {}

export class DaemonServer implements Disposable {
  private server: ReturnType<typeof Bun.serve> | null = null
  private readonly inputUsage = new Map<string, { startedAt: number; bytes: number }>()
  private readonly pendingSessions = new Map<string, number>()
  private ownershipSecret = ''
  private processIdentity = ''

  constructor(
    private readonly storage: DaemonStorage,
    private readonly supervisor: SessionSupervisor,
    private token: string = '',
    private readonly maxSessionsPerOwner: number = DEFAULT_MAX_SESSIONS_PER_OWNER,
    private readonly startLockHandoffToken?: string
  ) {}

  async start(): Promise<DaemonDescriptor> {
    const deadline = Date.now() + 20_000
    const startLockToken = this.startLockHandoffToken
      ? await this.storage.claimStartLock(this.startLockHandoffToken, deadline)
      : (await this.storage.acquireStartLock(deadline))?.token
    if (!startLockToken) {
      throw new Error('PTY daemon start lock was lost.')
    }
    try {
      await this.supervisor.initialize()
      this.ownershipSecret = await this.storage.ownershipSecret()
      this.processIdentity = (await processStartIdentity(process.pid, deadline)) ?? ''
      if (!this.processIdentity) throw new Error('Unable to verify daemon process identity.')
      this.token ||= crypto.randomUUID().replaceAll('-', '')
      if (await this.storage.descriptorOwnerAlive(deadline)) {
        throw new Error('PTY daemon is already running.')
      }
      this.server = Bun.serve({
        hostname: '127.0.0.1',
        port: 0,
        fetch: (request) => this.handle(request),
      })
      const descriptor = {
        pid: process.pid,
        processIdentity: this.processIdentity,
        endpoint: this.server.url.origin,
        protocolVersion: DAEMON_PROTOCOL_VERSION,
        token: this.token,
      }
      await this.storage.writeDescriptor(descriptor)
      await this.storage.releaseStartLock(startLockToken, deadline)
      return descriptor
    } catch (error) {
      this.server?.stop(true)
      this.server = null
      await this.storage.releaseStartLock(startLockToken, deadline)
      throw error
    }
  }

  async stop(): Promise<void> {
    this.server?.stop()
    await this.supervisor.shutdown?.(false)
    await this.supervisor.flush()
    await this.storage.removeDescriptor(this.token, this.processIdentity)
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
      const body = await this.requestBody(request)
      rpcRequest = JSON.parse(body) as RpcRequest
    } catch (error) {
      if (error instanceof ValidationError)
        return this.failure('', 'validation', error.message, 413)
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
            : message.includes('not authorized')
              ? 'authorization'
              : message.includes('limit')
                ? 'limit'
                : error instanceof ProcessError
                  ? 'process'
                  : message.includes('not found')
                    ? 'not_found'
                    : message.includes('closed')
                      ? 'session_closed'
                      : 'internal'
      return this.failure(
        rpcRequest.id,
        code,
        message,
        code === 'not_found' ? 404 : 400,
        error instanceof ProcessError ? error.spawnFailure : undefined
      )
    }
  }

  private async requestBody(request: Request): Promise<string> {
    const contentLength = request.headers.get('content-length')
    if (contentLength) {
      if (!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_REQUEST_BYTES) {
        throw new ValidationError('Request body is too large.')
      }
    }
    if (!request.body) return ''
    const reader = request.body.getReader()
    const decoder = new TextDecoder()
    let bytes = 0
    let body = ''
    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) return body + decoder.decode()
        if (!value) continue
        bytes += value.byteLength
        if (bytes > MAX_REQUEST_BYTES) {
          await reader.cancel()
          throw new ValidationError('Request body is too large.')
        }
        body += decoder.decode(value, { stream: true })
      }
    } finally {
      reader.releaseLock()
    }
  }

  private async dispatch(request: RpcRequest): Promise<unknown> {
    if (request.operation === 'health') {
      this.onlyFields(this.objectPayload(request.payload ?? {}), [])
      return {
        protocolVersion: DAEMON_PROTOCOL_VERSION,
        pid: process.pid,
        processIdentity: this.processIdentity,
      }
    }
    if (request.operation === 'diagnostics') {
      const owner = this.owner(request)
      return this.diagnostics(owner)
    }
    const owner = this.owner(request)
    switch (request.operation) {
      case 'spawn':
        return this.spawn(this.spawnPayload(request.payload), owner)
      case 'exec':
        return this.exec(this.execPayload(request.payload), owner)
      case 'write': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'data'])
        const id = this.requiredString(payload, 'id')
        const data = this.requiredString(payload, 'data')
        this.authorize(id, owner)
        this.useInput(owner, data)
        return this.supervisor.write(id, data)
      }
      case 'resize': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'cols', 'rows'])
        const id = this.requiredString(payload, 'id')
        this.authorize(id, owner)
        return this.supervisor.resize(
          id,
          this.requiredBoundedInteger(payload, 'cols', 1000),
          this.requiredBoundedInteger(payload, 'rows', 1000)
        )
      }
      case 'wait': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'condition', 'timeoutSeconds'])
        const id = this.requiredString(payload, 'id')
        this.authorize(id, owner)
        return this.supervisor.wait(
          id,
          this.waitCondition(payload.condition),
          this.requiredPositiveInteger(payload, 'timeoutSeconds')
        )
      }
      case 'sendWait': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'data', 'condition', 'timeoutSeconds'])
        const id = this.requiredString(payload, 'id')
        const data = this.requiredString(payload, 'data')
        this.authorize(id, owner)
        this.useInput(owner, data)
        return this.supervisor.sendWait(
          id,
          data,
          this.waitCondition(payload.condition),
          this.requiredPositiveInteger(payload, 'timeoutSeconds')
        )
      }
      case 'read': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'offset', 'limit', 'sequence'])
        const id = this.requiredString(payload, 'id')
        this.authorize(id, owner)
        return this.supervisor.read(
          id,
          this.optionalNonnegativeInteger(payload, 'offset'),
          this.optionalNonnegativeInteger(payload, 'limit'),
          this.optionalSequence(payload, 'sequence')
        )
      }
      case 'search': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'pattern', 'ignoreCase', 'offset', 'limit', 'sequence'])
        const id = this.requiredString(payload, 'id')
        this.authorize(id, owner)
        return this.supervisor.search(
          id,
          this.requiredString(payload, 'pattern'),
          this.optionalBoolean(payload, 'ignoreCase') ?? false,
          this.optionalNonnegativeInteger(payload, 'offset'),
          this.optionalNonnegativeInteger(payload, 'limit'),
          this.optionalSequence(payload, 'sequence')
        )
      }
      case 'list':
        return (await this.supervisor.list()).filter((record) => this.owns(record.id, owner))
      case 'get':
        return this.get(request.payload, owner)
      case 'rawOutput':
        return this.rawOutput(request.payload, owner)
      case 'execOutput':
        return this.execOutput(request.payload, owner)
      case 'stop':
        return this.stopSession(request.payload, owner)
      case 'cleanup':
        return this.cleanup(request.payload, owner)
      case 'cleanupByParentSession':
        return this.cleanupByParentSession(request.payload, owner)
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

  private get(payload: unknown, owner: OwnerContext) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    const id = this.requiredString(value, 'id')
    this.authorize(id, owner)
    return this.supervisor.get(id)
  }

  private rawOutput(payload: unknown, owner: OwnerContext) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    const id = this.requiredString(value, 'id')
    this.authorize(id, owner)
    return this.supervisor.rawOutput(id)
  }

  private execOutput(payload: unknown, owner: OwnerContext) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    const id = this.requiredString(value, 'id')
    this.authorize(id, owner)
    return this.supervisor.execOutput(id)
  }

  private stopSession(payload: unknown, owner: OwnerContext) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    const id = this.requiredString(value, 'id')
    this.authorize(id, owner)
    return this.supervisor.stop(id)
  }

  private cleanup(payload: unknown, owner: OwnerContext) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['id'])
    const id = this.requiredString(value, 'id')
    this.authorize(id, owner)
    return this.supervisor.cleanup(id)
  }

  private cleanupByParentSession(payload: unknown, owner: OwnerContext) {
    const value = this.objectPayload(payload)
    this.onlyFields(value, ['parentSessionId'])
    const parentSessionId = this.requiredString(value, 'parentSessionId')
    if (parentSessionId !== owner.parentSessionId) throw new Error('Owner is not authorized.')
    return this.supervisor.cleanupByParentSession(
      parentSessionId,
      owner.projectDirectory,
      owner.capability
    )
  }

  private async spawn(
    options: Parameters<SessionSupervisor['spawn']>[0],
    owner: OwnerContext
  ): Promise<unknown> {
    return this.withSessionSlot(owner, () =>
      this.supervisor.spawn({
        ...options,
        parentSessionId: owner.parentSessionId,
        ownerProjectDirectory: owner.projectDirectory,
        ownerCapabilityHash: owner.capability,
      })
    )
  }

  private async exec(
    options: Parameters<SessionSupervisor['exec']>[0],
    owner: OwnerContext
  ): Promise<unknown> {
    if ((options.timeoutSeconds ?? 0) > MAX_EXEC_RUNTIME_SECONDS) {
      throw new Error('Exec runtime limit exceeded.')
    }
    return this.withSessionSlot(owner, () =>
      this.supervisor.nativeExec({
        ...options,
        parentSessionId: owner.parentSessionId,
        ownerProjectDirectory: owner.projectDirectory,
        ownerCapabilityHash: owner.capability,
      })
    )
  }

  private owner(request: RpcRequest): OwnerContext {
    const owner = request.owner
    if (
      !owner ||
      typeof owner.parentSessionId !== 'string' ||
      !owner.parentSessionId ||
      typeof owner.projectDirectory !== 'string' ||
      !owner.projectDirectory ||
      typeof owner.capability !== 'string' ||
      owner.capability.length !== 64
    ) {
      throw new ValidationError('A valid owner context is required.')
    }
    let projectDirectory: string
    try {
      projectDirectory = realpathSync(resolve(owner.projectDirectory))
    } catch {
      throw new ValidationError('Owner project directory must exist.')
    }
    if (owner.capability !== this.capability(owner.parentSessionId, projectDirectory)) {
      throw new Error('Owner is not authorized.')
    }
    return { ...owner, projectDirectory }
  }

  private authorize(id: string, owner: OwnerContext): void {
    if (!this.owns(id, owner)) throw new Error('Owner is not authorized.')
  }

  private owns(id: string, owner: OwnerContext): boolean {
    return this.supervisor.owns(id, owner.parentSessionId, owner.projectDirectory, owner.capability)
  }

  private capability(parentSessionId: string, projectDirectory: string): string {
    return new Bun.CryptoHasher('sha256')
      .update(`${this.ownershipSecret}\0${parentSessionId}\0${projectDirectory}`)
      .digest('hex')
  }

  private active(status: string): boolean {
    return status === 'starting' || status === 'running' || status === 'stopping'
  }

  private async withSessionSlot<T>(owner: OwnerContext, task: () => Promise<T>): Promise<T> {
    const key = `${owner.parentSessionId}\0${owner.projectDirectory}\0${owner.capability}`
    const pending = (this.pendingSessions.get(key) ?? 0) + 1
    if (pending > this.maxSessionsPerOwner) throw new Error('Session limit exceeded.')
    this.pendingSessions.set(key, pending)
    try {
      const owned = (await this.supervisor.list()).filter((session) => this.owns(session.id, owner))
      if (
        owned.filter((session) => this.active(session.status)).length + pending >
        this.maxSessionsPerOwner
      )
        throw new Error('Session limit exceeded.')
      return await task()
    } finally {
      if (pending === 1) this.pendingSessions.delete(key)
      else this.pendingSessions.set(key, pending - 1)
    }
  }

  private useInput(owner: OwnerContext, data: string): void {
    const bytes = Buffer.byteLength(data)
    if (bytes > MAX_INPUT_BYTES) throw new Error('Input size limit exceeded.')
    const now = Date.now()
    const key = `${owner.parentSessionId}\0${owner.projectDirectory}\0${owner.capability}`
    const usage = this.inputUsage.get(key)
    const current = !usage || now - usage.startedAt >= 60_000 ? { startedAt: now, bytes: 0 } : usage
    if (current.bytes + bytes > MAX_INPUT_BYTES_PER_MINUTE)
      throw new Error('Input rate limit exceeded.')
    current.bytes += bytes
    this.inputUsage.set(key, current)
  }

  private diagnostics(owner: OwnerContext): DaemonDiagnostics {
    if (!owner.parentSessionId) throw new Error('Owner is not authorized.')
    return {
      protocolVersion: DAEMON_PROTOCOL_VERSION,
      pid: process.pid,
      limits: {
        maxSessionsPerOwner: this.maxSessionsPerOwner,
        maxInputBytes: MAX_INPUT_BYTES,
        maxInputBytesPerMinute: MAX_INPUT_BYTES_PER_MINUTE,
        maxOutputBytes: effectiveMaxOutputBytes(),
        maxExecRuntimeSeconds: MAX_EXEC_RUNTIME_SECONDS,
      },
      environment: { inheritEnabled: true, defaultProfile: 'safe' },
      platform: {
        nativeContainment: process.platform === 'linux' || process.platform === 'win32',
        processTreeTermination: process.platform === 'linux' || process.platform === 'win32',
        ptyContainment: process.platform === 'linux' || process.platform === 'win32',
        containmentVerification:
          process.platform === 'linux'
            ? 'linux_proc'
            : process.platform === 'win32'
              ? 'windows_job'
              : 'unavailable',
      },
    }
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

  private requiredPositiveInteger(payload: Record<string, unknown>, key: string): number {
    const value = this.optionalNonnegativeInteger(payload, key)
    if (!value) throw new ValidationError(`RPC field '${key}' must be positive.`)
    return value
  }

  private requiredBoundedInteger(
    payload: Record<string, unknown>,
    key: string,
    maximum: number
  ): number {
    const value = payload[key]
    if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
      throw new ValidationError(`RPC field '${key}' must be an integer from 1 to ${maximum}.`)
    return value as number
  }

  private optionalSequence(payload: Record<string, unknown>, key: string): number | undefined {
    const value = payload[key]
    if (value === undefined) return undefined
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      throw new ValidationError(`RPC field '${key}' must be a non-negative safe integer.`)
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
      'inheritEnv',
      'lifecycle',
      'title',
      'parentSessionId',
      'parentAgent',
      'timeoutSeconds',
      'name',
      'idempotencyKey',
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
    const inheritEnv = this.optionalBoolean(value, 'inheritEnv')
    const lifecycle = this.optionalString(value, 'lifecycle')
    if (lifecycle !== undefined && lifecycle !== 'conversation' && lifecycle !== 'persistent') {
      throw new ValidationError("RPC field 'lifecycle' must be 'conversation' or 'persistent'.")
    }
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
      parentSessionId: this.optionalString(value, 'parentSessionId') ?? '',
      parentAgent: this.optionalString(value, 'parentAgent'),
      timeoutSeconds,
      name: this.optionalString(value, 'name'),
      idempotencyKey: this.optionalString(value, 'idempotencyKey'),
      inheritEnv,
      lifecycle,
    }
  }

  private execPayload(payload: unknown): Parameters<SessionSupervisor['exec']>[0] {
    const value = this.objectPayload(payload)
    this.onlyFields(value, [
      'command',
      'args',
      'description',
      'workdir',
      'env',
      'inheritEnv',
      'lifecycle',
      'title',
      'parentSessionId',
      'parentAgent',
      'timeoutSeconds',
      'maxOutputBytes',
    ])
    const { maxOutputBytes: ignoredMaxOutputBytes, ...spawnValue } = value
    const spawn = this.spawnPayload(spawnValue)
    const maxOutputBytes = this.optionalBoundedInteger(value, 'maxOutputBytes', MAX_REQUEST_BYTES)
    if (maxOutputBytes === 0)
      throw new ValidationError("RPC field 'maxOutputBytes' must be positive.")
    return { ...spawn, maxOutputBytes }
  }

  private waitCondition(
    value: unknown
  ): { kind: 'exit' } | { kind: 'output'; literal?: string; regex?: string } {
    const condition = this.objectPayload(value)
    const kind = this.requiredString(condition, 'kind')
    if (kind === 'exit') {
      this.onlyFields(condition, ['kind'])
      return { kind }
    }
    if (kind !== 'output')
      throw new ValidationError("wait condition kind must be 'output' or 'exit'.")
    this.onlyFields(condition, ['kind', 'literal', 'regex'])
    const literal = this.optionalString(condition, 'literal')
    const regex = this.optionalString(condition, 'regex')
    if (Boolean(literal) === Boolean(regex)) {
      throw new ValidationError('Output wait requires exactly one of literal or regex.')
    }
    return { kind, literal, regex }
  }

  private optionalBoundedInteger(
    payload: Record<string, unknown>,
    key: string,
    maximum: number
  ): number | undefined {
    const value = payload[key]
    if (value === undefined) return undefined
    if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > maximum) {
      throw new ValidationError(
        `RPC field '${key}' must be a non-negative integer within the size limit.`
      )
    }
    return value as number
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
    status: number,
    spawnFailure?: RpcFailure['error']['spawnFailure']
  ): Response {
    return Response.json(
      {
        id,
        ok: false,
        error: { code, message, ...(spawnFailure ? { spawnFailure } : {}) },
      } satisfies RpcFailure,
      { status }
    )
  }
}
