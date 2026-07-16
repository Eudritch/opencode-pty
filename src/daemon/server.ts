import {
  DAEMON_PROTOCOL_VERSION,
  type DaemonDescriptor,
  type DaemonDiagnostics,
  type ApprovalLedger,
  type ApprovalPreparation,
  type ApprovalClaim,
  type ApprovalRequest,
  type OwnerContext,
  type RpcFailure,
  type RpcRequest,
  type RpcResponse,
  MAX_EXEC_RUNTIME_SECONDS,
} from './types.ts'
import type { DaemonStorage } from './storage.ts'
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
const MAX_APPROVAL_EXPIRY_SECONDS = 3600
const MAX_SESSION_GRANT_SECONDS = 24 * 60 * 60
const CLAIM_LEASE_MS = 30_000

class ValidationError extends Error {}

export class DaemonServer implements Disposable {
  private server: ReturnType<typeof Bun.serve> | null = null
  private readonly inputUsage = new Map<string, { startedAt: number; bytes: number }>()
  private readonly pendingSessions = new Map<string, number>()
  private approvalWrites: Promise<void> = Promise.resolve()
  private readonly approvalClaimTokens = new Map<string, string>()
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
      await this.supervisor.initialize(false)
      this.ownershipSecret = await this.storage.ownershipSecret()
      this.processIdentity = await this.storage.requiredCurrentProcessStartIdentity(deadline)
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
      void this.supervisor
        .reconcileWorkers()
        .catch((error) => console.warn(`PTY daemon session recovery failed: ${String(error)}`))
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
      case 'execStart':
        return this.execStart(this.execPayload(request.payload), owner)
      case 'execWait': {
        const payload = this.objectPayload(request.payload)
        this.onlyFields(payload, ['id', 'timeoutSeconds'])
        const id = this.requiredString(payload, 'id')
        this.authorize(id, owner)
        return this.supervisor.nativeExecWait(
          id,
          this.requiredPositiveInteger(payload, 'timeoutSeconds')
        )
      }
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
      case 'approvalCreate':
        this.approvalOwner(request)
        return this.approvalCreate(request.payload, owner)
      case 'approvalPrepare':
        this.approvalOwner(request)
        return this.approvalPrepare(request.payload, owner)
      case 'approvalClaim':
        this.approvalOwner(request)
        return this.approvalClaim(request.payload, owner)
      case 'approvalDecide':
        this.approvalOwner(request)
        return this.approvalDecide(request.payload, owner)
      case 'approvalWait':
        this.approvalOwner(request)
        return this.approvalWait(request.payload, owner)
      case 'approvalConsume':
        this.approvalOwner(request)
        return this.approvalConsume(request.payload, owner)
      case 'approvalNativeApprove':
        this.approvalOwner(request)
        return this.approvalNativeApprove(request.payload, owner)
      case 'approvalListGrants':
        this.approvalOwner(request)
        return this.approvalListGrants(owner)
      case 'approvalListRequests':
        this.approvalOwner(request)
        return this.approvalListRequests(owner)
      case 'approvalRevokeGrant':
        this.approvalOwner(request)
        return this.approvalRevokeGrant(request.payload, owner)
      case 'approvalCancel':
        this.approvalOwner(request)
        return this.approvalCancel(request.payload, owner)
      case 'approvalCleanupByParentSession':
        this.approvalOwner(request)
        return this.approvalCleanupByParentSession(request.payload, owner)
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

  private approvalOwner(request: RpcRequest): OwnerContext {
    const owner = this.owner(request)
    if (
      typeof request.approvalCapability !== 'string' ||
      request.approvalCapability.length !== 64 ||
      request.approvalCapability !==
        this.approvalCapability(owner.parentSessionId, owner.projectDirectory)
    ) {
      throw new Error('Owner is not authorized.')
    }
    return owner
  }

  private approvalPayload(payload: unknown, fields: string[]): Record<string, unknown> {
    const value = this.objectPayload(payload)
    this.onlyFields(value, fields)
    return value
  }

  private async approvalCreate(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, [
      'command',
      'reason',
      'capability',
      'workdir',
      'expirySeconds',
    ])
    const expirySeconds = this.requiredPositiveInteger(value, 'expirySeconds')
    if (expirySeconds > MAX_APPROVAL_EXPIRY_SECONDS)
      throw new ValidationError('Approval expiry exceeds the limit.')
    const intent = this.approvalIntent(value)
    return this.withApprovals(async (ledger) => {
      const now = new Date()
      const request: ApprovalRequest = {
        id: crypto.randomUUID(),
        parentSessionId: owner.parentSessionId,
        projectDirectory: owner.projectDirectory,
        digest: this.approvalDigest(intent),
        ...intent,
        status: 'pending',
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + expirySeconds * 1000).toISOString(),
      }
      ledger.requests.push(request)
      return request
    })
  }

  private async approvalPrepare(
    payload: unknown,
    owner: OwnerContext
  ): Promise<ApprovalPreparation> {
    const value = this.approvalPayload(payload, [
      'command',
      'reason',
      'capability',
      'workdir',
      'expirySeconds',
    ])
    const expirySeconds = this.requiredPositiveInteger(value, 'expirySeconds')
    if (expirySeconds > MAX_APPROVAL_EXPIRY_SECONDS)
      throw new ValidationError('Approval expiry exceeds the limit.')
    const intent = this.approvalIntent(value)
    return this.withApprovals(async (ledger) => {
      const now = new Date()
      const digest = this.approvalDigest(intent)
      ledger.grants = ledger.grants.filter((grant) => Date.parse(grant.expiresAt) > now.getTime())
      if (
        ledger.grants.some(
          (grant) =>
            grant.parentSessionId === owner.parentSessionId &&
            grant.projectDirectory === owner.projectDirectory &&
            grant.digest === digest &&
            grant.capability === intent.capability &&
            grant.workdir === intent.workdir
        )
      )
        return { status: 'approved_session' }
      const request: ApprovalRequest = {
        id: crypto.randomUUID(),
        parentSessionId: owner.parentSessionId,
        projectDirectory: owner.projectDirectory,
        digest,
        ...intent,
        status: 'pending',
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + expirySeconds * 1000).toISOString(),
      }
      ledger.requests.push(request)
      return request
    })
  }

  private async approvalClaim(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, ['id'])
    const claimed = await this.withApprovals(async (ledger) => {
      const request = this.approvalOwned(ledger, owner, this.requiredString(value, 'id'))
      this.refreshApproval(request)
      let claimToken: string | undefined
      if (request.status === 'pending' || request.status === 'native_fallback') {
        request.status = 'claimed'
        request.claimExpiresAt = new Date(Date.now() + CLAIM_LEASE_MS).toISOString()
        request.updatedAt = new Date().toISOString()
        claimToken = crypto.randomUUID().replaceAll('-', '')
      }
      return { request, claimToken }
    })
    if (!claimed.claimToken) return claimed.request
    this.approvalClaimTokens.set(claimed.request.id, claimed.claimToken)
    return { request: claimed.request, claimToken: claimed.claimToken } satisfies ApprovalClaim
  }

  private async approvalDecide(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, ['id', 'decision', 'claimToken'])
    const decision = this.requiredString(value, 'decision')
    if (!['approve_once', 'approve_session', 'reject'].includes(decision))
      throw new ValidationError('Approval decision is invalid.')
    const result = await this.withApprovals(async (ledger) => {
      const request = this.approvalOwned(ledger, owner, this.requiredString(value, 'id'))
      this.refreshApproval(request)
      if (this.approvalClaimTokens.get(request.id) !== this.requiredString(value, 'claimToken')) {
        throw new Error('Approval claim token is not authorized.')
      }
      if (request.status !== 'claimed') return request
      request.status =
        decision === 'approve_once'
          ? 'approved_once'
          : decision === 'approve_session'
            ? 'approved_session'
            : 'rejected'
      request.claimExpiresAt = undefined
      request.updatedAt = new Date().toISOString()
      if (request.status === 'approved_session') {
        ledger.grants.push({
          id: crypto.randomUUID(),
          parentSessionId: owner.parentSessionId,
          projectDirectory: owner.projectDirectory,
          digest: request.digest,
          capability: request.capability,
          workdir: request.workdir,
          createdAt: request.updatedAt,
          expiresAt: new Date(Date.now() + MAX_SESSION_GRANT_SECONDS * 1000).toISOString(),
        })
      }
      return request
    })
    if (result.status !== 'claimed') this.approvalClaimTokens.delete(result.id)
    return result
  }

  private async approvalWait(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, ['id', 'timeoutSeconds'])
    const id = this.requiredString(value, 'id')
    const deadline = Date.now() + this.requiredPositiveInteger(value, 'timeoutSeconds') * 1000
    if (deadline - Date.now() > MAX_APPROVAL_EXPIRY_SECONDS * 1000)
      throw new ValidationError('Approval wait exceeds the limit.')
    for (;;) {
      const request = await this.approvalStatus(id, owner)
      if (
        !['pending', 'claimed', 'native_fallback'].includes(request.status) ||
        Date.now() >= deadline
      )
        return request
      await Bun.sleep(Math.min(25, deadline - Date.now()))
    }
  }

  private async approvalConsume(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, [
      'id',
      'command',
      'reason',
      'capability',
      'workdir',
    ])
    const intent = this.approvalIntent(value)
    return this.withApprovals(async (ledger) => {
      const request = this.approvalOwned(ledger, owner, this.requiredString(value, 'id'))
      this.refreshApproval(request)
      if (request.digest !== this.approvalDigest(intent))
        throw new Error('Approval is not authorized.')
      if (['rejected', 'cancelled', 'expired'].includes(request.status)) return request
      if (request.status === 'approved_once') {
        request.status = 'consumed'
        request.updatedAt = new Date().toISOString()
        return request
      }
      if (request.status === 'consumed')
        throw new ValidationError('Approval has already been consumed.')
      if (
        ledger.grants.some(
          (grant) =>
            grant.parentSessionId === owner.parentSessionId &&
            grant.projectDirectory === owner.projectDirectory &&
            grant.digest === request.digest &&
            grant.capability === request.capability &&
            grant.workdir === request.workdir &&
            Date.parse(grant.expiresAt) > Date.now()
        )
      ) {
        return { ...request, status: 'approved_session' as const }
      }
      return { ...request, status: 'rejected' as const }
    })
  }

  private async approvalNativeApprove(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, ['id'])
    return this.withApprovals(async (ledger) => {
      const request = this.approvalOwned(ledger, owner, this.requiredString(value, 'id'))
      this.refreshApproval(request)
      if (request.status === 'pending' || request.status === 'native_fallback') {
        request.status = 'approved_once'
        request.updatedAt = new Date().toISOString()
      }
      return request
    })
  }

  private async approvalListGrants(owner: OwnerContext) {
    return this.withApprovals(async (ledger) => {
      ledger.grants = ledger.grants.filter((grant) => Date.parse(grant.expiresAt) > Date.now())
      return ledger.grants.filter(
        (grant) =>
          grant.parentSessionId === owner.parentSessionId &&
          grant.projectDirectory === owner.projectDirectory
      )
    })
  }

  private async approvalListRequests(owner: OwnerContext) {
    return this.withApprovals(async (ledger) => {
      for (const request of ledger.requests) this.refreshApproval(request)
      return ledger.requests.filter(
        (request) =>
          request.parentSessionId === owner.parentSessionId &&
          request.projectDirectory === owner.projectDirectory
      )
    })
  }

  private async approvalRevokeGrant(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, ['id'])
    const id = this.requiredString(value, 'id')
    return this.withApprovals(async (ledger) => {
      const index = ledger.grants.findIndex(
        (grant) =>
          grant.id === id &&
          grant.parentSessionId === owner.parentSessionId &&
          grant.projectDirectory === owner.projectDirectory
      )
      if (index < 0) throw new Error('Approval grant not found.')
      ledger.grants.splice(index, 1)
      return true
    })
  }

  private async approvalCancel(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, ['id'])
    return this.withApprovals(async (ledger) => {
      const request = this.approvalOwned(ledger, owner, this.requiredString(value, 'id'))
      this.refreshApproval(request)
      if (['pending', 'claimed', 'native_fallback'].includes(request.status)) {
        request.status = 'cancelled'
        request.claimExpiresAt = undefined
        this.approvalClaimTokens.delete(request.id)
        request.updatedAt = new Date().toISOString()
      }
      return request
    })
  }

  private async approvalCleanupByParentSession(payload: unknown, owner: OwnerContext) {
    const value = this.approvalPayload(payload, ['parentSessionId'])
    if (this.requiredString(value, 'parentSessionId') !== owner.parentSessionId)
      throw new Error('Owner is not authorized.')
    await this.withApprovals(async (ledger) => {
      for (const request of ledger.requests) {
        if (
          request.parentSessionId === owner.parentSessionId &&
          request.projectDirectory === owner.projectDirectory
        )
          this.approvalClaimTokens.delete(request.id)
      }
      ledger.requests = ledger.requests.filter(
        (request) =>
          request.parentSessionId !== owner.parentSessionId ||
          request.projectDirectory !== owner.projectDirectory
      )
      ledger.grants = ledger.grants.filter(
        (grant) =>
          grant.parentSessionId !== owner.parentSessionId ||
          grant.projectDirectory !== owner.projectDirectory
      )
    })
  }

  private async approvalStatus(id: string, owner: OwnerContext) {
    return this.withApprovals(async (ledger) => {
      const request = this.approvalOwned(ledger, owner, id)
      this.refreshApproval(request)
      return request
    })
  }

  private approvalOwned(ledger: ApprovalLedger, owner: OwnerContext, id: string): ApprovalRequest {
    const request = ledger.requests.find((entry) => entry.id === id)
    if (!request) throw new Error('Approval request not found.')
    if (
      request.parentSessionId !== owner.parentSessionId ||
      request.projectDirectory !== owner.projectDirectory
    )
      throw new Error('Owner is not authorized.')
    return request
  }

  private refreshApproval(request: ApprovalRequest): void {
    if (
      ['pending', 'claimed', 'native_fallback'].includes(request.status) &&
      Date.parse(request.expiresAt) <= Date.now()
    ) {
      request.status = 'expired'
      request.claimExpiresAt = undefined
      this.approvalClaimTokens.delete(request.id)
      request.updatedAt = new Date().toISOString()
    } else if (
      request.status === 'claimed' &&
      Date.parse(request.claimExpiresAt ?? '') <= Date.now()
    ) {
      request.status = 'native_fallback'
      request.claimExpiresAt = undefined
      this.approvalClaimTokens.delete(request.id)
      request.updatedAt = new Date().toISOString()
    }
  }

  private approvalIntent(
    payload: Record<string, unknown>
  ): Pick<ApprovalRequest, 'command' | 'reason' | 'capability' | 'workdir'> {
    const command = this.approvalText(payload, 'command', MAX_COMMAND_LENGTH)
    const capability = this.approvalText(payload, 'capability', 1024)
    const workdir = this.canonicalApprovalWorkdir(
      this.approvalText(payload, 'workdir', MAX_STRING_LENGTH)
    )
    const reason = this.approvalText(payload, 'reason', MAX_STRING_LENGTH, true)
    return { command, capability, workdir, ...(reason === undefined ? {} : { reason }) }
  }

  private approvalText(payload: Record<string, unknown>, key: string, maximum: number): string
  private approvalText(
    payload: Record<string, unknown>,
    key: string,
    maximum: number,
    optional: true
  ): string | undefined
  private approvalText(
    payload: Record<string, unknown>,
    key: string,
    maximum: number,
    optional = false
  ): string | undefined {
    if (optional && payload[key] === undefined) return undefined
    const value = this.requiredString(payload, key).normalize('NFC')
    if (value.length > maximum || value.includes('\0'))
      throw new ValidationError(`RPC field '${key}' is invalid for approval intent.`)
    return value
  }

  private canonicalApprovalWorkdir(workdir: string): string {
    try {
      return realpathSync(resolve(workdir))
    } catch {
      throw new ValidationError('Approval workdir must exist.')
    }
  }

  private approvalDigest(
    intent: Pick<ApprovalRequest, 'command' | 'reason' | 'capability' | 'workdir'>
  ): string {
    return new Bun.CryptoHasher('sha256').update(JSON.stringify(intent)).digest('hex')
  }

  private async withApprovals<T>(update: (ledger: ApprovalLedger) => Promise<T>): Promise<T> {
    let release!: () => void
    const previous = this.approvalWrites
    this.approvalWrites = new Promise<void>((resolve) => {
      release = resolve
    })
    await previous
    try {
      const ledger = await this.storage.readApprovals()
      const result = await update(ledger)
      await this.storage.writeApprovals(ledger)
      return result
    } finally {
      release()
    }
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

  private async execStart(
    options: Parameters<SessionSupervisor['nativeExecStart']>[0],
    owner: OwnerContext
  ): Promise<unknown> {
    if ((options.timeoutSeconds ?? 0) > MAX_EXEC_RUNTIME_SECONDS) {
      throw new Error('Exec runtime limit exceeded.')
    }
    return this.withSessionSlot(owner, () =>
      this.supervisor.nativeExecStart({
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

  private approvalCapability(parentSessionId: string, projectDirectory: string): string {
    return new Bun.CryptoHasher('sha256')
      .update(`approval\0${this.ownershipSecret}\0${parentSessionId}\0${projectDirectory}`)
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
