export const DAEMON_PROTOCOL_VERSION = 3

export const OUTPUT_JOURNAL_VERSION = 2

export type ExitReason =
  | { kind: 'code'; code: number }
  | { kind: 'signal'; signal: string }
  | { kind: 'timeout'; message?: string }
  | { kind: 'spawn_error'; message: string }
  | { kind: 'output_limit'; message?: string }
  | { kind: 'unknown' }

export type DaemonStatus =
  | 'starting'
  | 'running'
  | 'stopping'
  | 'exited'
  | 'timed_out'
  | 'lost'
  | 'spawn_failed'
  | 'output_limited'

export type ExecutionMode = 'pty' | 'exec'

export type SessionLifecycle = 'conversation' | 'persistent'

export interface OwnerContext {
  parentSessionId: string
  projectDirectory: string
  capability: string
}

export interface EnvironmentProfile {
  kind: 'safe' | 'inherit'
  keys: string[]
  fingerprint: string
  sensitive: boolean
}

export type WaitCondition =
  | { kind: 'exit' }
  | { kind: 'output'; literal?: string; regex?: string; afterSequence?: number }

export interface WaitResult {
  satisfied: boolean
  reason: 'output' | 'exit' | 'deadline'
  observedAt: string
  matched?: string
  exitCode?: number
  exitSignal?: number | string
  outputTruncated: boolean
}

export interface ExecResult {
  session: { id: string; status: DaemonStatus; mode: 'exec'; pid: number }
  stdout: string
  stderr: string
  exitCode?: number
  exitSignal?: number | string
  timedOut: boolean
  outputLimited: boolean
  terminationConfirmed: boolean
  startedAt: string
  exitedAt: string
}

export interface ExecOutput {
  stdout: string
  stderr: string
  stdoutBytes: number
  stderrBytes: number
  stdoutTruncated: boolean
  stderrTruncated: boolean
}

export interface WorkerReference {
  pid: number
  startIdentity: string
  endpoint: string
  protocolVersion: number
}

export interface SessionRecord {
  id: string
  title: string
  description?: string
  command: string
  args: string[]
  mode: ExecutionMode
  name?: string
  idempotencyKey?: string
  workdir: string
  ownerProjectDirectory: string
  ownerCapabilityHash: string
  lifecycle: SessionLifecycle
  environment: EnvironmentProfile
  status: DaemonStatus
  pid: number
  createdAt: string
  startedAt?: string
  exitedAt?: string
  lastOutputAt?: string
  updatedAt: string
  parentSessionId: string
  parentAgent?: string
  timeoutSeconds?: number
  timedOut: boolean
  terminationRequested: boolean
  terminationConfirmed: boolean
  exitCode?: number
  exitSignal?: number | string
  exitReason?: ExitReason
  nextSequence: number
  firstRetainedSequence: number
  outputBytes: number
  outputTruncated: boolean
  lineCount: number
  outputHasPartialLine: boolean
  outputJournalVersion: typeof OUTPUT_JOURNAL_VERSION
  execOutput?: ExecOutput
  worker?: WorkerReference
  lastWaitResult?: WaitResult
}

export interface OutputChunk {
  startSequence: number
  endSequence: number
  timestamp: string
  data: string
}

export interface DaemonDescriptor {
  pid: number
  endpoint: string
  protocolVersion: number
  token: string
}

export interface DaemonLaunchOptions {
  readonly dataDirectory?: string
  readonly token?: string
}

export interface RpcRequest {
  id: string
  version: number
  operation: string
  owner?: OwnerContext
  payload?: unknown
}

export interface RpcSuccess<T> {
  id: string
  ok: true
  result: T
}

export interface RpcFailure {
  id: string
  ok: false
  error: {
    code:
      | 'authentication'
      | 'validation'
      | 'not_found'
      | 'session_closed'
      | 'process'
      | 'storage'
      | 'internal'
      | 'protocol'
      | 'authorization'
      | 'limit'
    message: string
  }
}

export type RpcResponse<T> = RpcSuccess<T> | RpcFailure

export interface WriteResult {
  acceptedBytes: number
  acceptedCharacters: number
}

export interface StopResult {
  requested: boolean
  terminationConfirmed: boolean
}

export interface DaemonDiagnostics {
  protocolVersion: number
  pid: number
  limits: {
    maxSessionsPerOwner: number
    maxInputBytes: number
    maxInputBytesPerMinute: number
    maxOutputBytes: number
    maxExecRuntimeSeconds: number
  }
  environment: { inheritEnabled: boolean; defaultProfile: 'safe' }
  platform: { nativeContainment: false; processTreeTermination: false }
}
