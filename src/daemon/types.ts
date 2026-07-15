export const DAEMON_PROTOCOL_VERSION = 4

export const OUTPUT_JOURNAL_VERSION = 2

export type ExitReason =
  | { kind: 'code'; code: number }
  | { kind: 'signal'; signal: string }
  | { kind: 'timeout'; message?: string }
  | { kind: 'stopped' }
  | { kind: 'spawn_error'; message: string; cleanup?: SpawnCleanup }
  | { kind: 'output_limit'; message?: string }
  | { kind: 'unknown'; message?: string }

export type DaemonStatus =
  | 'starting'
  | 'running'
  | 'stopping'
  | 'exited'
  | 'timed_out'
  | 'lost'
  | 'spawn_failed'
  | 'output_limited'

export interface SpawnCleanup {
  requested: boolean
  terminationConfirmed: boolean
  method: 'shutdown' | 'rollback' | 'kill' | 'none'
  directChildStarted?: boolean
  directChildPid?: number
  message?: string
}

export interface SpawnFailure {
  cleanup: SpawnCleanup
}

export interface ContainmentReport {
  platform: 'linux_proc' | 'windows_job' | 'posix_verification_unavailable' | 'not_applicable'
  status:
    | 'posix_best_effort_empty'
    | 'posix_processes_remaining'
    | 'posix_escape_observed'
    | 'posix_containment_unknown'
    | 'windows_job_empty'
    | 'windows_job_processes_remaining'
    | 'windows_job_unknown'
    | 'not_applicable'
  rootPid: number
  processGroupId?: number
  sessionId?: number
  rootStartIdentity: string
  rootIdentityVerified: boolean
  observedGroupPids: number[]
  observedSessionPids: number[]
  observedEscapedDescendantPids: number[]
  observedEscapedDescendants?: Array<{ pid: number; startIdentity: string }>
  verifiedAt: string
}

export interface TerminationResult {
  requested: boolean
  termSignalSent: boolean
  killSignalSent: boolean
  rootExited: boolean
  directChildExited: boolean
  containment: ContainmentReport
}

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
  containment?: ContainmentReport
  termination?: TerminationResult
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
  containment?: ContainmentReport
  termination?: TerminationResult
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
  containment?: ContainmentReport
  termination?: TerminationResult
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
  pendingCleanup?: boolean
  // Direct-child exit is distinct from descendant containment drain on POSIX.
  directChildExited?: boolean
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
  containment?: ContainmentReport
  termination?: TerminationResult
  storageFailure?: string
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
  processIdentity: string
  endpoint: string
  protocolVersion: number
  token: string
}

export interface DaemonLaunchOptions {
  readonly dataDirectory?: string
  readonly token?: string
  readonly startLockHandoffToken?: string
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
    spawnFailure?: SpawnFailure
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
  directChildExited?: boolean
  containment?: ContainmentReport
  termination?: TerminationResult
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
  platform: {
    nativeContainment: boolean
    processTreeTermination: boolean
    ptyContainment: boolean
    containmentVerification: 'linux_proc' | 'windows_job' | 'unavailable'
  }
}
