export const DAEMON_PROTOCOL_VERSION = 1

export const OUTPUT_JOURNAL_VERSION = 2

export type ExitReason =
  | { kind: 'code'; code: number }
  | { kind: 'signal'; signal: string }
  | { kind: 'timeout'; message?: string }
  | { kind: 'spawn_error'; message: string }
  | { kind: 'unknown' }

export type DaemonStatus =
  | 'starting'
  | 'running'
  | 'stopping'
  | 'exited'
  | 'timed_out'
  | 'lost'
  | 'spawn_failed'

export interface SessionRecord {
  id: string
  title: string
  description?: string
  command: string
  args: string[]
  workdir: string
  env?: Record<string, string>
  status: DaemonStatus
  pid: number
  createdAt: string
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
