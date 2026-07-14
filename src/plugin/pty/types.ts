import type {
  ExecOutput,
  ContainmentReport,
  ExecutionMode,
  ExitReason,
  SessionLifecycle,
  WaitResult,
} from '../../daemon/types.ts'

export type PTYStatus =
  | 'starting'
  | 'running'
  | 'stopping'
  | 'exited'
  | 'timed_out'
  | 'lost'
  | 'spawn_failed'
  | 'output_limited'

export interface PTYSessionInfo {
  id: string
  title: string
  description?: string
  command: string
  args: string[]
  mode: ExecutionMode
  name?: string
  idempotencyKey?: string
  workdir: string
  status: PTYStatus
  timeoutSeconds?: number
  timedOut: boolean
  terminationRequested: boolean
  terminationConfirmed: boolean
  containment?: ContainmentReport
  termination?: import('../../daemon/types.ts').TerminationResult
  exitCode?: number
  exitSignal?: number | string
  exitReason?: ExitReason
  pid: number
  createdAt: string
  startedAt?: string
  exitedAt?: string
  lineCount: number
  outputSequence?: number
  firstRetainedSequence?: number
  outputTruncated?: boolean
  lastWaitResult?: WaitResult
  execOutput?: ExecOutput
  environment?: {
    kind: 'safe' | 'inherit'
    keys: string[]
    fingerprint: string
    sensitive: boolean
  }
}

export interface SpawnOptions {
  command: string
  args?: string[]
  workdir?: string
  env?: Record<string, string>
  inheritEnv?: boolean
  lifecycle?: SessionLifecycle
  title?: string
  description?: string
  parentSessionId: string
  parentAgent?: string
  timeoutSeconds?: number
  name?: string
  idempotencyKey?: string
  // Daemon-only fields are attached after authenticated owner validation.
  ownerProjectDirectory?: string
  ownerCapabilityHash?: string
}

export interface ReadResult {
  lines: string[]
  sequences: number[]
  totalLines: number
  offset: number
  hasMore: boolean
  firstRetainedSequence: number
  nextSequence: number
  truncated: boolean
  containment?: ContainmentReport
  termination?: import('../../daemon/types.ts').TerminationResult
}

export interface SearchResult {
  matches: Array<{ lineNumber: number; sequence: number; text: string }>
  totalMatches: number
  totalLines: number
  offset: number
  hasMore: boolean
  firstRetainedSequence: number
  nextSequence: number
  truncated: boolean
  containment?: ContainmentReport
  termination?: import('../../daemon/types.ts').TerminationResult
}
