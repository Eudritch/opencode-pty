import type { ExecutionMode, ExitReason, WaitResult } from '../../daemon/types.ts'

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
}

export interface SpawnOptions {
  command: string
  args?: string[]
  workdir?: string
  env?: Record<string, string>
  title?: string
  description?: string
  parentSessionId: string
  parentAgent?: string
  timeoutSeconds?: number
  name?: string
  idempotencyKey?: string
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
}
