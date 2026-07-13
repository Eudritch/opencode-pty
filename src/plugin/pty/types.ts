import type { ExitReason } from '../../daemon/types.ts'

export type PTYStatus =
  | 'starting'
  | 'running'
  | 'stopping'
  | 'exited'
  | 'timed_out'
  | 'lost'
  | 'spawn_failed'

export interface PTYSessionInfo {
  id: string
  title: string
  description?: string
  command: string
  args: string[]
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
  lineCount: number
  outputSequence?: number
  firstRetainedSequence?: number
  outputTruncated?: boolean
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
