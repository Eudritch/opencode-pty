export const DEFAULT_MAX_SESSIONS_PER_OWNER = 32
export const MAX_ACTIVE_SESSIONS = 64
export const MAX_RECORDS_PER_OWNER = 64
export const MAX_RECORDS = 128
export const MAX_PENDING_WAITS_PER_SESSION = 8
export const MAX_PENDING_WAITS_PER_OWNER = 32
export const MAX_PENDING_WAITS = 128
export const MAX_QUEUED_INPUT_BYTES_PER_SESSION = 64 * 1024
export const MAX_QUEUED_INPUT_BYTES_PER_OWNER = 256 * 1024
export const MAX_QUEUED_INPUT_BYTES = 1024 * 1024
export const DEFAULT_MAX_OUTPUT_BYTES = 1000000
export const MAX_OUTPUT_BYTES = 64 * 1024 * 1024
export const MAX_RETAINED_OUTPUT_BYTES_PER_OWNER = 64 * 1024 * 1024
export const MAX_RETAINED_OUTPUT_BYTES = 128 * 1024 * 1024
export const TERMINAL_RETENTION_SECONDS = 24 * 60 * 60

export interface SessionLimits {
  maxActiveSessions: number
  maxRecordsPerOwner: number
  maxRecords: number
  maxPendingWaitsPerSession: number
  maxPendingWaitsPerOwner: number
  maxPendingWaits: number
  maxQueuedInputBytesPerSession: number
  maxQueuedInputBytesPerOwner: number
  maxQueuedInputBytes: number
  maxRetainedOutputBytesPerOwner: number
  maxRetainedOutputBytes: number
  terminalRetentionSeconds: number
}

export const DEFAULT_SESSION_LIMITS: SessionLimits = {
  maxActiveSessions: MAX_ACTIVE_SESSIONS,
  maxRecordsPerOwner: MAX_RECORDS_PER_OWNER,
  maxRecords: MAX_RECORDS,
  maxPendingWaitsPerSession: MAX_PENDING_WAITS_PER_SESSION,
  maxPendingWaitsPerOwner: MAX_PENDING_WAITS_PER_OWNER,
  maxPendingWaits: MAX_PENDING_WAITS,
  maxQueuedInputBytesPerSession: MAX_QUEUED_INPUT_BYTES_PER_SESSION,
  maxQueuedInputBytesPerOwner: MAX_QUEUED_INPUT_BYTES_PER_OWNER,
  maxQueuedInputBytes: MAX_QUEUED_INPUT_BYTES,
  maxRetainedOutputBytesPerOwner: MAX_RETAINED_OUTPUT_BYTES_PER_OWNER,
  maxRetainedOutputBytes: MAX_RETAINED_OUTPUT_BYTES,
  terminalRetentionSeconds: TERMINAL_RETENTION_SECONDS,
}

export function effectiveMaxOutputBytes(value = process.env.PTY_MAX_OUTPUT_BYTES): number {
  const parsed = Number.parseInt(value ?? '', 10)
  return Number.isSafeInteger(parsed) && parsed > 0
    ? Math.min(parsed, MAX_OUTPUT_BYTES)
    : DEFAULT_MAX_OUTPUT_BYTES
}
