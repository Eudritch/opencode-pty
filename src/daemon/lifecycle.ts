import type {
  DaemonStatus,
  LegacyTombstone,
  SessionRecord,
  SessionState,
  SessionStateEvidence,
  TerminalSessionOutcome,
  TerminalSessionPayload,
} from './types.ts'

export type LifecycleEvent =
  | 'worker_ready'
  | 'stop_requested'
  | 'child_exited'
  | 'timed_out'
  | 'output_limited'
  | 'spawn_failed'
  | 'unreachable'
  | 'recovered'

export type LifecycleReduction =
  | { ok: true; status: DaemonStatus }
  | { ok: false; error: 'invalid_transition' }

export type SessionStateReduction =
  | { ok: true; state: SessionState }
  | { ok: false; error: 'invalid_transition' }

type LifecycleProjection = Pick<
  SessionRecord,
  | 'status'
  | 'pid'
  | 'startedAt'
  | 'exitedAt'
  | 'timedOut'
  | 'terminationRequested'
  | 'terminationConfirmed'
  | 'pendingCleanup'
  | 'directChildExited'
  | 'exitCode'
  | 'exitSignal'
  | 'exitReason'
  | 'worker'
  | 'workerPrestart'
  | 'workerStartAttempted'
  | 'containment'
  | 'termination'
  | 'execOutput'
  | 'storageFailure'
  | 'diagnostics'
  | 'lastWaitResult'
  | 'legacyTombstone'
  | 'legacyOutputCleanupPending'
  | 'streamDrain'
  | 'lastKnown'
>

function evidenceFromState(state: SessionState): SessionStateEvidence {
  const value = { ...state } as Record<string, unknown>
  delete value.kind
  delete value.target
  delete value.outcome
  delete value.lastKnown
  delete value.terminal
  return value as unknown as SessionStateEvidence
}

function terminalPayload(state: SessionState): TerminalSessionPayload | undefined {
  if (state.kind === 'terminal')
    return { outcome: state.outcome, evidence: evidenceFromState(state) }
  if (state.kind === 'cleaning' && state.target === 'terminal' && state.outcome)
    return { outcome: state.outcome, evidence: evidenceFromState(state) }
  if (state.kind === 'unreachable' || state.kind === 'cleaning') return state.terminal
  return undefined
}

function lastKnown(state: SessionState): LegacyTombstone['lastKnown'] {
  if (state.kind === 'cleaning')
    return state.target === 'unreachable' ? (state.lastKnown ?? 'unreachable') : state.target
  return state.kind
}

function terminalProven(state: SessionState): boolean {
  const cleanup = state.exitReason?.kind === 'spawn_error' ? state.exitReason.cleanup : undefined
  if (
    state.kind === 'terminal' &&
    state.outcome === 'spawn_failed' &&
    cleanup?.directChildStarted === false &&
    cleanup.terminationConfirmed
  ) {
    return true
  }
  return Boolean(
    state.termination.confirmed &&
      state.child.directExited === true &&
      (state.containment?.status === 'posix_best_effort_empty' ||
        state.containment?.status === 'windows_job_empty' ||
        state.containment?.status === 'not_applicable' ||
        process.platform === 'darwin')
  )
}

function terminalOrUnreachable(
  state: SessionState,
  outcome: TerminalSessionOutcome,
  cleaning: boolean
): SessionState {
  const terminal = { ...evidenceFromState(state), kind: 'terminal', outcome } as SessionState
  if (terminalProven(terminal)) {
    return cleaning
      ? { ...evidenceFromState(terminal), kind: 'cleaning', target: 'terminal', outcome }
      : terminal
  }
  const payload: TerminalSessionPayload = { outcome, evidence: evidenceFromState(terminal) }
  return cleaning
    ? {
        ...evidenceFromState(state),
        kind: 'cleaning',
        target: 'unreachable',
        lastKnown: 'terminal',
        terminal: payload,
      }
    : { ...evidenceFromState(state), kind: 'unreachable', lastKnown: 'terminal', terminal: payload }
}

function unreachable(state: SessionState, cleaning = false): SessionState {
  const terminal = terminalPayload(state)
  const known = terminal ? 'terminal' : lastKnown(state)
  const base = { ...evidenceFromState(state), lastKnown: known, ...(terminal ? { terminal } : {}) }
  return cleaning
    ? { ...base, kind: 'cleaning', target: 'unreachable' }
    : { ...base, kind: 'unreachable' }
}

function cleaning(state: SessionState): SessionState {
  if (state.kind === 'cleaning') return state
  if (state.kind === 'terminal')
    return {
      ...evidenceFromState(state),
      kind: 'cleaning',
      target: 'terminal',
      outcome: state.outcome,
    }
  if (state.kind === 'unreachable')
    return {
      ...evidenceFromState(state),
      kind: 'cleaning',
      target: 'unreachable',
      lastKnown: state.lastKnown,
      ...(state.terminal ? { terminal: state.terminal } : {}),
    }
  return { ...evidenceFromState(state), kind: 'cleaning', target: state.kind }
}

function terminalEvent(event: LifecycleEvent): TerminalSessionOutcome | undefined {
  if (event === 'child_exited') return 'exited'
  if (event === 'timed_out') return 'timed_out'
  if (event === 'output_limited') return 'output_limited'
  if (event === 'spawn_failed') return 'spawn_failed'
  return undefined
}

export function reduceSessionState(
  current: SessionState,
  event: LifecycleEvent
): SessionStateReduction {
  if (event === 'unreachable')
    return { ok: true, state: unreachable(current, current.kind === 'cleaning') }

  if (current.kind === 'unreachable') {
    if (
      event === 'recovered' &&
      current.lastKnown !== 'terminal' &&
      current.lastKnown !== 'unreachable'
    ) {
      return { ok: true, state: { ...evidenceFromState(current), kind: 'running' } }
    }
    return { ok: false, error: 'invalid_transition' }
  }

  if (current.kind === 'cleaning') {
    const outcome = terminalEvent(event)
    if (outcome && current.target !== 'terminal' && current.target !== 'unreachable')
      return { ok: true, state: terminalOrUnreachable(current, outcome, true) }
    if (
      event === 'stop_requested' &&
      (current.target === 'running' || current.target === 'stopping')
    )
      return {
        ok: true,
        state: { ...evidenceFromState(current), kind: 'cleaning', target: 'stopping' },
      }
    return { ok: false, error: 'invalid_transition' }
  }

  if (current.kind === 'creating') {
    if (event === 'worker_ready')
      return { ok: true, state: { ...evidenceFromState(current), kind: 'running' } }
    if (event === 'spawn_failed')
      return { ok: true, state: terminalOrUnreachable(current, 'spawn_failed', false) }
    return { ok: false, error: 'invalid_transition' }
  }

  if (current.kind === 'running' || current.kind === 'stopping') {
    if (event === 'worker_ready' && current.kind === 'running') return { ok: true, state: current }
    if (event === 'stop_requested')
      return { ok: true, state: { ...evidenceFromState(current), kind: 'stopping' } }
    const outcome = terminalEvent(event)
    if (outcome) return { ok: true, state: terminalOrUnreachable(current, outcome, false) }
    return { ok: false, error: 'invalid_transition' }
  }

  if (current.kind === 'terminal') {
    const outcome = terminalEvent(event)
    if (outcome === current.outcome) return { ok: true, state: current }
  }
  return { ok: false, error: 'invalid_transition' }
}

export function projectSessionState(state: SessionState): LifecycleProjection {
  let status: DaemonStatus
  let lastKnown: LegacyTombstone['lastKnown'] | undefined
  switch (state.kind) {
    case 'creating':
      status = 'starting'
      break
    case 'running':
    case 'stopping':
      status = state.kind
      break
    case 'terminal':
      status = state.outcome
      break
    case 'unreachable':
      status = 'lost'
      lastKnown = state.lastKnown
      break
    case 'cleaning':
      status =
        state.target === 'creating'
          ? 'starting'
          : state.target === 'running' || state.target === 'stopping'
            ? state.target
            : state.target === 'terminal'
              ? (state.outcome as TerminalSessionOutcome)
              : 'lost'
      lastKnown = state.target === 'unreachable' ? state.lastKnown : undefined
      break
  }
  lastKnown ??= state.legacy?.tombstone?.lastKnown
  return {
    status,
    pid: state.child.pid,
    startedAt: state.startedAt,
    exitedAt: state.exitedAt,
    timedOut: state.timedOut,
    terminationRequested: state.termination.requested,
    terminationConfirmed: state.termination.confirmed,
    pendingCleanup: state.kind === 'cleaning' ? true : undefined,
    directChildExited: state.child.directExited,
    exitCode: state.exitCode,
    exitSignal: state.exitSignal,
    exitReason: state.exitReason,
    worker: state.worker,
    workerPrestart: state.prestart,
    workerStartAttempted: state.startAttempted,
    containment: state.containment,
    termination: state.termination.result,
    execOutput: state.execOutput,
    storageFailure: state.storageFailure,
    diagnostics: state.diagnostics,
    lastWaitResult: state.lastWaitResult,
    legacyTombstone: state.legacy?.tombstone,
    legacyOutputCleanupPending: state.legacy?.outputCleanupPending,
    streamDrain: state.streamDrain,
    lastKnown,
  }
}

export function refreshSessionState(
  state: SessionState,
  record: LifecycleProjection
): SessionState {
  const evidence: SessionStateEvidence = {
    child: {
      pid: record.pid,
      ...(record.directChildExited === undefined ? {} : { directExited: record.directChildExited }),
    },
    ...(record.startedAt === undefined ? {} : { startedAt: record.startedAt }),
    ...(record.exitedAt === undefined ? {} : { exitedAt: record.exitedAt }),
    timedOut: record.timedOut,
    termination: {
      requested: record.terminationRequested,
      confirmed: record.terminationConfirmed,
      ...(record.termination ? { result: record.termination } : {}),
    },
    ...(record.containment ? { containment: record.containment } : {}),
    ...(record.exitCode === undefined ? {} : { exitCode: record.exitCode }),
    ...(record.exitSignal === undefined ? {} : { exitSignal: record.exitSignal }),
    ...(record.exitReason ? { exitReason: record.exitReason } : {}),
    ...(record.worker ? { worker: record.worker } : {}),
    ...(record.workerPrestart ? { prestart: record.workerPrestart } : {}),
    ...(record.workerStartAttempted === undefined
      ? {}
      : { startAttempted: record.workerStartAttempted }),
    streamDrain: record.streamDrain ?? 'unknown',
    ...(record.execOutput ? { execOutput: record.execOutput } : {}),
    ...(record.storageFailure ? { storageFailure: record.storageFailure } : {}),
    ...(record.diagnostics ? { diagnostics: record.diagnostics } : {}),
    ...(record.lastWaitResult ? { lastWaitResult: record.lastWaitResult } : {}),
    ...(record.legacyTombstone || record.legacyOutputCleanupPending
      ? {
          legacy: {
            ...(record.legacyTombstone ? { tombstone: record.legacyTombstone } : {}),
            ...(record.legacyOutputCleanupPending ? { outputCleanupPending: true as const } : {}),
          },
        }
      : {}),
  }
  if (state.kind === 'terminal') {
    const terminal = { ...evidence, kind: 'terminal', outcome: state.outcome } as SessionState
    if (terminalProven(terminal)) return record.pendingCleanup ? cleaning(terminal) : terminal
    const unreachable: SessionState = {
      ...evidence,
      kind: 'unreachable',
      lastKnown: 'terminal',
      terminal: { outcome: state.outcome, evidence },
    }
    return record.pendingCleanup ? cleaning(unreachable) : unreachable
  }
  if (record.pendingCleanup && state.kind !== 'cleaning') return cleaning({ ...state, ...evidence })
  if (state.kind === 'unreachable')
    return {
      ...evidence,
      kind: 'unreachable',
      lastKnown: state.lastKnown,
      ...(state.terminal ? { terminal: state.terminal } : {}),
    }
  if (state.kind === 'cleaning') {
    const next = {
      ...evidence,
      kind: 'cleaning',
      target: state.target,
      ...(state.outcome ? { outcome: state.outcome } : {}),
      ...(state.lastKnown ? { lastKnown: state.lastKnown } : {}),
      ...(state.terminal ? { terminal: state.terminal } : {}),
    } as SessionState
    return state.target === 'terminal'
      ? terminalOrUnreachable(next, state.outcome as TerminalSessionOutcome, true)
      : next
  }
  return { ...evidence, kind: state.kind }
}

// This accepts only the legacy flat view at construction/migration boundaries. Runtime transitions
// must use reduceSessionState instead.
export function sessionStateFromCompatibility(record: LifecycleProjection): SessionState {
  const state = refreshSessionState(
    {
      kind:
        record.status === 'starting'
          ? 'creating'
          : record.status === 'running' || record.status === 'stopping'
            ? record.status
            : record.status === 'lost'
              ? 'unreachable'
              : 'terminal',
      ...(record.status === 'lost'
        ? { lastKnown: record.lastKnown ?? record.legacyTombstone?.lastKnown ?? 'unreachable' }
        : record.status === 'starting' ||
            record.status === 'running' ||
            record.status === 'stopping'
          ? {}
          : { outcome: record.status as TerminalSessionOutcome }),
      child: { pid: record.pid },
      timedOut: record.timedOut,
      termination: {
        requested: record.terminationRequested,
        confirmed: record.terminationConfirmed,
      },
      streamDrain: record.streamDrain ?? 'unknown',
    } as SessionState,
    record
  )
  if (state.kind !== 'terminal' || terminalProven(state))
    return record.pendingCleanup ? cleaning(state) : state
  const payload: TerminalSessionPayload = {
    outcome: state.outcome,
    evidence: evidenceFromState(state),
  }
  const unreachableState: SessionState = {
    ...evidenceFromState(state),
    kind: 'unreachable',
    lastKnown: 'terminal',
    terminal: payload,
  }
  return record.pendingCleanup ? cleaning(unreachableState) : unreachableState
}

export function reduceDaemonStatus(
  current: DaemonStatus,
  event: LifecycleEvent
): LifecycleReduction {
  if (event === 'unreachable') return { ok: true, status: 'lost' }
  if (current === 'lost' && event === 'recovered') return { ok: true, status: 'running' }

  if (current === 'starting') {
    if (event === 'worker_ready') return { ok: true, status: 'running' }
    if (event === 'spawn_failed') return { ok: true, status: 'spawn_failed' }
    return { ok: false, error: 'invalid_transition' }
  }

  if (current === 'running' || current === 'stopping') {
    if (event === 'worker_ready' && current === 'running') return { ok: true, status: 'running' }
    if (event === 'stop_requested') return { ok: true, status: 'stopping' }
    if (event === 'child_exited') return { ok: true, status: 'exited' }
    if (event === 'timed_out') return { ok: true, status: 'timed_out' }
    if (event === 'output_limited') return { ok: true, status: 'output_limited' }
    return { ok: false, error: 'invalid_transition' }
  }

  if (
    (current === 'exited' && event === 'child_exited') ||
    (current === 'timed_out' && event === 'timed_out') ||
    (current === 'output_limited' && event === 'output_limited') ||
    (current === 'spawn_failed' && event === 'spawn_failed')
  ) {
    return { ok: true, status: current }
  }

  return { ok: false, error: 'invalid_transition' }
}

export function isActiveDaemonStatus(status: DaemonStatus): boolean {
  return status === 'starting' || status === 'running' || status === 'stopping'
}
