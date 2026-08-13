import type { DaemonStatus } from './types.ts'

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
