import { expect, test } from 'bun:test'
import {
  isActiveDaemonStatus,
  reduceDaemonStatus,
  reduceSessionState,
} from '../src/daemon/lifecycle.ts'
import type { DaemonStatus } from '../src/daemon/types.ts'

test('lifecycle reducer accepts legal transitions', () => {
  for (const [current, event, status] of [
    ['starting', 'worker_ready', 'running'],
    ['starting', 'spawn_failed', 'spawn_failed'],
    ['lost', 'recovered', 'running'],
    ['running', 'stop_requested', 'stopping'],
    ['running', 'child_exited', 'exited'],
    ['running', 'timed_out', 'timed_out'],
    ['running', 'output_limited', 'output_limited'],
    ['stopping', 'child_exited', 'exited'],
    ['stopping', 'stop_requested', 'stopping'],
    ['exited', 'child_exited', 'exited'],
    ['timed_out', 'timed_out', 'timed_out'],
    ['output_limited', 'output_limited', 'output_limited'],
    ['spawn_failed', 'spawn_failed', 'spawn_failed'],
  ] as const) {
    expect(reduceDaemonStatus(current, event)).toEqual({ ok: true, status })
  }
})

test('lifecycle reducer always permits an unreachable observation', () => {
  for (const status of ['starting', 'running', 'stopping', 'exited', 'timed_out', 'lost'] as const)
    expect(reduceDaemonStatus(status, 'unreachable')).toEqual({ ok: true, status: 'lost' })
})

test('lifecycle reducer rejects regressions and outcome changes', () => {
  for (const [current, event] of [
    ['starting', 'stop_requested'],
    ['stopping', 'worker_ready'],
    ['exited', 'timed_out'],
    ['lost', 'worker_ready'],
  ] as const)
    expect(reduceDaemonStatus(current, event)).toEqual({ ok: false, error: 'invalid_transition' })
})

test('only start, run, and stop statuses are active', () => {
  const active = ['starting', 'running', 'stopping'] as const satisfies readonly DaemonStatus[]
  const inactive = [
    'exited',
    'timed_out',
    'output_limited',
    'spawn_failed',
    'lost',
  ] as const satisfies readonly DaemonStatus[]
  expect(active.every(isActiveDaemonStatus)).toBe(true)
  expect(inactive.some(isActiveDaemonStatus)).toBe(false)
})

function state(kind: 'creating' | 'running' | 'stopping' = 'creating') {
  return {
    kind,
    child: { pid: 1, directExited: false },
    timedOut: false,
    termination: { requested: false, confirmed: false },
    streamDrain: 'unknown' as const,
  }
}

test('V2 reducer accepts legal transitions and rejects regressions', () => {
  expect(reduceSessionState(state(), 'worker_ready')).toMatchObject({
    ok: true,
    state: { kind: 'running' },
  })
  expect(reduceSessionState(state('running'), 'stop_requested')).toMatchObject({
    ok: true,
    state: { kind: 'stopping' },
  })
  expect(reduceSessionState(state('stopping'), 'worker_ready')).toEqual({
    ok: false,
    error: 'invalid_transition',
  })
})

test('V2 reducer preserves an unproven terminal payload when it becomes unreachable', () => {
  const result = reduceSessionState(
    {
      ...state('running'),
      child: { pid: 1, directExited: true },
      termination: { requested: true, confirmed: false },
      exitReason: { kind: 'timeout' },
    },
    'timed_out'
  )

  expect(result).toMatchObject({
    ok: true,
    state: {
      kind: 'unreachable',
      lastKnown: 'terminal',
      terminal: { outcome: 'timed_out', evidence: { exitReason: { kind: 'timeout' } } },
    },
  })
})

test('cleaning cannot return to running', () => {
  const cleaning = {
    ...state('running'),
    kind: 'cleaning' as const,
    target: 'running' as const,
  }
  expect(reduceSessionState(cleaning, 'worker_ready')).toEqual({
    ok: false,
    error: 'invalid_transition',
  })
  expect(reduceSessionState(cleaning, 'recovered')).toEqual({
    ok: false,
    error: 'invalid_transition',
  })
  expect(reduceSessionState(cleaning, 'unreachable')).toMatchObject({
    ok: true,
    state: { kind: 'cleaning', target: 'unreachable', lastKnown: 'running' },
  })
})
