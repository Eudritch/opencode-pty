import { expect, test } from 'bun:test'
import { isActiveDaemonStatus, reduceDaemonStatus } from '../src/daemon/lifecycle.ts'
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
