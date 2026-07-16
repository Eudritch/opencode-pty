import { expect, test } from 'bun:test'
import { commandPreview, ownerForRoute, sessionCard } from '../src/tui-state.ts'

test('TUI owner derivation requires the active route session', () => {
  const route = { name: 'session', params: { sessionID: 'session-1' } }
  expect(ownerForRoute(route, { id: 'session-1', directory: process.cwd() })?.parentSessionId).toBe(
    'session-1'
  )
  expect(ownerForRoute(route, { id: 'other', directory: process.cwd() })).toBeUndefined()
  expect(
    ownerForRoute({ name: 'home' }, { id: 'session-1', directory: process.cwd() })
  ).toBeUndefined()
})

test('TUI cards label PTY origin and redact command assignments', () => {
  expect(commandPreview('API_TOKEN=secret', ['run'])).toContain('API_TOKEN=[REDACTED]')
  expect(
    sessionCard({
      id: '1',
      title: 'dev',
      command: 'API_TOKEN=secret',
      args: [],
      mode: 'pty',
      lifecycle: 'persistent',
      workdir: process.cwd(),
      status: 'running',
      timedOut: false,
      terminationRequested: false,
      terminationConfirmed: false,
      pid: 1,
      createdAt: new Date().toISOString(),
      lineCount: 0,
    })
  ).toContain('opencode-pty | background | persistent')
})
