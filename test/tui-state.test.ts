import { expect, test } from 'bun:test'
import {
  commandPreview,
  ownerForRoute,
  ownerMatchesRoute,
  redactPreview,
  sessionCard,
} from '../src/tui-state.ts'

test('TUI owner derivation requires the active route session', () => {
  const route = { name: 'session', params: { sessionID: 'session-1' } }
  expect(ownerForRoute(route, { id: 'session-1', directory: process.cwd() })?.parentSessionId).toBe(
    'session-1'
  )
  expect(ownerForRoute(route, { id: 'other', directory: process.cwd() })).toBeUndefined()
  expect(
    ownerForRoute({ name: 'home' }, { id: 'session-1', directory: process.cwd() })
  ).toBeUndefined()
  const owner = ownerForRoute(route, { id: 'session-1', directory: process.cwd() })
  expect(owner && ownerMatchesRoute(route, process.cwd(), owner)).toBe(true)
  expect(
    owner &&
      ownerMatchesRoute(
        { name: 'session', params: { sessionID: 'session-2' } },
        process.cwd(),
        owner
      )
  ).toBe(false)
})

test('TUI previews redact command and text secrets', () => {
  const secrets = ['token-value', 'api-key-value', 'password-value', 'bearer-value', 'url-value']
  const preview = commandPreview('API_TOKEN=token-value', [
    '--api-key=api-key-value',
    '--password',
    'password-value',
    'Authorization: Bearer bearer-value',
    'https://user:url-value@example.test/?api_key=api-key-value',
    '$env:SECRET = "token-value"',
    'setenv KEY token-value',
  ])
  for (const secret of secrets) expect(preview).not.toContain(secret)
  expect(preview).toContain('API_TOKEN=[REDACTED]')
  expect(redactPreview('https://user:password-value@example.test')).toBe(
    'https://[REDACTED]@example.test'
  )
})

test('TUI cards label PTY origin', () => {
  const card = sessionCard({
    id: '1',
    title: 'dev --token=secret',
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
  expect(card).toContain('opencode-pty | background | persistent')
  expect(card).not.toContain('secret')
})
