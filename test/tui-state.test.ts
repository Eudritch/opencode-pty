import { expect, test } from 'bun:test'
import {
  commandPreview,
  approvalSummary,
  canClaimApproval,
  grantSummary,
  isApprovalClaim,
  ownerForRoute,
  ownerMatchesRoute,
  redactPreview,
  sessionCard,
  scopeForRoute,
  scopeMatchesRoute,
} from '../src/tui-state.ts'

const approval = (status: 'pending' | 'native_fallback' = 'pending') => ({
  id: 'approval-1',
  parentSessionId: 'session-1',
  projectDirectory: process.cwd(),
  digest: 'digest',
  command: 'API_TOKEN=token-value run',
  capability: 'bash',
  workdir: process.cwd(),
  status,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
})

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

test('TUI scopes discard a stale route or project result', () => {
  const route = { name: 'session', params: { sessionID: 'session-1' } }
  const scope = scopeForRoute(route, process.cwd())
  if (!scope) throw new Error('Expected route scope.')
  expect(scopeMatchesRoute(route, process.cwd(), scope)).toBe(true)
  expect(
    scopeMatchesRoute({ name: 'session', params: { sessionID: 'session-2' } }, process.cwd(), scope)
  ).toBe(false)
  expect(scopeMatchesRoute(route, `${process.cwd()}-other`, scope)).toBe(false)
})

test('TUI only claims pending approvals and keeps tokens out of display transforms', () => {
  expect(canClaimApproval(approval())).toBe(true)
  expect(canClaimApproval(approval('native_fallback'))).toBe(false)
  expect(isApprovalClaim(approval())).toBe(false)
  expect(isApprovalClaim({ request: approval(), claimToken: 'secret-token' })).toBe(false)
  expect(
    isApprovalClaim({ request: { ...approval(), status: 'claimed' }, claimToken: 'secret-token' })
  ).toBe(true)
  expect(approvalSummary(approval())).not.toContain('token-value')
  expect(
    grantSummary({
      id: 'grant-1',
      parentSessionId: 'session-1',
      projectDirectory: process.cwd(),
      digest: 'digest',
      capability: 'secret-token',
      workdir: 'https://user:password-value@example.test',
      createdAt: new Date().toISOString(),
      expiresAt: new Date().toISOString(),
    })
  ).toBe('https://[REDACTED]@example.test')
})

test('TUI previews redact command and text secrets', () => {
  const secrets = [
    'token-value',
    'api-key-value',
    'header-api-key-value',
    'basic-value',
    'bearer-value',
    'password-value',
    'url-value',
  ]
  const preview = commandPreview('API_TOKEN=token-value', [
    '--api-key=api-key-value',
    '-H',
    "'X-Api-Key: header-api-key-value'",
    '-H',
    '"Authorization: Basic basic-value"',
    '-H',
    'Authorization: Bearer bearer-value',
    '--password',
    'password-value',
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

test('TUI previews redact quoted and unquoted header credentials', () => {
  const previews = [
    "curl -H 'X-Api-Key: header-api-key-value' example.test",
    'curl -H "Authorization: Basic basic-value" example.test',
    'curl -H Authorization:Bearer bearer-value example.test',
    "curl -H 'Cookie: session_id=cookie-value; theme=dark' example.test",
    "curl -H 'Set-Cookie: session=cookie-value; HttpOnly' example.test",
    'curl -H X-Session-Token:session-value example.test',
  ]
  const secrets = [
    'header-api-key-value',
    'basic-value',
    'bearer-value',
    'cookie-value',
    'session-value',
  ]
  for (const preview of previews) {
    const redacted = redactPreview(preview)
    for (const secret of secrets) expect(redacted).not.toContain(secret)
    expect(redacted).toContain('[REDACTED]')
  }
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
