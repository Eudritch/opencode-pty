import { expect, test } from 'bun:test'
import { bashApprovalCapability, createBash } from '../src/plugin/pty/tools/bash.ts'

interface AskRequest {
  permission: string
  patterns: string[]
  always: string[]
  metadata: { output: string }
}

const execResult = (overrides: Record<string, unknown> = {}) => ({
  session: { id: 'exec', status: 'exited', mode: 'exec', pid: 1 },
  stdout: 'ok\n',
  stderr: '',
  exitCode: 0,
  timedOut: false,
  outputLimited: false,
  terminationConfirmed: true,
  startedAt: '',
  exitedAt: '',
  ...overrides,
})

const baseDaemon = (calls: string[]) => ({
  prepareApproval: async (request: { command: string; capability: string }) => {
    calls.push(`prepare:${request.capability}`)
    return { id: 'approval', status: 'pending' }
  },
  waitForApproval: async () => {
    calls.push('wait')
    return { id: 'approval', status: 'approved_once' }
  },
  approveNativeApproval: async () => {
    calls.push('approve-native')
    return { id: 'approval', status: 'approved_once' }
  },
  consumeApproval: async () => {
    calls.push('consume')
    return { id: 'approval', status: 'consumed' }
  },
  cancelApproval: async () => {
    calls.push('cancel')
    return { id: 'approval', status: 'cancelled' }
  },
  execStart: async () => {
    calls.push('start')
    return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
  },
  execWait: async () => execResult(),
  stop: async () => ({ terminationConfirmed: true }),
})

const context = (overrides: Record<string, unknown> = {}) =>
  ({
    sessionID: 'test-session',
    directory: process.cwd(),
    agent: 'test-agent',
    abort: new AbortController().signal,
    ask: async () => {},
    metadata: () => {},
    ...overrides,
  }) as never

test('allow policy runs exec without touching the approval ledger', async () => {
  const calls: string[] = []
  const bash = createBash(
    async () => ({ action: 'allow', workdir: process.cwd() }),
    baseDaemon(calls) as never
  )
  const asks: AskRequest[] = []
  const output = await bash.execute(
    { command: 'echo ok' },
    context({
      ask: async (request: AskRequest) => void asks.push(request),
    })
  )
  expect(calls).toEqual(['start'])
  expect(asks).toEqual([])
  expect(output).toContain('status="exited"')
})

test('ask policy prepares, waits, and consumes an opaque-capability approval', async () => {
  const calls: string[] = []
  const bash = createBash(
    async () => ({ action: 'ask', workdir: process.cwd() }),
    baseDaemon(calls) as never
  )
  const asks: AskRequest[] = []
  const output = await bash.execute(
    { command: 'echo ok' },
    context({
      ask: async (request: AskRequest) => void asks.push(request),
    })
  )
  const capability = bashApprovalCapability('test-agent')
  expect(capability).toStartWith('bash:')
  expect(capability).not.toContain('test-agent')
  expect(calls).toEqual([`prepare:${capability}`, 'wait', 'consume', 'start'])
  expect(asks).toEqual([])
  expect(output).toContain('status="exited"')
})

test('approved_session preparation short-circuits waiting and consuming', async () => {
  const calls: string[] = []
  const daemon = {
    ...baseDaemon(calls),
    prepareApproval: async () => {
      calls.push('prepare')
      return { status: 'approved_session' }
    },
  }
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), daemon as never)
  const asks: AskRequest[] = []
  await bash.execute(
    { command: 'echo granted' },
    context({
      ask: async (request: AskRequest) => void asks.push(request),
    })
  )
  expect(calls).toEqual(['prepare', 'start'])
  expect(asks).toEqual([])
})

test('native fallback asks the host with the bash permission before consuming', async () => {
  const calls: string[] = []
  const daemon = {
    ...baseDaemon(calls),
    waitForApproval: async () => {
      calls.push('wait')
      return { id: 'approval', status: 'native_fallback' }
    },
  }
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), daemon as never)
  const asks: AskRequest[] = []
  await bash.execute(
    { command: 'echo fallback' },
    context({
      ask: async (request: AskRequest) => {
        calls.push('ask')
        asks.push(request)
      },
    })
  )
  expect(calls).toEqual([
    `prepare:${bashApprovalCapability('test-agent')}`,
    'wait',
    'ask',
    'approve-native',
    'consume',
    'start',
  ])
  expect(asks).toEqual([
    {
      permission: 'bash',
      patterns: ['echo fallback'],
      always: ['echo fallback'],
      metadata: { output: '[opencode-pty · foreground · awaiting approval]' },
    },
  ])
})

test('rejected approvals cancel the ledger entry and never execute', async () => {
  const calls: string[] = []
  const daemon = {
    ...baseDaemon(calls),
    waitForApproval: async () => {
      calls.push('wait')
      return { id: 'approval', status: 'rejected' }
    },
    consumeApproval: async () => {
      calls.push('consume')
      return { id: 'approval', status: 'rejected' }
    },
  }
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), daemon as never)
  await expect(bash.execute({ command: 'echo rejected' }, context())).rejects.toThrow('not granted')
  expect(calls).toEqual([
    `prepare:${bashApprovalCapability('test-agent')}`,
    'wait',
    'consume',
    'cancel',
  ])
  expect(calls).not.toContain('start')
})

test('abort during the approval wait cancels the approval and throws', async () => {
  const calls: string[] = []
  const controller = new AbortController()
  const daemon = {
    ...baseDaemon(calls),
    waitForApproval: () => {
      calls.push('wait')
      controller.abort()
      return new Promise(() => {})
    },
  }
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), daemon as never)
  await expect(
    bash.execute({ command: 'echo aborted' }, context({ abort: controller.signal }))
  ).rejects.toThrow('cancelled')
  expect(calls).toEqual([`prepare:${bashApprovalCapability('test-agent')}`, 'wait', 'cancel'])
  expect(calls).not.toContain('start')
})

test('external directory ask still fires when the workdir leaves the project', async () => {
  const calls: string[] = []
  const bash = createBash(
    async () => ({
      action: 'allow',
      workdir: process.cwd(),
      externalAction: 'ask',
      externalPattern: '/external/*',
    }),
    baseDaemon(calls) as never
  )
  const asks: AskRequest[] = []
  await bash.execute(
    { command: 'echo outside' },
    context({
      ask: async (request: AskRequest) => void asks.push(request),
    })
  )
  expect(asks).toEqual([
    {
      permission: 'external_directory',
      patterns: ['/external/*'],
      always: ['/external/*'],
      metadata: { output: '[opencode-pty · foreground · awaiting approval]' },
    },
  ])
  expect(calls).toEqual(['start'])
})

test('bash output reports containment evidence like shell_exec', async () => {
  const calls: string[] = []
  const daemon = {
    ...baseDaemon(calls),
    execWait: async () =>
      execResult({
        containment: {
          platform: 'windows_job',
          status: 'windows_job_empty',
          rootPid: 1,
          rootStartIdentity: 'identity',
          rootIdentityVerified: true,
          observedGroupPids: [1, 2],
          observedSessionPids: [3],
          observedEscapedDescendantPids: [],
          verifiedAt: new Date().toISOString(),
        },
        termination: { directChildExited: true },
      }),
  }
  const bash = createBash(
    async () => ({ action: 'allow', workdir: process.cwd() }),
    daemon as never
  )
  const output = await bash.execute({ command: 'echo contained' }, context())
  expect(output).toContain(
    '<containment status="windows_job_empty" direct_child_exited="true" root_identity_verified="true" group_pids="1,2" session_pids="3" escaped_pids=""/>'
  )
  const plain = await createBash(
    async () => ({ action: 'allow', workdir: process.cwd() }),
    baseDaemon([]) as never
  ).execute({ command: 'echo plain' }, context())
  expect(plain).not.toContain('<containment')
})
