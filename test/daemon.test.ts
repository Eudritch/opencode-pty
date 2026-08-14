import { afterAll, afterEach, expect, test } from 'bun:test'
import { existsSync, realpathSync, watch } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DaemonServer } from '../src/daemon/server.ts'
import { sessionStateFromCompatibility } from '../src/daemon/lifecycle.ts'
import {
  DaemonStorage,
  parseWindowsProcessIdentity,
  processIdentityProbe,
  processStartIdentity,
  renameWithWindowsRetry,
  requiredProcessStartIdentity,
  windowsProcessIdentityCommand,
} from '../src/daemon/storage.ts'
import {
  WorkerClient as NativeWorkerClient,
  WorkerClient,
  WorkerStartError,
  workerLaunchOptions,
  type WorkerSnapshot,
} from '../src/daemon/worker-client.ts'
import {
  effectiveMaxOutputBytes,
  ProcessError,
  runtimeEnvironment,
  SessionSupervisor,
} from '../src/daemon/supervisor.ts'
import {
  DAEMON_PROTOCOL_VERSION,
  SESSION_RECORD_VERSION,
  type SessionRecord,
} from '../src/daemon/types.ts'
import type { SpawnOptions } from '../src/plugin/pty/types.ts'
import {
  daemonLaunchCommand,
  daemonLaunchOptions,
  daemonReadinessDeadline,
  DaemonClient,
  ownerContext,
  resolveDaemonLauncher,
  safeStartupStderrTail,
} from '../src/plugin/pty/daemon-client.ts'
import { formatLine, formatSessionInfo } from '../src/plugin/pty/formatters.ts'
import { createSpawnAuthorizer } from '../src/plugin/pty/permissions.ts'
import { createBashAuthorizer } from '../src/plugin/pty/permissions.ts'
import { match } from '../src/plugin/pty/wildcard.ts'
import {
  bashApprovalCapability,
  bashArgv,
  bashTimeout,
  createBash,
} from '../src/plugin/pty/tools/bash.ts'
import { PTYPlugin } from '../src/plugin.ts'
import { manager } from '../src/plugin/pty/manager.ts'
import { parseEscapeSequences } from '../src/plugin/pty/tools/write.ts'
import { escapeXml } from '../src/plugin/pty/xml.ts'

async function processGone(pid: number) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      process.kill(pid, 0)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') return true
      throw error
    }
    await Bun.sleep(25)
  }
  return false
}

const roots: string[] = []
const OWNER_HASH = 'a'.repeat(64)
const DIRECT_OWNER_HASH = 'b'.repeat(64)
const FIRST_OWNER_HASH = 'c'.repeat(64)
const SECOND_OWNER_HASH = 'd'.repeat(64)
const IDEMPOTENCY_OWNER_HASH = 'e'.repeat(64)
const nativeWorkerPath =
  process.env.PTY_NATIVE_WORKER_PATH ??
  join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
if (existsSync(nativeWorkerPath)) process.env.PTY_NATIVE_WORKER_PATH ??= nativeWorkerPath

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

afterAll(() => {
  // Regression tripwire: an unguarded `process.env.PTY_DAEMON_DIR = <saved undefined>`
  // coerces to the literal string "undefined" and creates an `undefined/` directory.
  expect(process.env.PTY_DAEMON_DIR).not.toBe('undefined')
})

async function withProcessEnv<T>(
  values: Record<string, string>,
  run: () => Promise<T>
): Promise<T> {
  const previous = new Map(Object.keys(values).map((key) => [key, process.env[key]] as const))
  for (const [key, value] of Object.entries(values)) process.env[key] = value
  try {
    return await run()
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

test('runtime environment keeps a single trusted PATH despite caller overrides', () => {
  const environment = runtimeEnvironment(
    { PATH: '.', Path: 'also-malicious', CUSTOM: 'preserved' },
    false,
    { Path: 'trusted-path', HOME: 'trusted-home' },
    true
  )

  expect(environment).toMatchObject({
    PATH: 'trusted-path',
    HOME: 'trusted-home',
    CUSTOM: 'preserved',
  })
  expect(Object.keys(environment).filter((key) => key.toUpperCase() === 'PATH')).toEqual(['PATH'])
})

test('safe Windows environment retains credential locations but excludes secrets and automation', () => {
  const environment = runtimeEnvironment(
    undefined,
    false,
    {
      AppData: 'C:\\Users\\test\\AppData\\Roaming',
      LOCALAPPDATA: 'C:\\Users\\test\\AppData\\Local',
      SystemRoot: 'C:\\Windows',
      SystemDrive: 'C:',
      ComSpec: 'C:\\Windows\\System32\\cmd.exe',
      TEMP: 'C:\\Temp',
      ProgramData: 'C:\\ProgramData',
      ALLUSERSPROFILE: 'C:\\ProgramData',
      PUBLIC: 'C:\\Users\\Public',
      Path: 'trusted-path',
      PATHEXT: '.EXE;.CMD',
      GH_TOKEN: 'secret',
      GIT_TERMINAL_PROMPT: '0',
      GCM_INTERACTIVE: 'never',
    },
    true
  )

  expect(environment).toEqual({
    AppData: 'C:\\Users\\test\\AppData\\Roaming',
    LOCALAPPDATA: 'C:\\Users\\test\\AppData\\Local',
    SystemRoot: 'C:\\Windows',
    SystemDrive: 'C:',
    ComSpec: 'C:\\Windows\\System32\\cmd.exe',
    TEMP: 'C:\\Temp',
    ProgramData: 'C:\\ProgramData',
    ALLUSERSPROFILE: 'C:\\ProgramData',
    PUBLIC: 'C:\\Users\\Public',
    PATHEXT: '.EXE;.CMD',
    PATH: 'trusted-path',
  })
})

function record(
  root: string,
  id: string,
  status: SessionRecord['status'] = 'running'
): SessionRecord {
  const now = new Date().toISOString()
  const flat: Omit<SessionRecord, 'state'> = {
    recordVersion: SESSION_RECORD_VERSION,
    id,
    title: id,
    command: 'test',
    args: [],
    mode: 'pty',
    workdir: root,
    ownerProjectDirectory: root,
    ownerCapabilityHash: OWNER_HASH,
    lifecycle: 'conversation',
    environment: { kind: 'safe', keys: [], fingerprint: '', sensitive: false },
    status,
    pid: 1,
    createdAt: now,
    updatedAt: now,
    parentSessionId: 'parent',
    timedOut: false,
    terminationRequested: false,
    terminationConfirmed:
      status === 'exited' || status === 'timed_out' || status === 'spawn_failed',
    nextSequence: 0,
    firstRetainedSequence: 0,
    outputBytes: 0,
    outputTruncated: false,
    lineCount: 0,
    outputHasPartialLine: false,
    outputJournalVersion: 2,
  }
  return { ...flat, state: sessionStateFromCompatibility(flat) }
}

function directOwner(root: string) {
  return { ownerProjectDirectory: root, ownerCapabilityHash: DIRECT_OWNER_HASH }
}

function markTerminalProof(session: SessionRecord): void {
  session.directChildExited = true
  session.containment = {
    platform: 'not_applicable',
    status: 'not_applicable',
    rootPid: session.pid,
    rootStartIdentity: 'test-root',
    rootIdentityVerified: true,
    observedGroupPids: [],
    observedSessionPids: [],
    observedEscapedDescendantPids: [],
    verifiedAt: session.updatedAt,
  }
  session.state = sessionStateFromCompatibility(session)
}

async function owner(storage: DaemonStorage, parentSessionId: string, projectDirectory: string) {
  const canonicalProjectDirectory = realpathSync(projectDirectory)
  return {
    parentSessionId,
    projectDirectory,
    capability: new Bun.CryptoHasher('sha256')
      .update(
        `${await storage.ownershipSecret()}\0${parentSessionId}\0${canonicalProjectDirectory}`
      )
      .digest('hex'),
  }
}

async function approvalCapability(
  storage: DaemonStorage,
  parentSessionId: string,
  projectDirectory: string
) {
  return new Bun.CryptoHasher('sha256')
    .update(
      `approval\0${await storage.ownershipSecret()}\0${parentSessionId}\0${realpathSync(projectDirectory)}`
    )
    .digest('hex')
}

function workerSnapshot(overrides: Partial<WorkerSnapshot> = {}): WorkerSnapshot {
  return {
    status: 'running',
    pid: 1,
    mode: 'pty',
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    nextSequence: 0,
    firstRetainedSequence: 0,
    outputTruncated: false,
    outputLineCount: 0,
    outputHasPartialLine: false,
    startedAt: new Date().toISOString(),
    timedOut: false,
    terminationRequested: false,
    terminationConfirmed: false,
    directChildExited: false,
    stdoutEof: false,
    stderrEof: false,
    outputComplete: false,
    outputIncomplete: false,
    containment: {
      platform: 'not_applicable',
      status: 'not_applicable',
      rootPid: 1,
      rootStartIdentity: 'start',
      rootIdentityVerified: true,
      observedGroupPids: [],
      observedSessionPids: [],
      observedEscapedDescendantPids: [],
      verifiedAt: new Date().toISOString(),
    },
    ...overrides,
  }
}

async function rpc(
  descriptor: { endpoint: string; token: string },
  operation: string,
  payload: unknown,
  context: unknown
) {
  return fetch(`${descriptor.endpoint}/rpc`, {
    method: 'POST',
    headers: { authorization: `Bearer ${descriptor.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      id: crypto.randomUUID(),
      version: DAEMON_PROTOCOL_VERSION,
      operation,
      owner: context,
      payload,
    }),
  })
}

test.skipIf(process.platform === 'win32')(
  'daemon authenticates RPC and retains PTY output',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-'))
    roots.push(root)
    const storage = new DaemonStorage(root)
    const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
    const descriptor = await server.start()
    const context = await owner(storage, 'test-session', root)
    const rpc = async (operation: string, payload?: unknown, token = 'test-token') =>
      fetch(`${descriptor.endpoint}/rpc`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          id: crypto.randomUUID(),
          version: DAEMON_PROTOCOL_VERSION,
          operation,
          owner: context,
          payload,
        }),
      })

    try {
      expect((await rpc('health', undefined, 'wrong-token')).status).toBe(401)
      expect((await rpc('health', undefined, 'test-token')).status).toBe(200)
      const mismatch = await fetch(`${descriptor.endpoint}/rpc`, {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
        body: JSON.stringify({ id: 'mismatch', version: 99, operation: 'health' }),
      })
      expect(mismatch.status).toBe(400)
      const spawned = await rpc('spawn', {
        command: process.execPath,
        args: ['-e', "console.log('durable output')"],
        description: 'test daemon output',
        parentSessionId: 'test-session',
        workdir: root,
      })
      const session = ((await spawned.json()) as { result: { id: string } }).result

      let output = ''
      let exited = false
      for (
        let attempt = 0;
        attempt < 40 && (!output.includes('durable output') || !exited);
        attempt += 1
      ) {
        await Bun.sleep(25)
        const response = await rpc('rawOutput', { id: session.id })
        output = ((await response.json()) as { result: { raw: string } }).result.raw
        const details = await rpc('get', { id: session.id })
        exited =
          ((await details.json()) as { result: { status: string } }).result.status === 'exited'
      }
      expect(output).toContain('durable output')
      expect(exited).toBeTrue()
    } finally {
      await server.stop()
    }
  }
)

test('daemon validates RPC fields and uses literal searches', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-validation-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  const descriptor = await server.start()
  const rpc = async (operation: string, payload?: unknown) =>
    fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation,
        payload,
      }),
    })

  try {
    const invalid = await rpc('search', { id: 'pty_test', pattern: 'x', flags: 'g' })
    expect(((await invalid.json()) as { error: { code: string } }).error.code).toBe('validation')
  } finally {
    await server.stop()
  }
})

test('daemon rejects malformed owner capability hashes before authorization', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-owner-hash-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  const descriptor = await server.start()
  const context = await owner(storage, 'parent', root)
  const rpc = async (capability: string) =>
    fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation: 'list',
        owner: { ...context, capability },
      }),
    })
  try {
    for (const capability of ['a'.repeat(63), 'A'.repeat(64), 'x'.repeat(64)]) {
      expect(
        ((await (await rpc(capability)).json()) as { error: { code: string } }).error.code
      ).toBe('validation')
    }
    expect(
      ((await (await rpc('b'.repeat(64))).json()) as { error: { code: string } }).error.code
    ).toBe('authorization')
  } finally {
    await server.stop()
  }
}, 30_000)

test('a foreign owner cannot snapshot a routed worker', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-routed-owner-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const server = new DaemonServer(storage, supervisor, 'test-token')
  const descriptor = await server.start()
  const ownerContext = await owner(storage, 'parent', root)
  const session = record(root, 'pty_routed_owner')
  session.parentSessionId = ownerContext.parentSessionId
  session.ownerCapabilityHash = ownerContext.capability
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )
  let snapshots = 0
  ;(supervisor as unknown as { nativeWorkers: Map<string, unknown> }).nativeWorkers.set(
    session.id,
    {
      snapshot: async () => {
        snapshots += 1
        return workerSnapshot()
      },
    }
  )

  try {
    const denied = await rpc(
      descriptor,
      'get',
      { id: session.id },
      await owner(storage, 'other', root)
    )
    expect(((await denied.json()) as { error: { code: string } }).error.code).toBe('authorization')
    expect(snapshots).toBe(0)
  } finally {
    await server.stop()
  }
})

test.skipIf(process.platform === 'win32')(
  'daemon denies other owners and reports bounded diagnostics',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-owner-'))
    roots.push(root)
    const storage = new DaemonStorage(root)
    const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
    const descriptor = await server.start()
    const one = await owner(storage, 'one', root)
    const two = await owner(storage, 'two', root)
    const rpc = async (operation: string, payload: unknown, context = one) =>
      fetch(`${descriptor.endpoint}/rpc`, {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
        body: JSON.stringify({
          id: crypto.randomUUID(),
          version: DAEMON_PROTOCOL_VERSION,
          operation,
          owner: context,
          payload,
        }),
      })
    try {
      const spawned = await rpc('spawn', {
        command: process.execPath,
        args: ['-e', 'setTimeout(() => {}, 5000)'],
        description: 'owner isolation test',
        parentSessionId: 'forged',
        workdir: root,
      })
      const id = ((await spawned.json()) as { result: { id: string } }).result.id
      const denied = await rpc('read', { id }, two)
      expect(((await denied.json()) as { error: { code: string } }).error.code).toBe(
        'authorization'
      )
      const invalidCapability = await rpc('list', {}, { ...one, capability: 'x'.repeat(64) })
      expect(((await invalidCapability.json()) as { error: { code: string } }).error.code).toBe(
        'authorization'
      )
      const diagnostics = (await (await rpc('diagnostics', {})).json()) as {
        result: {
          limits: { maxSessionsPerOwner: number }
          platform: { nativeContainment: boolean }
        }
      }
      expect(diagnostics.result.limits.maxSessionsPerOwner).toBe(32)
      expect(diagnostics.result.platform.nativeContainment).toBeTrue()
      await rpc('stop', { id })
    } finally {
      await server.stop()
    }
  }
)

test('daemon persists owner-bound approval decisions and cleanup', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-approval-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  const descriptor = await server.start()
  const one = await owner(storage, 'one', root)
  const two = await owner(storage, 'two', root)
  const approvals = await approvalCapability(storage, 'one', root)
  const approvalRpc = async (
    operation: string,
    payload: unknown,
    context = one,
    capability = approvals
  ) =>
    fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation,
        owner: context,
        approvalCapability: capability,
        payload,
      }),
    })
  const request = async (expirySeconds = 30) => {
    const response = await approvalRpc('approvalCreate', {
      command: 'bun test',
      reason: 'test approval',
      capability: 'tool',
      workdir: root,
      expirySeconds,
      uiLeaseSeconds: 5,
    })
    return ((await response.json()) as { result: { id: string } }).result.id
  }
  try {
    const missingApproval = await rpc(descriptor, 'approvalCreate', {}, one)
    expect(((await missingApproval.json()) as { error: { code: string } }).error.code).toBe(
      'authorization'
    )
    const id = await request()
    const suppliedDigest = await approvalRpc('approvalCreate', {
      digest: 'client-chosen',
      command: 'bun test',
      reason: 'test approval',
      capability: 'tool',
      workdir: root,
      expirySeconds: 30,
    })
    expect(((await suppliedDigest.json()) as { error: { code: string } }).error.code).toBe(
      'validation'
    )
    const claim = (await (await approvalRpc('approvalClaim', { id })).json()) as {
      result: { request: { status: string }; claimToken: string }
    }
    expect(claim.result.request.status).toBe('claimed')
    expect(claim.result.claimToken).toMatch(/^[a-f0-9]{32}$/)
    const missingClaimToken = await approvalRpc('approvalDecide', { id, decision: 'approve_once' })
    expect(((await missingClaimToken.json()) as { error: { code: string } }).error.code).toBe(
      'validation'
    )
    expect(
      (
        (await (
          await approvalRpc('approvalDecide', {
            id,
            decision: 'approve_once',
            claimToken: claim.result.claimToken,
          })
        ).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('approved_once')
    expect(
      (
        (await (
          await approvalRpc('approvalConsume', {
            id,
            command: 'bun test',
            reason: 'test approval',
            capability: 'tool',
            workdir: root,
          })
        ).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('consumed')
    const replay = await approvalRpc('approvalConsume', {
      id,
      command: 'bun test',
      reason: 'test approval',
      capability: 'tool',
      workdir: root,
    })
    expect(((await replay.json()) as { error: { code: string } }).error.code).toBe('validation')

    const expiringOnce = await request()
    const expiringClaim = (await (
      await approvalRpc('approvalClaim', { id: expiringOnce })
    ).json()) as {
      result: { claimToken: string }
    }
    await approvalRpc('approvalDecide', {
      id: expiringOnce,
      decision: 'approve_once',
      claimToken: expiringClaim.result.claimToken,
    })
    const expiringLedger = await storage.readApprovals()
    const expiredOnce = expiringLedger.requests.find((entry) => entry.id === expiringOnce)
    if (!expiredOnce) throw new Error('Expected expiring one-shot approval.')
    expiredOnce.expiresAt = new Date(0).toISOString()
    await storage.writeApprovals(expiringLedger)
    expect(
      (
        (await (
          await approvalRpc('approvalConsume', {
            id: expiringOnce,
            command: 'bun test',
            reason: 'test approval',
            capability: 'tool',
            workdir: root,
          })
        ).json()) as { result: { status: string } }
      ).result.status
    ).toBe('expired')

    const cancelledOnce = await request()
    const cancelledClaim = (await (
      await approvalRpc('approvalClaim', { id: cancelledOnce })
    ).json()) as {
      result: { claimToken: string }
    }
    await approvalRpc('approvalDecide', {
      id: cancelledOnce,
      decision: 'approve_once',
      claimToken: cancelledClaim.result.claimToken,
    })
    expect(
      (
        (await (await approvalRpc('approvalCancel', { id: cancelledOnce })).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('cancelled')
    expect(
      (
        (await (
          await approvalRpc('approvalConsume', {
            id: cancelledOnce,
            command: 'bun test',
            reason: 'test approval',
            capability: 'tool',
            workdir: root,
          })
        ).json()) as { result: { status: string } }
      ).result.status
    ).toBe('cancelled')

    const rejected = await request()
    const rejectedClaim = (await (await approvalRpc('approvalClaim', { id: rejected })).json()) as {
      result: { claimToken: string }
    }
    expect(
      (
        (await (
          await approvalRpc('approvalDecide', {
            id: rejected,
            decision: 'reject',
            claimToken: rejectedClaim.result.claimToken,
          })
        ).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('rejected')
    const leased = await request()
    const leaseClaim = (await (await approvalRpc('approvalClaim', { id: leased })).json()) as {
      result: { claimToken: string }
    }
    const ledger = await storage.readApprovals()
    const leasedRequest = ledger.requests.find((entry) => entry.id === leased)
    if (!leasedRequest) throw new Error('Expected leased approval.')
    leasedRequest.claimExpiresAt = new Date(0).toISOString()
    await storage.writeApprovals(ledger)
    const expiredLease = await approvalRpc('approvalDecide', {
      id: leased,
      decision: 'approve_once',
      claimToken: leaseClaim.result.claimToken,
    })
    expect(((await expiredLease.json()) as { error: { code: string } }).error.code).toBe(
      'authorization'
    )
    const noClaim = await request()
    const noClaimLedger = await storage.readApprovals()
    const noClaimRequest = noClaimLedger.requests.find((entry) => entry.id === noClaim)
    if (!noClaimRequest) throw new Error('Expected available approval.')
    noClaimRequest.uiExpiresAt = new Date(0).toISOString()
    await storage.writeApprovals(noClaimLedger)
    expect(
      (
        (await (await approvalRpc('approvalClaim', { id: noClaim })).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('native_fallback')
    const fallback = await request()
    const fallbackClaim = (await (await approvalRpc('approvalClaim', { id: fallback })).json()) as {
      result: { claimToken: string }
    }
    const fallbackLedger = await storage.readApprovals()
    const fallbackRequest = fallbackLedger.requests.find((entry) => entry.id === fallback)
    if (!fallbackRequest) throw new Error('Expected fallback approval.')
    fallbackRequest.claimExpiresAt = new Date(0).toISOString()
    await storage.writeApprovals(fallbackLedger)
    const fallbackAgain = (await (await approvalRpc('approvalClaim', { id: fallback })).json()) as {
      result: { status: string; claimToken?: string }
    }
    expect(fallbackAgain.result.status).toBe('native_fallback')
    expect(fallbackAgain.result.claimToken).toBeUndefined()
    const fallbackDecision = await approvalRpc('approvalDecide', {
      id: fallback,
      decision: 'approve_session',
      claimToken: fallbackClaim.result.claimToken,
    })
    expect(((await fallbackDecision.json()) as { error: { code: string } }).error.code).toBe(
      'authorization'
    )
    expect(
      (
        (await (await approvalRpc('approvalNativeApprove', { id: fallback })).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('approved_once')
    expect(
      (
        (await (
          await approvalRpc('approvalConsume', {
            id: fallback,
            command: 'bun test',
            reason: 'test approval',
            capability: 'tool',
            workdir: root,
          })
        ).json()) as { result: { status: string } }
      ).result.status
    ).toBe('consumed')
    expect(fallbackClaim.result.claimToken).toMatch(/^[a-f0-9]{32}$/)
    const cancelled = await request()
    expect(
      (
        (await (await approvalRpc('approvalCancel', { id: cancelled })).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('cancelled')

    const session = await request()
    const sessionClaim = (await (await approvalRpc('approvalClaim', { id: session })).json()) as {
      result: { claimToken: string }
    }
    await approvalRpc('approvalDecide', {
      id: session,
      decision: 'approve_session',
      claimToken: sessionClaim.result.claimToken,
    })
    const grants = (await (await approvalRpc('approvalListGrants', {})).json()) as {
      result: Array<{ id: string; expiresAt: string }>
    }
    expect(grants.result).toHaveLength(1)
    expect(Date.parse(grants.result[0]?.expiresAt ?? '')).toBeLessThanOrEqual(
      Date.now() + 24 * 60 * 60 * 1000
    )
    const persisted = await storage.readApprovals()
    const grant = persisted.grants[0]
    if (!grant) throw new Error('Expected approval grant.')
    grant.expiresAt = new Date(0).toISOString()
    await storage.writeApprovals(persisted)
    expect(
      ((await (await approvalRpc('approvalListGrants', {})).json()) as { result: unknown[] }).result
    ).toHaveLength(0)
    expect(
      (
        (await (
          await approvalRpc('approvalConsume', {
            id: session,
            command: 'bun test',
            reason: 'test approval',
            capability: 'tool',
            workdir: root,
          })
        ).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('rejected')

    const expired = await request(1)
    await Bun.sleep(1_050)
    expect(
      (
        (await (await approvalRpc('approvalClaim', { id: expired })).json()) as {
          result: { status: string }
        }
      ).result.status
    ).toBe('expired')

    const isolated = await approvalRpc(
      'approvalClaim',
      { id: cancelled },
      two,
      await approvalCapability(storage, 'two', root)
    )
    expect(((await isolated.json()) as { error: { code: string } }).error.code).toBe(
      'authorization'
    )
    await approvalRpc('approvalCleanupByParentSession', { parentSessionId: 'one' })
    expect((await storage.readApprovals()).requests).toHaveLength(0)
  } finally {
    await server.stop()
  }
}, 10_000)

test('approval preparation binds intent and retains a long native approval window', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-approval-prepare-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'prepare-token')
  const context = await owner(storage, 'prepare', root)
  const capability = await approvalCapability(storage, 'prepare', root)
  try {
    const descriptor = await server.start()
    const response = await fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer prepare-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation: 'approvalPrepare',
        owner: context,
        approvalCapability: capability,
        payload: {
          command: 'bun test',
          capability: 'bash',
          workdir: root,
          expirySeconds: 3600,
        },
      }),
    })
    const prepared = (await response.json()) as { result: { status: string; expiresAt?: string } }
    expect(prepared.result.status).toBe('pending')
    expect(Date.parse(prepared.result.expiresAt ?? '')).toBeGreaterThan(Date.now() + 3_500_000)
  } finally {
    await server.stop()
  }
})

test('advanced approval grants are isolated by capability', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-approval-agent-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'agent-token')
  const descriptor = await server.start()
  const context = await owner(storage, 'agent-session', root)
  const approvals = await approvalCapability(storage, 'agent-session', root)
  const approvalRpc = (operation: string, payload: unknown) =>
    fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer agent-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation,
        owner: context,
        approvalCapability: approvals,
        payload,
      }),
    })
  const agentA = 'advanced:agent-a'
  const agentB = 'advanced:agent-b'
  try {
    const created = (await (
      await approvalRpc('approvalCreate', {
        command: 'bun test',
        reason: 'test approval',
        capability: agentA,
        workdir: root,
        expirySeconds: 30,
        uiLeaseSeconds: 5,
      })
    ).json()) as { result: { id: string } }
    const claimed = (await (
      await approvalRpc('approvalClaim', { id: created.result.id })
    ).json()) as {
      result: { claimToken: string }
    }
    await approvalRpc('approvalDecide', {
      id: created.result.id,
      decision: 'approve_session',
      claimToken: claimed.result.claimToken,
    })
    const prepared = (await (
      await approvalRpc('approvalPrepare', {
        command: 'bun test',
        reason: 'test approval',
        capability: agentB,
        workdir: root,
        expirySeconds: 30,
      })
    ).json()) as { result: { status: string } }
    expect(prepared.result.status).toBe('pending')
  } finally {
    await server.stop()
  }
})

test('approval ledger discards legacy session grants without expiry', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-legacy-approval-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  const descriptor = await server.start()
  const context = await owner(storage, 'legacy', root)
  const intent = {
    command: 'bun test',
    reason: 'legacy approval',
    capability: 'tool',
    workdir: root,
  }
  const digest = new Bun.CryptoHasher('sha256')
    .update(
      JSON.stringify({
        command: intent.command,
        capability: intent.capability,
        workdir: intent.workdir,
        reason: intent.reason,
      })
    )
    .digest('hex')
  const now = new Date().toISOString()
  const expiresAt = new Date(Date.now() + 30_000).toISOString()
  const approvals = await approvalCapability(storage, 'legacy', root)
  const approvalRpc = (operation: string, payload: unknown) =>
    fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation,
        owner: context,
        approvalCapability: approvals,
        payload,
      }),
    })
  try {
    await writeFile(
      join(root, 'approvals.json'),
      JSON.stringify({
        requests: [
          {
            id: 'session',
            parentSessionId: 'legacy',
            projectDirectory: root,
            digest,
            ...intent,
            status: 'approved_session',
            createdAt: now,
            updatedAt: now,
            expiresAt,
          },
          {
            id: 'once',
            parentSessionId: 'legacy',
            projectDirectory: root,
            digest,
            ...intent,
            status: 'approved_once',
            createdAt: now,
            updatedAt: now,
            expiresAt,
          },
        ],
        grants: [
          {
            id: 'grant',
            parentSessionId: 'legacy',
            projectDirectory: root,
            digest,
            capability: 'tool',
            workdir: root,
            createdAt: now,
          },
        ],
      })
    )
    const consume = (id: string) => approvalRpc('approvalConsume', { id, ...intent })
    const sessionResponse = (await (await consume('session')).json()) as {
      result?: { status: string }
      error?: { message: string }
    }
    if (!sessionResponse.result) throw new Error(sessionResponse.error?.message)
    expect(sessionResponse.result.status).toBe('rejected')
    expect(
      ((await (await consume('once')).json()) as { result: { status: string } }).result.status
    ).toBe('consumed')
    expect((await storage.readApprovals()).grants).toHaveLength(0)
    const rewritten = JSON.parse(await readFile(join(root, 'approvals.json'), 'utf8')) as {
      grants: unknown[]
    }
    expect(rewritten.grants).toHaveLength(0)
  } finally {
    await server.stop()
  }
})

test.skipIf(process.platform === 'win32')(
  'a new client retains owned output, list, and cleanup access after daemon restart',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-owner-restart-'))
    roots.push(root)
    const previousDirectory = process.env.PTY_DAEMON_DIR
    process.env.PTY_DAEMON_DIR = root
    const storage = new DaemonStorage(root)
    const first = new DaemonServer(storage, new SessionSupervisor(storage), 'first-token')
    await first.start()
    const context = ownerContext('same-parent', root)
    let restarted: DaemonServer | undefined
    try {
      const client = new DaemonClient()
      const session = await client.spawn(
        {
          command: process.execPath,
          args: ['-e', "console.log('retained')"],
          parentSessionId: 'same-parent',
          workdir: root,
        },
        context
      )
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const output = (await client.getRawBuffer(session.id, context))?.raw
        const status = (await client.get(session.id, context))?.status
        if (output?.includes('retained') && status === 'exited') break
        await Bun.sleep(25)
      }
      await first.stop()

      restarted = new DaemonServer(storage, new SessionSupervisor(storage), 'second-token')
      await restarted.start()
      const recreated = new DaemonClient()
      expect((await recreated.list(context)).map((item) => item.id)).toContain(session.id)
      expect((await recreated.getRawBuffer(session.id, context))?.raw).toContain('retained')
      expect(await recreated.cleanup(session.id, context)).toBeTrue()
      await restarted.stop()
    } finally {
      await first.stop().catch(() => undefined)
      await restarted?.stop().catch(() => undefined)
      if (previousDirectory === undefined) delete process.env.PTY_DAEMON_DIR
      else process.env.PTY_DAEMON_DIR = previousDirectory
    }
  }
)

test.skipIf(process.platform === 'win32')(
  'server canonicalizes project owners and limits only active PTY and exec sessions',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-owner-path-'))
    roots.push(root)
    const storage = new DaemonStorage(root)
    const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token', 1)
    const descriptor = await server.start()
    const canonical = await owner(storage, 'parent', root)
    const alias = { ...canonical, projectDirectory: join(root, '.') }
    try {
      const pty = await rpc(
        descriptor,
        'spawn',
        {
          command: process.execPath,
          args: ['-e', 'setTimeout(() => {}, 5000)'],
          workdir: join(root, '.'),
        },
        alias
      )
      const ptyId = ((await pty.json()) as { result: { id: string } }).result.id
      expect(
        (
          (await (
            await rpc(
              descriptor,
              'exec',
              {
                command: process.execPath,
                args: ['-e', 'process.exit()'],
                timeoutSeconds: 1,
                workdir: root,
              },
              canonical
            )
          ).json()) as { error: { code: string } }
        ).error.code
      ).toBe('limit')
      await rpc(descriptor, 'stop', { id: ptyId }, canonical)
      await Bun.sleep(50)
      const [firstExec, secondExec] = await Promise.all([
        rpc(
          descriptor,
          'exec',
          {
            command: process.execPath,
            args: ['-e', 'setTimeout(() => {}, 100)'],
            timeoutSeconds: 1,
            workdir: root,
          },
          canonical
        ),
        rpc(
          descriptor,
          'exec',
          {
            command: process.execPath,
            args: ['-e', 'setTimeout(() => {}, 100)'],
            timeoutSeconds: 1,
            workdir: root,
          },
          canonical
        ),
      ])
      const results = [await firstExec.json(), await secondExec.json()] as Array<{
        result?: { session: { id: string } }
        error?: { code: string }
      }>
      expect(results.filter((result) => result.error?.code === 'limit')).toHaveLength(1)
      const exec = results.find((result) => result.result) as {
        result: { session: { id: string } }
      }
      expect(exec.result.session.id).toStartWith('exec_')
    } finally {
      await server.stop()
    }
  }
)

test('owner reservations atomically enforce caps, isolate owners, and reuse matching PTYs at capacity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-owner-reservations-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const prepare = NativeWorkerClient.prepare
  const reference = {
    pid: 1,
    startIdentity: 'reserved-worker',
    processIdentity: 'reserved-process',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async () =>
    ({
      reference,
      client: {
        start: async () => workerSnapshot(),
        wait: async () => new Promise<WorkerSnapshot>(() => undefined),
      },
    }) as unknown as Awaited<ReturnType<typeof NativeWorkerClient.prepare>>
  const owner = {
    parentSessionId: 'reserved-parent',
    ownerProjectDirectory: root,
    ownerCapabilityHash: DIRECT_OWNER_HASH,
    workdir: root,
  }
  try {
    const first = await supervisor.spawn(
      {
        ...owner,
        command: 'reserved-command',
        idempotencyKey: 'reserved-key',
      },
      2
    )
    const reused = await supervisor.spawn(
      {
        ...owner,
        command: 'reserved-command',
        idempotencyKey: 'reserved-key',
      },
      2
    )
    expect(reused.id).toBe(first.id)

    const concurrent = await Promise.allSettled([
      supervisor.spawn({ ...owner, command: 'second-command' }, 2),
      supervisor.spawn({ ...owner, command: 'third-command' }, 2),
    ])
    expect(concurrent.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
    const rejected = concurrent.find((result) => result.status === 'rejected')
    expect(rejected).toMatchObject({ reason: { code: 'limit' } })

    await expect(
      supervisor.spawn(
        {
          ...owner,
          command: 'other-owner-command',
          ownerCapabilityHash: SECOND_OWNER_HASH,
        },
        2
      )
    ).resolves.toMatchObject({ id: expect.stringMatching(/^pty_/) })
  } finally {
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = prepare
  }
})

test('first record-write failure releases its reservation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-reservation-first-write-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const prepare = NativeWorkerClient.prepare
  const writeSession = storage.writeSession.bind(storage)
  const reference = {
    pid: 1,
    startIdentity: 'first-write-worker',
    processIdentity: 'first-write-process',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async () =>
    ({
      reference,
      client: {
        start: async () => workerSnapshot(),
        wait: async () => new Promise<WorkerSnapshot>(() => undefined),
      },
    }) as unknown as Awaited<ReturnType<typeof NativeWorkerClient.prepare>>
  let fail = true
  storage.writeSession = async (entry) => {
    if (fail) {
      fail = false
      throw Object.assign(new Error('initial record write failed'), { code: 'ENOSPC' })
    }
    await writeSession(entry)
  }
  const options = {
    command: 'first-write-command',
    parentSessionId: 'first-write-parent',
    ...directOwner(root),
    workdir: root,
  }
  try {
    await expect(supervisor.spawn(options, 1)).rejects.toThrow('initial record write failed')
    await expect(supervisor.spawn(options, 1)).resolves.toMatchObject({ id: expect.any(String) })
  } finally {
    storage.writeSession = writeSession
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = prepare
  }
})

test('uncertain starts retain capacity until durable proof and deletion release it', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-reservation-uncertain-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const prepare = NativeWorkerClient.prepare
  const options = {
    command: 'uncertain-command',
    parentSessionId: 'uncertain-parent',
    ...directOwner(root),
    workdir: root,
  }
  ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async () => {
    throw new WorkerStartError('worker state is uncertain', {
      requested: false,
      terminationConfirmed: false,
      method: 'none',
    })
  }
  try {
    await expect(supervisor.spawn(options, 1)).rejects.toBeInstanceOf(ProcessError)
    await expect(supervisor.spawn(options, 1)).rejects.toMatchObject({ code: 'limit' })

    const records = (supervisor as unknown as { records: Map<string, SessionRecord> }).records
    const uncertain = [...records.values()][0]
    if (!uncertain) throw new Error('Expected an uncertain session record.')
    uncertain.terminationConfirmed = true
    markTerminalProof(uncertain)
    await storage.writeSession(uncertain)
    expect(await supervisor.cleanup(uncertain.id)).toBeTrue()

    const reference = {
      pid: 1,
      startIdentity: 'released-worker',
      processIdentity: 'released-process',
      endpoint: 'http://127.0.0.1:1',
      tokenFingerprint: 'f'.repeat(64),
      protocolVersion: 5,
    }
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async () =>
      ({
        reference,
        client: {
          start: async () => workerSnapshot(),
          wait: async () => new Promise<WorkerSnapshot>(() => undefined),
        },
      }) as unknown as Awaited<ReturnType<typeof NativeWorkerClient.prepare>>
    await expect(supervisor.spawn(options, 1)).resolves.toMatchObject({ id: expect.any(String) })
  } finally {
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = prepare
  }
})

test('strict no-child cleanup and pre-activation records release capacity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-reservation-no-child-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const stale = record(root, 'pty_pre_activation', 'starting')
  stale.pid = 0
  await storage.writeSession(stale)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize(false)
  expect(await storage.loadSessions()).toEqual([])

  const prepare = NativeWorkerClient.prepare
  const options = {
    command: 'no-child-command',
    parentSessionId: 'no-child-parent',
    ...directOwner(root),
    workdir: root,
  }
  ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async () => {
    throw new WorkerStartError('child never started', {
      requested: false,
      terminationConfirmed: true,
      method: 'rollback',
      directChildStarted: false,
    })
  }
  try {
    await expect(supervisor.spawn(options, 1)).rejects.toBeInstanceOf(ProcessError)
    const reference = {
      pid: 1,
      startIdentity: 'no-child-worker',
      processIdentity: 'no-child-process',
      endpoint: 'http://127.0.0.1:1',
      tokenFingerprint: 'f'.repeat(64),
      protocolVersion: 5,
    }
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async () =>
      ({
        reference,
        client: {
          start: async () => workerSnapshot(),
          wait: async () => new Promise<WorkerSnapshot>(() => undefined),
        },
      }) as unknown as Awaited<ReturnType<typeof NativeWorkerClient.prepare>>
    await expect(supervisor.spawn(options, 1)).resolves.toMatchObject({ id: expect.any(String) })
  } finally {
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = prepare
  }
})

test('admission is isolated from an unrelated worker snapshot', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-reservation-isolation-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const prepare = NativeWorkerClient.prepare
  const reference = {
    pid: 1,
    startIdentity: 'isolation-worker',
    processIdentity: 'isolation-process',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  let stallSnapshots = false
  ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async () =>
    ({
      reference,
      client: {
        start: async () => workerSnapshot(),
        snapshot: async () =>
          stallSnapshots ? new Promise<WorkerSnapshot>(() => undefined) : workerSnapshot(),
        wait: async () => new Promise<WorkerSnapshot>(() => undefined),
      },
    }) as unknown as Awaited<ReturnType<typeof NativeWorkerClient.prepare>>
  try {
    const first = await supervisor.spawn({
      command: 'first-owner-command',
      parentSessionId: 'first-owner',
      ...directOwner(root),
      workdir: root,
    })
    stallSnapshots = true
    void supervisor.get(first.id)
    await expect(
      Promise.race([
        supervisor.spawn({
          command: 'second-owner-command',
          parentSessionId: 'second-owner',
          ownerProjectDirectory: root,
          ownerCapabilityHash: SECOND_OWNER_HASH,
          workdir: root,
        }),
        Bun.sleep(1500).then(() => {
          throw new Error('Unrelated admission waited for a worker snapshot.')
        }),
      ])
    ).resolves.toMatchObject({ id: expect.any(String) })
  } finally {
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = prepare
  }
})

test('controller lane orders writes before stop and rejects later resize', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-controller-lane-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const session = record(root, 'pty_controller_lane')
  storage.writeSession = async () => {}
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )
  const terminal = workerSnapshot({
    status: 'exited',
    exitedAt: new Date().toISOString(),
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
  })
  const operations: string[] = []
  const worker = {
    write: async () => {
      operations.push('write')
      return { arrivalSequence: 0 }
    },
    resize: async () => ({ cols: 80, rows: 24 }),
    stop: async () => {
      operations.push('stop')
      return terminal
    },
    finalSnapshot: async () => terminal,
    shutdown: async () => terminal,
  }
  ;(supervisor as unknown as { nativeWorkers: Map<string, unknown> }).nativeWorkers.set(
    session.id,
    worker
  )

  const write = supervisor.write(session.id, 'input')
  const stop = supervisor.stop(session.id)
  const resize = supervisor.resize(session.id, 80, 24)

  const [written, stopped, resized] = await Promise.allSettled([write, stop, resize])
  expect(written).toMatchObject({ status: 'fulfilled', value: { acceptedBytes: 5 } })
  expect(stopped).toMatchObject({
    status: 'fulfilled',
    value: { requested: true, terminationConfirmed: true },
  })
  expect(resized).toMatchObject({ status: 'rejected', reason: { code: 'session_closed' } })
  expect(operations).toEqual(['write', 'stop'])
})

test('controller lane ignores a queued duplicate terminal finalizer', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-controller-finalizer-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const session = record(root, 'pty_controller_finalizer')
  await storage.writeSession(session)
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )
  const terminal = workerSnapshot({
    status: 'exited',
    exitedAt: new Date().toISOString(),
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
  })
  let snapshots = 0
  const worker = {
    finalSnapshot: async () => {
      snapshots += 1
      return terminal
    },
    shutdown: async () => terminal,
  }
  ;(supervisor as unknown as { nativeWorkers: Map<string, unknown> }).nativeWorkers.set(
    session.id,
    worker
  )

  await Promise.all([
    (
      supervisor as unknown as {
        finalizeNative: (
          record: SessionRecord,
          worker: unknown,
          result: WorkerSnapshot
        ) => Promise<unknown>
      }
    ).finalizeNative(session, worker, terminal),
    (
      supervisor as unknown as {
        finalizeNative: (
          record: SessionRecord,
          worker: unknown,
          result: WorkerSnapshot
        ) => Promise<unknown>
      }
    ).finalizeNative(session, worker, terminal),
  ])

  expect(snapshots).toBe(1)
  expect(session.status).toBe('exited')
})

test.skipIf(process.platform === 'win32')(
  'conversation cleanup excludes persistent sessions and environment values stay out of records',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-lifecycle-'))
    const otherProject = await mkdtemp(join(tmpdir(), 'opencode-pty-lifecycle-other-'))
    roots.push(root, otherProject)
    const supervisor = new SessionSupervisor(new DaemonStorage(root))
    await supervisor.initialize()
    const common = {
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 5000)'],
      parentSessionId: 'owner',
      ownerProjectDirectory: root,
      ownerCapabilityHash: FIRST_OWNER_HASH,
      workdir: root,
      env: { API_TOKEN: 'test-secret-value' },
    }
    const conversation = await supervisor.spawn(common)
    const persistent = await supervisor.spawn({ ...common, lifecycle: 'persistent' })
    const other = await supervisor.spawn({
      ...common,
      ownerProjectDirectory: otherProject,
      ownerCapabilityHash: SECOND_OWNER_HASH,
    })
    expect((await supervisor.get(conversation.id))?.environment).toEqual({
      kind: 'safe',
      keys: expect.arrayContaining(['[REDACTED_ENV_KEY]']),
      fingerprint: expect.any(String),
      sensitive: true,
    })
    expect(JSON.stringify(await new DaemonStorage(root).loadSessions())).not.toContain(
      'test-secret-value'
    )
    expect(
      (
        await supervisor.nativeExec({
          ...common,
          args: ['-e', 'console.log(process.env.API_TOKEN)'],
          timeoutSeconds: 2,
        })
      ).stdout
    ).toBe('[REDACTED]\n')
    await supervisor.cleanupByParentSession('owner', root, FIRST_OWNER_HASH)
    expect((await supervisor.get(conversation.id))?.terminationRequested).toBeTrue()
    expect((await supervisor.get(persistent.id))?.terminationRequested).toBeFalse()
    expect((await supervisor.get(other.id))?.terminationRequested).toBeFalse()
    await supervisor.stop(persistent.id)
    await supervisor.stop(other.id)
    await Bun.sleep(50)
    await supervisor.flush()
  }
)

test('spawn permission adapter uses native ask unless locally allowed or denied', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-permissions-'))
  const external = await mkdtemp(join(tmpdir(), 'opencode-pty-permissions-external-'))
  roots.push(root, external)
  const authorizer = (permission: unknown) =>
    createSpawnAuthorizer(
      {
        config: { get: async () => ({ data: { permission } }) },
        tui: { showToast: async () => {} },
      } as never,
      root
    )
  const ask = async (request: {
    permission: string
    patterns: string[]
    always: string[]
    metadata: { output: string }
  }) => void asks.push(request)
  const asks: {
    permission: string
    patterns: string[]
    always: string[]
    metadata: { output: string }
  }[] = []
  await authorizer({ bash: 'ask' })(process.execPath, ['--version'], root, undefined, ask)
  expect(asks).toEqual([
    {
      permission: 'bash',
      patterns: [`${process.execPath} --version`],
      always: [`${process.execPath} --version`],
      metadata: { output: '[opencode-pty · authorization request]' },
    },
  ])

  const denied = authorizer({ bash: 'deny' })
  await expect(denied(process.execPath, [], root, undefined, ask)).rejects.toThrow('denied')
  expect(asks).toHaveLength(1)

  await authorizer({ bash: 'allow' })(process.execPath, [], root, undefined, ask)
  expect(asks).toHaveLength(1)

  await authorizer({ bash: 'allow' })(process.execPath, [], external, undefined, ask)
  expect(asks.at(-1)).toEqual({
    permission: 'external_directory',
    patterns: [`${resolve(external, '..').replace(/\\/g, '/')}/*`],
    always: [`${resolve(external, '..').replace(/\\/g, '/')}/*`],
    metadata: { output: '[opencode-pty · authorization request]' },
  })

  await expect(
    authorizer({ bash: 'allow', external_directory: 'deny' })(
      process.execPath,
      [],
      external,
      undefined,
      ask
    )
  ).rejects.toThrow('denied')

  expect(match('git', 'git *')).toBeTrue()
  expect(match('C:\\Work\\Repo', 'c:/work/*', 'win32')).toBeTrue()
})

test('spawn permission adapter requires local allow for custom environments', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-permissions-environment-'))
  roots.push(root)
  let asks = 0
  const ask = async () => {
    asks += 1
  }
  const authorizer = (permission: unknown) =>
    createSpawnAuthorizer(
      {
        config: { get: async () => ({ data: { permission } }) },
        tui: { showToast: async () => {} },
      } as never,
      root
    )

  const customEnvironment = { API_TOKEN: 'super-secret-value' }
  await expect(
    authorizer({ bash: 'ask' })(process.execPath, [], root, undefined, ask, customEnvironment)
  ).rejects.toThrow('custom or inherited environment requires an explicit local bash allow rule')
  expect(asks).toBe(0)

  await expect(
    authorizer({ bash: 'ask' })(process.execPath, [], root, undefined, ask, undefined, true)
  ).rejects.toThrow('custom or inherited environment requires an explicit local bash allow rule')
  expect(asks).toBe(0)

  await authorizer({ bash: 'ask' })(process.execPath, [], root, undefined, ask, {})
  expect(asks).toBe(1)

  await authorizer({ bash: 'allow' })(
    process.execPath,
    [],
    root,
    undefined,
    ask,
    customEnvironment,
    true
  )
  expect(asks).toBe(1)

  await expect(
    authorizer({ bash: 'deny' })(process.execPath, [], root, undefined, ask, customEnvironment)
  ).rejects.toThrow('local permission policy')
  expect(asks).toBe(1)
})

test('experimental Bash keeps raw policy input and external ask patterns', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-bash-policy-'))
  const external = await mkdtemp(join(tmpdir(), 'opencode-pty-bash-external-'))
  roots.push(root, external)
  const authorizer = (permission: unknown) =>
    createBashAuthorizer(
      {
        config: { get: async () => ({ data: { permission } }) },
        tui: { showToast: async () => {} },
      } as never,
      root
    )
  expect(
    await authorizer({ bash: { 'git status && whoami': 'allow' } })('git status && whoami')
  ).toMatchObject({
    action: 'allow',
    workdir: root,
  })
  await expect(authorizer({ bash: { '*': 'deny' } })('git status && whoami')).rejects.toThrow(
    'local permission policy'
  )
  expect(await authorizer({ bash: 'ask' })('git status')).toMatchObject({ action: 'ask' })
  await expect(
    createBashAuthorizer(
      {
        config: {
          get: async () => ({
            data: {
              permission: { bash: 'allow' },
              agent: { restricted: { permission: { bash: 'deny' } } },
            },
          }),
        },
        tui: { showToast: async () => {} },
      } as never,
      root
    )('git status', undefined, 'restricted')
  ).rejects.toThrow('local permission policy')
  await expect(
    createSpawnAuthorizer(
      {
        config: {
          get: async () => ({
            data: {
              permission: { bash: 'deny' },
              agent: { permissive: { permission: { bash: 'allow' } } },
            },
          }),
        },
        tui: { showToast: async () => {} },
      } as never,
      root
    )(process.execPath, [], root, 'permissive', async () => {})
  ).rejects.toThrow('local permission policy')
  expect(await authorizer({ bash: 'allow' })('git status', external)).toMatchObject({
    action: 'allow',
    externalPattern: `${resolve(external, '..').replace(/\\/g, '/')}/*`,
  })
})

test('bash wrapper keeps host metadata private and consumes native approval once', async () => {
  expect(bashArgv('echo ok', 'win32', { ComSpec: 'cmd.exe' }, () => true)).toEqual([
    'cmd.exe',
    ['/d', '/s', '/c', 'echo ok'],
  ])
  expect(bashArgv('echo ok', 'linux', {}, () => true)).toEqual(['/bin/sh', ['-lc', 'echo ok']])
  expect(bashTimeout(1999)).toBe(1)
  expect(() => bashTimeout(999)).toThrow('at least 1000')
  expect(() => bashTimeout(3_600_000)).not.toThrow()
  expect(() => bashTimeout(3_601_000)).toThrow('3600 second limit')
  const calls: string[] = []
  const daemon = {
    prepareApproval: async (request: unknown) => {
      expect(request).toEqual({
        command: 'echo ok',
        capability: bashApprovalCapability('test'),
        workdir: process.cwd(),
        expirySeconds: 3600,
        uiLeaseSeconds: 5,
      })
      return { id: 'approval', status: 'pending' }
    },
    waitForApproval: async () => {
      calls.push('wait')
      return { id: 'approval', status: 'native_fallback' }
    },
    approveNativeApproval: async () => {
      calls.push('approve')
      return { id: 'approval', status: 'approved_once' }
    },
    consumeApproval: async () => {
      calls.push('consume')
      return { id: 'approval', status: 'consumed' }
    },
    cancelApproval: async () => ({ id: 'approval', status: 'cancelled' }),
    execStart: async (options: { command: string; args: string[] }) => {
      calls.push(`exec:${options.command}:${options.args.join(',')}`)
      return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
    },
    execWait: async () => {
      return {
        session: { id: 'exec', status: 'exited', mode: 'exec', pid: 1 },
        stdout: 'ok\n',
        stderr: '',
        exitCode: 0,
        timedOut: false,
        outputLimited: false,
        terminationConfirmed: true,
        startedAt: '',
        exitedAt: '',
      }
    },
    stop: async () => ({ terminationConfirmed: true }),
  }
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), daemon as never)
  const metadata: string[] = []
  const output = await bash.execute({ command: 'echo ok', description: 'test bash' }, {
    sessionID: 'test-session',
    directory: process.cwd(),
    agent: 'test',
    abort: new AbortController().signal,
    ask: async (request: {
      permission: string
      patterns: string[]
      always: string[]
      metadata: unknown
    }) => {
      calls.push('ask')
      expect(request.permission).toBe('bash')
      expect(request.patterns).toEqual(['echo ok'])
      expect(request.always).toEqual(['echo ok'])
      expect(request.metadata).toEqual({
        output: '[opencode-pty · foreground · awaiting approval]',
      })
    },
    metadata: (input: { title?: string; metadata?: { output?: string; description?: string } }) => {
      expect(input.title).toBe('Bash')
      expect(input.metadata?.description).toBeUndefined()
      if (input.metadata?.output) metadata.push(input.metadata.output)
    },
  } as never)
  expect(calls).toEqual([
    'wait',
    'ask',
    'approve',
    'consume',
    `exec:${process.platform === 'win32' ? process.env.ComSpec : '/bin/sh'}:${process.platform === 'win32' ? '/d,/s,/c,echo ok' : '-lc,echo ok'}`,
  ])
  expect(metadata).toEqual([
    '[opencode-pty · foreground · awaiting approval]',
    '[opencode-pty · foreground · running]',
    '[opencode-pty · foreground · completed]',
  ])
  expect(output).toContain(
    '<bash origin="opencode-pty" mode="foreground" status="exited" exit_code="0"'
  )
  const rejected: string[] = []
  const rejectingBash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), {
    ...daemon,
    prepareApproval: async () => ({ id: 'approval', status: 'pending' }),
    waitForApproval: async () => ({ id: 'approval', status: 'native_fallback' }),
    cancelApproval: async () => {
      rejected.push('cancel')
      return { id: 'approval', status: 'cancelled' }
    },
    execStart: async () => {
      rejected.push('exec')
      throw new Error('must not execute')
    },
  } as never)
  await expect(
    rejectingBash.execute({ command: 'echo no' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: new AbortController().signal,
      ask: async () => {
        throw new Error('rejected')
      },
      metadata: () => {},
    } as never)
  ).rejects.toThrow('rejected')
  expect(rejected).toEqual(['cancel'])
})

test('bash rejects nonterminal exec results rather than claiming completion', async () => {
  const bash = createBash(async () => ({ action: 'allow', workdir: process.cwd() }), {
    execStart: async () => ({ id: 'exec', status: 'running', mode: 'exec', pid: 1 }),
    execWait: async () => ({
      session: { id: 'exec', status: 'running', mode: 'exec', pid: 1 },
      stdout: 'partial',
      stderr: '',
      timedOut: false,
      outputLimited: false,
      terminationConfirmed: false,
      startedAt: '',
      exitedAt: '',
    }),
    stop: async () => ({ terminationConfirmed: false }),
  } as never)

  await expect(
    bash.execute({ command: 'echo partial' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: new AbortController().signal,
      ask: async () => {},
      metadata: () => {},
    } as never)
  ).rejects.toThrow('without terminal evidence')
})

test('bash cancels durable approval when native ctx.ask is unavailable', async () => {
  const calls: string[] = []
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), {
    prepareApproval: async () => ({ id: 'approval', status: 'pending' }),
    waitForApproval: async () => ({ id: 'approval', status: 'native_fallback' }),
    cancelApproval: async () => {
      calls.push('cancel')
      return { id: 'approval', status: 'cancelled' }
    },
    execStart: async () => {
      calls.push('start')
      return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
    },
    execWait: async () => {
      throw new Error('must not wait')
    },
    stop: async () => ({ terminationConfirmed: true }),
  } as never)
  await expect(
    bash.execute({ command: 'echo no' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: new AbortController().signal,
      metadata: () => {},
    } as never)
  ).rejects.toThrow('approval is unavailable')
  expect(calls).toEqual(['cancel'])
})

test('bash reuses a matching session grant without native approval', async () => {
  const calls: string[] = []
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), {
    prepareApproval: async () => ({ status: 'approved_session' }),
    execStart: async () => {
      calls.push('start')
      return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
    },
    execWait: async () => ({
      session: { id: 'exec', status: 'exited', mode: 'exec', pid: 1 },
      stdout: '',
      stderr: '',
      timedOut: false,
      outputLimited: false,
      terminationConfirmed: true,
      startedAt: '',
      exitedAt: '',
    }),
    stop: async () => ({ terminationConfirmed: true }),
  } as never)
  await expect(
    bash.execute({ command: 'echo granted' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: new AbortController().signal,
      ask: async () => {
        calls.push('ask')
      },
      metadata: () => {},
    } as never)
  ).resolves.toContain('status="exited"')
  expect(calls).toEqual(['start'])
})

test('bash retains the external directory ask when not locally allowed', async () => {
  const calls: string[] = []
  const external = await mkdtemp(join(tmpdir(), 'opencode-pty-bash-external-ask-'))
  roots.push(external)
  const externalPattern = `${resolve(external, '..').replace(/\\/g, '/')}/*`
  const bash = createBash(
    async () => ({ action: 'allow', workdir: external, externalPattern, externalAction: 'ask' }),
    {
      execStart: async () => {
        calls.push('start')
        return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
      },
      execWait: async () => ({
        session: { id: 'exec', status: 'exited', mode: 'exec', pid: 1 },
        stdout: '',
        stderr: '',
        timedOut: false,
        outputLimited: false,
        terminationConfirmed: true,
        startedAt: '',
        exitedAt: '',
      }),
      stop: async () => ({ terminationConfirmed: true }),
    } as never
  )
  await expect(
    bash.execute({ command: 'echo external' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: new AbortController().signal,
      ask: async (request: { permission: string; patterns: string[]; always: string[] }) => {
        calls.push(`ask:${request.permission}`)
        expect(request.patterns).toEqual([externalPattern])
        expect(request.always).toEqual([externalPattern])
      },
      metadata: () => {},
    } as never)
  ).resolves.toContain('status="exited"')
  expect(calls).toEqual(['ask:external_directory', 'start'])
})

test('bash accepts a companion session decision without native ctx.ask', async () => {
  const calls: string[] = []
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), {
    prepareApproval: async () => ({ id: 'approval', status: 'pending' }),
    waitForApproval: async () => ({ id: 'approval', status: 'approved_session' }),
    consumeApproval: async () => {
      calls.push('consume')
      return { id: 'approval', status: 'approved_session' }
    },
    execStart: async () => {
      calls.push('start')
      return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
    },
    execWait: async () => ({
      session: { id: 'exec', status: 'exited', mode: 'exec', pid: 1 },
      stdout: '',
      stderr: '',
      timedOut: false,
      outputLimited: false,
      terminationConfirmed: true,
      startedAt: '',
      exitedAt: '',
    }),
    stop: async () => ({ terminationConfirmed: true }),
  } as never)
  await expect(
    bash.execute({ command: 'echo granted' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: new AbortController().signal,
      ask: async () => calls.push('ask'),
      metadata: () => {},
    } as never)
  ).resolves.toContain('status="exited"')
  expect(calls).toEqual(['consume', 'start'])
})

test('bash never launches a rejected companion approval', async () => {
  const calls: string[] = []
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), {
    prepareApproval: async () => ({ id: 'approval', status: 'pending' }),
    waitForApproval: async () => ({ id: 'approval', status: 'rejected' }),
    consumeApproval: async () => ({ id: 'approval', status: 'rejected' }),
    cancelApproval: async () => ({ id: 'approval', status: 'cancelled' }),
    execStart: async () => {
      calls.push('start')
      return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
    },
    execWait: async () => {
      throw new Error('must not wait')
    },
    stop: async () => ({ terminationConfirmed: true }),
  } as never)
  await expect(
    bash.execute({ command: 'echo rejected' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: new AbortController().signal,
      ask: async () => calls.push('ask'),
      metadata: () => {},
    } as never)
  ).rejects.toThrow('not granted')
  expect(calls).toEqual([])
})

test('Bash asks again when a session grant belongs to another agent', async () => {
  const calls: string[] = []
  const granted = bashApprovalCapability('agent-a')
  expect(granted).not.toContain('agent-a')
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), {
    prepareApproval: async (request: { capability: string }) =>
      request.capability === granted
        ? { status: 'approved_session' }
        : { id: 'approval', status: 'pending' },
    approveNativeApproval: async () => ({ id: 'approval', status: 'approved_once' }),
    waitForApproval: async () => ({ id: 'approval', status: 'native_fallback' }),
    consumeApproval: async () => ({ id: 'approval', status: 'consumed' }),
    cancelApproval: async () => ({ id: 'approval', status: 'cancelled' }),
    execStart: async () => ({ id: 'exec', status: 'running', mode: 'exec', pid: 1 }),
    execWait: async () => ({
      session: { id: 'exec', status: 'exited', mode: 'exec', pid: 1 },
      stdout: '',
      stderr: '',
      timedOut: false,
      outputLimited: false,
      terminationConfirmed: true,
      startedAt: '',
      exitedAt: '',
    }),
    stop: async () => ({ terminationConfirmed: true }),
  } as never)
  const context = (agent: string) =>
    ({
      sessionID: 'test-session',
      directory: process.cwd(),
      agent,
      abort: new AbortController().signal,
      ask: async () => calls.push(`ask:${agent}`),
      metadata: () => {},
    }) as never

  await bash.execute({ command: 'echo granted' }, context('agent-a'))
  await bash.execute({ command: 'echo granted' }, context('agent-b'))
  expect(calls).toEqual(['ask:agent-b'])
})

test('bash asks when no matching session grant is available', async () => {
  const calls: string[] = []
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), {
    prepareApproval: async () => ({ id: 'approval', status: 'pending' }),
    waitForApproval: async () => ({ id: 'approval', status: 'native_fallback' }),
    approveNativeApproval: async () => {
      calls.push('approve')
      return { id: 'approval', status: 'approved_once' }
    },
    consumeApproval: async () => ({ id: 'approval', status: 'consumed' }),
    cancelApproval: async () => ({ id: 'approval', status: 'cancelled' }),
    execStart: async () => ({ id: 'exec', status: 'running', mode: 'exec', pid: 1 }),
    execWait: async () => ({
      session: { id: 'exec', status: 'exited', mode: 'exec', pid: 1 },
      stdout: '',
      stderr: '',
      timedOut: false,
      outputLimited: false,
      terminationConfirmed: true,
      startedAt: '',
      exitedAt: '',
    }),
    stop: async () => ({ terminationConfirmed: true }),
  } as never)
  await bash.execute({ command: 'echo expired' }, {
    sessionID: 'test-session',
    directory: process.cwd(),
    agent: 'test',
    abort: new AbortController().signal,
    ask: async () => {
      calls.push('ask')
    },
    metadata: () => {},
  } as never)
  expect(calls).toEqual(['ask', 'approve'])
})

test('bash abort cancels pending approval before dispatch', async () => {
  const calls: string[] = []
  const controller = new AbortController()
  const bash = createBash(async () => ({ action: 'ask', workdir: process.cwd() }), {
    prepareApproval: async () => ({ id: 'approval', status: 'pending' }),
    waitForApproval: async () => ({ id: 'approval', status: 'native_fallback' }),
    approveNativeApproval: async () => ({ id: 'approval', status: 'approved_once' }),
    consumeApproval: async () => ({ id: 'approval', status: 'consumed' }),
    cancelApproval: async () => {
      calls.push('cancel')
      return { id: 'approval', status: 'cancelled' }
    },
    execStart: async () => {
      calls.push('start')
      return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
    },
    execWait: async () => {
      throw new Error('must not wait')
    },
    stop: async () => ({ terminationConfirmed: true }),
  } as never)
  await expect(
    bash.execute({ command: 'echo no' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: controller.signal,
      ask: async () => {
        controller.abort()
      },
      metadata: () => {},
    } as never)
  ).rejects.toThrow('cancelled')
  expect(calls).toEqual(['cancel'])
})

test('bash abort stops dispatched exec and waits for terminal evidence', async () => {
  const calls: string[] = []
  const controller = new AbortController()
  const bash = createBash(async () => ({ action: 'allow', workdir: process.cwd() }), {
    execStart: async () => {
      calls.push('start')
      return { id: 'exec', status: 'running', mode: 'exec', pid: 1 }
    },
    execWait: async (
      _id: string,
      timeoutSeconds: number,
      _owner: unknown,
      signal?: AbortSignal
    ) => {
      calls.push(`wait:${timeoutSeconds}`)
      if (signal) {
        controller.abort()
        throw new DOMException('aborted', 'AbortError')
      }
      return {
        session: { id: 'exec', status: 'exited', mode: 'exec', pid: 1 },
        stdout: '',
        stderr: '',
        timedOut: false,
        outputLimited: false,
        terminationConfirmed: true,
        startedAt: '',
        exitedAt: '',
      }
    },
    stop: async () => {
      calls.push('stop')
      return { terminationConfirmed: true }
    },
  } as never)
  await expect(
    bash.execute({ command: 'echo no' }, {
      sessionID: 'test-session',
      directory: process.cwd(),
      agent: 'test',
      abort: controller.signal,
      ask: async () => {},
      metadata: () => {},
    } as never)
  ).rejects.toThrow('termination_confirmed=true')
  expect(calls).toEqual(['start', 'wait:125', 'stop', 'wait:5'])
})

test.skipIf(!existsSync(nativeWorkerPath))(
  'bash execStart stop reaches a terminal daemon record',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-bash-abort-'))
    roots.push(root)
    const previousPath = process.env.PTY_NATIVE_WORKER_PATH
    process.env.PTY_NATIVE_WORKER_PATH = nativeWorkerPath
    const storage = new DaemonStorage(root)
    const server = new DaemonServer(storage, new SessionSupervisor(storage), 'bash-abort')
    try {
      const descriptor = await server.start()
      const context = await owner(storage, 'bash-abort', root)
      const started = (await rpc(
        descriptor,
        'execStart',
        {
          command: process.execPath,
          args: ['-e', 'setInterval(() => {}, 1000)'],
          timeoutSeconds: 10,
          workdir: root,
        },
        context
      ).then((response) => response.json())) as { result: { id: string } }
      const stopped = await rpc(descriptor, 'stop', { id: started.result.id }, context).then(
        (response) => response.json()
      )
      expect(stopped).toMatchObject({ result: { requested: true, terminationConfirmed: true } })
      const terminal = await rpc(
        descriptor,
        'execWait',
        { id: started.result.id, timeoutSeconds: 5 },
        context
      ).then((response) => response.json())
      expect(terminal).toMatchObject({
        result: { session: { status: 'exited' }, terminationConfirmed: true },
      })
    } finally {
      await server.stop()
      if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
      else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    }
  },
  10_000
)

test('bash override is opt-in and native Bash remains the default', async () => {
  const input = {
    client: { config: { get: async () => ({ data: { permission: { bash: 'allow' } } }) } },
    directory: process.cwd(),
  } as never
  expect((await PTYPlugin(input)).tool).not.toHaveProperty('bash')
  expect((await PTYPlugin(input, { bash: false })).tool).not.toHaveProperty('bash')
  const withBash = await PTYPlugin(input, { bash: true })
  expect(withBash.tool).toHaveProperty('bash')
  expect(withBash.tool).toHaveProperty('pty_spawn')
  expect(withBash.tool).toHaveProperty('shell_exec')
})

test('session deletion cleans up with the deleted session project owner', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-plugin-owner-'))
  const project = await mkdtemp(join(tmpdir(), 'opencode-pty-plugin-project-'))
  roots.push(root, project)
  const cleanupBySession = manager.cleanupBySession
  let cleanupOwner: Parameters<typeof manager.cleanupBySession>[0]
  manager.cleanupBySession = async (owner) => {
    cleanupOwner = owner
  }
  try {
    const plugin = await PTYPlugin({ client: {}, directory: root } as never)
    await plugin.event?.({
      event: {
        type: 'session.deleted',
        properties: { info: { id: 'deleted-session', directory: project } },
      },
    } as never)
    expect(cleanupOwner).toEqual(ownerContext('deleted-session', project))
    expect(cleanupOwner?.projectDirectory).not.toBe(realpathSync(root))
  } finally {
    manager.cleanupBySession = cleanupBySession
  }
})

test('streaming redaction keeps split secrets out of PTY journals and exec streams', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-redaction-stream-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const exec = await supervisor.nativeExec({
    command: process.execPath,
    args: [
      '-e',
      "process.stdout.write('before split-sec'); setTimeout(() => process.stdout.write('ret-value after\\n'), 20)",
    ],
    env: { API_TOKEN: 'split-secret-value' },
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 2,
  })
  expect(exec.stdout).toBe('before [REDACTED] after\n')
  expect(exec.stdout).not.toContain('split-secret-value')
  expect((await supervisor.execOutput(exec.session.id))?.stdout).not.toContain('split-secret-value')
})

test('Windows process identities require the queried PID and a creation time', () => {
  expect(parseWindowsProcessIdentity(42, 'windows:42:133713371337')).toBe('windows:42:133713371337')
  expect(parseWindowsProcessIdentity(42, 'windows:43:133713371337')).toBeNull()
  expect(parseWindowsProcessIdentity(42, 'windows:42:0')).toBeNull()
  expect(parseWindowsProcessIdentity(42, 'windows:42:0001')).toBeNull()
  expect(parseWindowsProcessIdentity(42, 'unexpected output')).toBeNull()
})

test('Windows process probe uses the system PowerShell path', () => {
  expect(windowsProcessIdentityCommand(42, 'C:\\Windows')?.[0]).toBe(
    resolve('C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  )
  expect(windowsProcessIdentityCommand(42, 'C:\\Windows')?.at(-1)).toContain('Get-Process -Id 42')
  expect(windowsProcessIdentityCommand(42, '')).toBeNull()
})

test('process identity probe returns null when its executable cannot launch', async () => {
  expect(
    await processIdentityProbe(
      ['opencode-pty-process-identity-probe-does-not-exist'],
      Date.now() + 1000
    )
  ).toBeNull()
})

test('process identity probe stops at its deadline', async () => {
  expect(
    await processIdentityProbe(
      [process.execPath, '-e', 'setTimeout(() => {}, 10_000)'],
      Date.now() + 25
    )
  ).toBeNull()
})

test.skipIf(process.platform !== 'win32')(
  'Windows process identity probe identifies the current process',
  async () => {
    expect(await processStartIdentity(process.pid)).toMatch(
      new RegExp(`^windows:${process.pid}:\\d+$`)
    )
  }
)

test('required process identity reports the failed probe', async () => {
  await expect(requiredProcessStartIdentity(process.pid, Date.now())).rejects.toThrow(
    /process.*probe failed/
  )
})

test('start lock creation fails safely when its identity probe deadline expires', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-start-lock-probe-failure-'))
  roots.push(root)
  await expect(new DaemonStorage(root).acquireStartLock(Date.now())).rejects.toThrow(
    /process.*probe failed/
  )
})

test('same-root storage initialization shares one attempt and retries failures', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-initialize-'))
  roots.push(root)
  const first = new DaemonStorage(root)
  const second = new DaemonStorage(join(root, '.'))
  let calls = 0
  const internals = first as unknown as { initializeRoot: () => Promise<void> }
  const original = internals.initializeRoot
  internals.initializeRoot = async () => {
    calls += 1
    await Bun.sleep(20)
  }
  try {
    await Promise.all([first.initialize(), second.initialize()])
    expect(calls).toBe(1)
  } finally {
    internals.initializeRoot = original
  }
})

test('storage caches only the current process identity per root', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-identity-cache-'))
  roots.push(root)
  const first = new DaemonStorage(root)
  const second = new DaemonStorage(root)
  const identity = await first.requiredCurrentProcessStartIdentity()
  expect(await second.requiredCurrentProcessStartIdentity(Date.now())).toBe(identity)
  expect(await processStartIdentity(process.pid)).toBe(identity)
})

test('start locks retain live owners and recover exactly one dead owner', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-start-lock-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const live = await storage.acquireStartLock()
  expect(typeof live?.token).toBe('string')
  expect(typeof live?.handoffToken).toBe('string')
  expect(await storage.acquireStartLock()).toBeNull()
  if (!live) throw new Error('Expected start lock.')
  await storage.releaseStartLock(live.token)
  await writeFile(
    join(root, 'daemon-start.lock'),
    JSON.stringify({ token: 'dead', pid: 2147483647, processIdentity: 'dead' })
  )
  const recovered = await Promise.all([storage.acquireStartLock(), storage.acquireStartLock()])
  expect(recovered.filter(Boolean)).toHaveLength(1)
  const recoveredLock = recovered.find((lock) => lock !== null)
  if (!recoveredLock) throw new Error('Expected recovered start lock.')
  await storage.releaseStartLock(recoveredLock.token)
})

test('concurrent recoverers claim one stale recovery lock', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-stale-recovery-lock-'))
  roots.push(root)
  const stale = JSON.stringify({
    token: 'dead',
    handoffToken: null,
    pid: 2147483647,
    processIdentity: 'dead',
  })
  await writeFile(join(root, 'daemon-start.lock'), stale)
  await writeFile(join(root, 'daemon-start-recovery.lock'), stale)

  const recovered = await Promise.all([
    new DaemonStorage(root).acquireStartLock(),
    new DaemonStorage(root).acquireStartLock(),
  ])
  expect(recovered.filter(Boolean)).toHaveLength(1)
  const recoveredLock = recovered.find((lock) => lock !== null)
  if (!recoveredLock) throw new Error('Expected recovered start lock.')
  await new DaemonStorage(root).releaseStartLock(recoveredLock.token)
})

test('recovery retains a lock replaced after observation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-replaced-recovery-lock-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const stale = { token: 'dead', handoffToken: null, pid: 2147483647, processIdentity: 'dead' }
  const replacement = { ...stale, token: 'replacement' }
  await storage.initialize()
  await writeFile(join(root, 'daemon-start-recovery.lock'), JSON.stringify(stale))
  const internals = storage as unknown as {
    startLockOwnerAlive: (...args: never[]) => Promise<boolean>
    acquireStartLockRecovery: () => Promise<boolean>
  }
  const ownerAlive = internals.startLockOwnerAlive
  internals.startLockOwnerAlive = async () => {
    await rm(join(root, 'daemon-start-recovery.lock'))
    await writeFile(join(root, 'daemon-start-recovery.lock'), JSON.stringify(replacement))
    return false
  }
  try {
    expect(await internals.acquireStartLockRecovery()).toBeFalse()
  } finally {
    internals.startLockOwnerAlive = ownerAlive
  }
  expect(JSON.parse(await readFile(join(root, 'daemon-start-recovery.lock'), 'utf8'))).toEqual(
    replacement
  )
})

test('start lock handoff permits one distinct daemon identity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-start-lock-handoff-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  if (!(await processStartIdentity(process.pid))) return
  const lock = await storage.acquireStartLock()
  if (!lock) throw new Error('Expected start lock.')

  const module = new URL('../src/daemon/storage.ts', import.meta.url).href
  const claim = async (token: string) => {
    const child = Bun.spawn({
      cmd: [
        process.execPath,
        '-e',
        `import { DaemonStorage } from ${JSON.stringify(module)}; process.stdout.write(String(Boolean(await new DaemonStorage(process.argv[1]).claimStartLock(process.argv[2]))))`,
        root,
        token,
      ],
      cwd: root,
      stdout: 'pipe',
      stderr: 'pipe',
    })
    const output = await new Response(child.stdout).text()
    expect(await child.exited).toBe(0)
    return output
  }
  expect(await claim('wrong-token')).toBe('false')
  expect(await claim(lock.handoffToken)).toBe('true')
  expect(await claim(lock.handoffToken)).toBe('false')
  expect(await storage.claimStartLock(lock.handoffToken)).toBeNull()
  await storage.releaseStartLock(lock.token)
  const claimed = JSON.parse(await readFile(join(root, 'daemon-start.lock'), 'utf8')) as {
    token: string
    handoffToken: string | null
    pid: number
  }
  expect(claimed).toMatchObject({ handoffToken: null })
  expect(claimed.token).not.toBe(lock.token)
  expect(claimed.pid).not.toBe(process.pid)
}, 30_000)

test('a claimed handoff lock survives its launching client and blocks duplicates', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-start-lock-claimed-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const lock = await storage.acquireStartLock()
  if (!lock) throw new Error('Expected start lock.')

  const module = new URL('../src/daemon/storage.ts', import.meta.url).href
  const child = Bun.spawn({
    cmd: [
      process.execPath,
      '-e',
      `import { DaemonStorage } from ${JSON.stringify(module)}; const storage = new DaemonStorage(process.argv[1]); const token = await storage.claimStartLock(process.argv[2]); process.stdout.write(token ? 'claimed' : 'missed'); await new Promise(() => {})`,
      root,
      lock.handoffToken,
    ],
    cwd: root,
    stdout: 'pipe',
    stderr: 'pipe',
  })
  try {
    const reader = child.stdout.getReader()
    const { value } = await reader.read()
    reader.releaseLock()
    expect(new TextDecoder().decode(value)).toBe('claimed')
    await storage.releaseStartLock(lock.token)
    expect(await storage.acquireStartLock()).toBeNull()
  } finally {
    child.kill()
    await child.exited
  }
}, 30_000)

test('start lock recovery removes crash remnants but retains a valid live lock', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-start-lock-remnants-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  for (const value of [
    '',
    '{',
    JSON.stringify({ token: 'old', handoffToken: null, pid: process.pid, processIdentity: 'old' }),
  ]) {
    await storage.initialize()
    await writeFile(join(root, 'daemon-start.lock'), value)
    const token = await storage.acquireStartLock()
    expect(typeof token?.token).toBe('string')
    expect(typeof token?.handoffToken).toBe('string')
    if (!token) throw new Error('Expected recovered start lock.')
    await storage.releaseStartLock(token.token)
  }
  const live = await storage.acquireStartLock()
  expect(typeof live?.token).toBe('string')
  expect(typeof live?.handoffToken).toBe('string')
  expect(await storage.acquireStartLock()).toBeNull()
  if (live) await storage.releaseStartLock(live.token)
}, 30_000)

test('start locks reject reused PIDs with a different process identity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-start-lock-identity-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const identity = await processStartIdentity(process.pid)
  if (!identity) return
  await storage.initialize()
  await writeFile(
    join(root, 'daemon-start.lock'),
    JSON.stringify({ token: 'old', pid: process.pid, processIdentity: `${identity}-old` })
  )
  const token = await storage.acquireStartLock()
  expect(typeof token?.token).toBe('string')
  expect(typeof token?.handoffToken).toBe('string')
  if (token) await storage.releaseStartLock(token.token)
})

test('claimed start locks recover a reused PID', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-claimed-lock-identity-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const identity = await processStartIdentity(process.pid)
  if (!identity) return
  const lock = await storage.acquireStartLock()
  if (!lock) throw new Error('Expected start lock.')
  const claimed = await storage.claimStartLock(lock.handoffToken)
  if (!claimed) throw new Error('Expected claimed start lock.')
  const persisted = JSON.parse(await readFile(join(root, 'daemon-start.lock'), 'utf8')) as {
    processIdentity: string | null
  }
  expect(persisted.processIdentity).toBe(identity)
  await writeFile(
    join(root, 'daemon-start.lock'),
    JSON.stringify({
      token: claimed,
      handoffToken: null,
      pid: process.pid,
      processIdentity: `${identity}-old`,
    })
  )
  const recovered = await storage.acquireStartLock()
  expect(typeof recovered?.token).toBe('string')
  if (recovered) await storage.releaseStartLock(recovered.token)
}, 30_000)

test('claimed handoff recovery locks with a reused PID do not block startup', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-claimed-recovery-lock-identity-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const lock = await storage.acquireStartLock()
  if (!lock) throw new Error('Expected start lock.')
  await writeFile(
    join(root, 'daemon-start-recovery.lock'),
    JSON.stringify({ token: 'old', handoffToken: null, pid: process.pid, processIdentity: null })
  )
  const claimed = await storage.claimStartLock(lock.handoffToken)
  expect(typeof claimed).toBe('string')
  if (claimed) await storage.releaseStartLock(claimed)
}, 30_000)

test('startup stderr tail redacts secrets and is null only when empty', () => {
  expect(
    safeStartupStderrTail(
      'daemon failed: startup-token-value startup-options-value',
      'startup-token-value',
      'startup-options-value'
    )
  ).toBe('daemon failed: [REDACTED] [REDACTED]')
  expect(safeStartupStderrTail('daemon failed: plain', 'startup-token-value')).toBe(
    'daemon failed: plain'
  )
  expect(safeStartupStderrTail('', 'startup-token-value')).toBeNull()
  expect(safeStartupStderrTail(undefined, 'startup-token-value')).toBeNull()
  expect(safeStartupStderrTail('   ', 'startup-token-value')).toBeNull()
})

test('descriptor ownership rejects a reused PID with a different process identity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-descriptor-identity-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const identity = await processStartIdentity(process.pid)
  if (!identity) return
  await storage.writeDescriptor({
    pid: process.pid,
    processIdentity: `${identity}-old`,
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: DAEMON_PROTOCOL_VERSION,
    token: 'old-token',
  })
  expect(await storage.descriptorOwnerAlive()).toBeFalse()
})

test('daemon stop leaves a replacement descriptor intact', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-descriptor-owner-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'first-token')
  await server.start()
  await storage.writeDescriptor({
    pid: process.pid,
    processIdentity: 'replacement',
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: DAEMON_PROTOCOL_VERSION,
    token: 'replacement-token',
  })
  await server.stop()
  expect((await storage.readDescriptor())?.token).toBe('replacement-token')
})

test('daemon rejects oversized content-length and chunked RPC bodies before JSON materialization', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-request-cap-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  const descriptor = await server.start()
  const headers = { authorization: 'Bearer test-token', 'content-type': 'application/json' }
  try {
    await expect(
      (server as unknown as { requestBody(request: Request): Promise<string> }).requestBody(
        new Request(`${descriptor.endpoint}/rpc`, {
          method: 'POST',
          headers: { ...headers, 'content-length': '1048577' },
          body: '{}',
        })
      )
    ).rejects.toThrow('too large')
    const chunked = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(1024 * 1024))
        controller.enqueue(new Uint8Array(1))
        controller.close()
      },
    })
    await expect(
      (server as unknown as { requestBody(request: Request): Promise<string> }).requestBody(
        new Request(`${descriptor.endpoint}/rpc`, {
          method: 'POST',
          headers,
          body: chunked,
          // Bun accepts request streams; browsers require this flag and ignore it here.
          duplex: 'half',
        } as RequestInit)
      )
    ).rejects.toThrow('too large')
  } finally {
    await server.stop()
  }
})

test('malformed session metadata is quarantined without blocking daemon recovery', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-malformed-session-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  await storage.initialize()
  const bad = join(root, 'sessions', 'pty_bad')
  await mkdir(bad)
  await writeFile(
    join(bad, 'session.json'),
    JSON.stringify({ id: 'pty_bad', command: 'test', args: [], status: 'not-a-status' }),
    'utf8'
  )
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  expect(await supervisor.list()).toEqual([])
  expect(await readdir(join(root, 'quarantine'))).toHaveLength(1)
})

test('corrupt journal quarantines only its session and preserves healthy recovery', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-corrupt-journal-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const healthy = record(root, 'pty_healthy', 'exited')
  const corrupt = record(root, 'pty_corrupt', 'exited')
  await storage.writeSession(healthy)
  await storage.appendOutput(healthy.id, [
    { startSequence: 0, endSequence: 3, timestamp: healthy.updatedAt, data: 'ok\n' },
  ])
  healthy.nextSequence = 3
  healthy.outputBytes = 3
  healthy.lineCount = 1
  await storage.writeSession(healthy)
  await storage.writeSession(corrupt)
  await mkdir(join(root, 'sessions', corrupt.id, 'output'))
  await writeFile(
    join(root, 'sessions', corrupt.id, 'output', '00000000000000000000.json'),
    '{"startSequence":0,"endSequence":1,"timestamp":"2026-01-01T00:00:00.000Z","data":"\\ud800"}',
    'utf8'
  )

  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()

  expect((await supervisor.list()).map((item) => item.id)).toEqual([healthy.id])
  expect(await supervisor.rawOutput(healthy.id)).toEqual({ raw: 'ok\n', byteLength: 3 })
  expect(await readdir(join(root, 'quarantine'))).toHaveLength(1)
})

test('invalid persistent fields quarantine before a valid legacy record migrates', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-session-fields-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const invalid = [
    { pid: null },
    { nextSequence: -1 },
    { nextSequence: 1, firstRetainedSequence: 2 },
    { nextSequence: 1, outputBytes: 2 },
    { outputJournalVersion: 99 },
    { createdAt: null },
    { parentSessionId: null },
  ]
  for (const [index, fields] of invalid.entries()) {
    const id = `pty_invalid_${index}`
    const session = record(root, id, 'exited')
    await storage.writeSession(session)
    await writeFile(
      join(root, 'sessions', id, 'session.json'),
      JSON.stringify({ ...session, ...fields })
    )
  }
  const legacy = record(root, 'pty_legacy_valid', 'exited')
  markTerminalProof(legacy)
  legacy.nextSequence = 7
  legacy.outputBytes = 7
  legacy.lineCount = 1
  await storage.writeSession(legacy)
  await writeFile(
    join(root, 'sessions', legacy.id, 'session.json'),
    JSON.stringify(
      Object.fromEntries(
        Object.entries(legacy).filter(
          ([key]) => key !== 'recordVersion' && key !== 'outputJournalVersion'
        )
      )
    )
  )
  await writeFile(join(root, 'sessions', legacy.id, 'output.log'), 'legacy\n', 'utf8')

  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()

  expect((await supervisor.list()).map((item) => item.id)).toEqual([legacy.id])
  expect(await supervisor.rawOutput(legacy.id)).toMatchObject({ raw: 'legacy\n', byteLength: 7 })
  expect(
    JSON.parse(await readFile(join(root, 'sessions', legacy.id, 'session.json'), 'utf8'))
  ).toMatchObject({
    recordVersion: SESSION_RECORD_VERSION,
    state: { kind: 'terminal', outcome: 'exited' },
  })
  expect(await Bun.file(join(root, 'sessions', legacy.id, 'output.log')).exists()).toBeFalse()
  expect(await readdir(join(root, 'quarantine'))).toHaveLength(invalid.length)
})

test('legacy terminal status without explicit proof becomes a cleanup tombstone', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v0-unproven-terminal-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v0_unproven', 'exited')
  session.nextSequence = 7
  session.outputBytes = 7
  session.lineCount = 1
  const legacy = Object.fromEntries(
    Object.entries(session).filter(
      ([key]) => key !== 'recordVersion' && key !== 'outputJournalVersion' && key !== 'state'
    )
  )
  await storage.writeSession(session)
  await writeFile(join(root, 'sessions', session.id, 'session.json'), JSON.stringify(legacy))
  const legacyOutput = join(root, 'sessions', session.id, 'output.log')
  await writeFile(legacyOutput, 'legacy\n', 'utf8')

  const first = new SessionSupervisor(storage)
  await first.initialize()
  expect(await first.get(session.id)).toMatchObject({ status: 'lost', lifecycle: 'conversation' })
  expect((await storage.loadSessions())[0]).toMatchObject({
    legacyTombstone: { sourceRecordVersion: 0, lastKnown: 'terminal' },
    directChildExited: false,
  })
  expect(await first.rawOutput(session.id)).toEqual({ raw: 'legacy\n', byteLength: 7 })
  expect(await Bun.file(legacyOutput).exists()).toBeTrue()

  const second = new SessionSupervisor(storage)
  await second.initialize()
  expect(await second.rawOutput(session.id)).toEqual({ raw: 'legacy\n', byteLength: 7 })
  expect(await Bun.file(legacyOutput).exists()).toBeTrue()
})

test('V0 records with null owner fields stay inert beside healthy sessions', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v0-null-owner-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const healthy = record(root, 'pty_v1_healthy', 'exited')
  const legacy = record(root, 'pty_v0_null_owner', 'running')
  await storage.writeSession(healthy)
  await storage.writeSession(legacy)
  const legacyPath = join(root, 'sessions', legacy.id, 'session.json')
  const rawLegacy = {
    ...Object.fromEntries(
      Object.entries(legacy).filter(
        ([key]) => key !== 'recordVersion' && key !== 'outputJournalVersion'
      )
    ),
    ownerCapabilityHash: null,
  }
  const rawBytes = JSON.stringify(rawLegacy)
  await writeFile(legacyPath, rawBytes, 'utf8')

  expect((await storage.loadSessions()).map((session) => session.id)).toEqual([healthy.id])
  expect(await readFile(legacyPath, 'utf8')).toBe(rawBytes)
  expect(await Bun.file(join(root, 'quarantine')).exists()).toBeFalse()
})

test('V2 retries legacy output cleanup left after terminal migration', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v1-legacy-output-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v1_cleanup', 'exited')
  markTerminalProof(session)
  session.nextSequence = 7
  session.outputBytes = 7
  session.lineCount = 1
  session.legacyOutputCleanupPending = true
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 7, timestamp: session.updatedAt, data: 'legacy\n' },
  ])
  const legacyOutput = join(root, 'sessions', session.id, 'output.log')
  await writeFile(legacyOutput, 'legacy\n', 'utf8')

  const loaded = await storage.loadSessions()
  expect(loaded).toHaveLength(1)
  expect(await storage.readOutput(session.id)).toBe('legacy\n')
  expect(await Bun.file(legacyOutput).exists()).toBeFalse()
  expect((await storage.loadSessions())[0]?.legacyOutputCleanupPending).toBeUndefined()
})

test('fragmented PTY output is coalesced and retained output stays bounded', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-fragmented-output-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_fragmented', 'exited')
  await storage.writeSession(session)
  const fragments = ['A', '😀', 'B']
  let sequence = 0
  for (const data of fragments) {
    const endSequence = sequence + Buffer.byteLength(data)
    await storage.appendOutput(session.id, [
      { startSequence: sequence, endSequence, timestamp: session.updatedAt, data },
    ])
    sequence = endSequence
  }
  for (let index = 0; index < 256; index += 1) {
    await storage.appendOutput(session.id, [
      {
        startSequence: sequence,
        endSequence: sequence + 1,
        timestamp: session.updatedAt,
        data: 'x',
      },
    ])
    sequence += 1
  }
  expect((await readdir(join(root, 'sessions', session.id, 'output'))).length).toBe(1)
  expect(await storage.readOutput(session.id)).toStartWith('A😀B')
  expect(await storage.trimOutput(session.id, 32)).toMatchObject({
    outputBytes: 0,
    outputTruncated: true,
  })
  expect(Buffer.byteLength(await storage.readOutput(session.id))).toBeLessThanOrEqual(32)
})

test('invalid PTY_MAX_OUTPUT_BYTES reports the effective safe default', () => {
  expect(effectiveMaxOutputBytes('invalid')).toBe(1000000)
  expect(effectiveMaxOutputBytes('0')).toBe(1000000)
})

test('pty_write and pty_send_wait use equivalent terminal escape decoding', () => {
  expect(parseEscapeSequences(String.raw`one\n\x03\u2192\\`)).toBe('one\n\x03→\\')
})

test('exec returns distinct stdout, stderr, exit, timeout, and output-limit evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage, 32)
  await supervisor.initialize()

  const success = await supervisor.nativeExec({
    command: process.execPath,
    args: ['-e', "console.log('out'); console.error('err')"],
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 2,
  })
  expect(success).toMatchObject({ stdout: 'out\n', stderr: 'err\n', exitCode: 0, timedOut: false })

  const failure = await supervisor.nativeExec({
    command: process.execPath,
    args: ['-e', "console.error('failed'); process.exit(7)"],
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 2,
  })
  expect(failure).toMatchObject({ stderr: 'failed\n', exitCode: 7, timedOut: false })

  const timeout = await supervisor.nativeExec({
    command: process.execPath,
    args: ['-e', 'setTimeout(() => {}, 5000)'],
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 1,
  })
  expect(timeout.timedOut).toBeTrue()

  const limited = await supervisor.nativeExec({
    command: process.execPath,
    args: ['-e', "process.stdout.write('x'.repeat(100))"],
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 2,
    maxOutputBytes: 8,
  })
  expect(limited).toMatchObject({ outputLimited: true, stdout: 'xxxxxxxx' })
  expect(await supervisor.execOutput(limited.session.id)).toMatchObject({
    stdout: 'xxxxxxxx',
    stderr: '',
    stdoutBytes: 8,
    stdoutTruncated: true,
  })
}, 15_000)

test('exec force-kills after grace and reports bounded, truthful termination state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-kill-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  await supervisor.initialize()
  const started = Date.now()
  const result = await supervisor.nativeExec({
    command: process.execPath,
    args: [
      '-e',
      process.platform === 'win32'
        ? 'setInterval(() => {}, 1000)'
        : "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)",
    ],
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 1,
  })
  expect(Date.now() - started).toBeLessThan(3000)
  expect(result.timedOut).toBeTrue()
  if (process.platform !== 'win32') expect(result.terminationConfirmed).toBeTrue()
})

test('exec truncation preserves complete UTF-8 text', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-utf8-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  await supervisor.initialize()
  const result = await supervisor.nativeExec({
    command: process.execPath,
    args: ['-e', "process.stdout.write('A😀B')"],
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 2,
    maxOutputBytes: 4,
  })
  expect(result.stdout).toBe('A')
  expect(Buffer.byteLength(result.stdout)).toBe(1)
})

test('exec truncation redacts a secret that crosses the output cap', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-redaction-limit-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const result = await supervisor.nativeExec({
    command: process.execPath,
    args: ['-e', "process.stdout.write('before-super-secret-value-after')"],
    env: { API_TOKEN: 'super-secret-value' },
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 2,
    maxOutputBytes: 12,
  })
  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  const durable = await recovered.execOutput(result.session.id)

  expect(result).toMatchObject({ outputLimited: true, stdout: 'before-[REDA' })
  expect(durable).toMatchObject({ stdout: 'before-[REDA', stdoutBytes: 12, stdoutTruncated: true })
  for (const output of [result.stdout, durable?.stdout]) {
    expect(output).not.toContain('super')
    expect(output).not.toContain('secret')
  }
})

test.skipIf(process.platform === 'win32')(
  'PTY idempotency reuses only an active matching owner and spec',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-idempotency-'))
    roots.push(root)
    const storage = new DaemonStorage(root)
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize()
    const options = {
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 5000)'],
      parentSessionId: 'owner',
      ...directOwner(root),
      workdir: root,
      name: 'server',
      idempotencyKey: 'deploy-1',
    }
    const first = await supervisor.spawn(options)
    const reused = await supervisor.spawn(options)
    expect(reused.id).toBe(first.id)
    expect(
      (
        await supervisor.spawn({
          ...options,
          title: 'renamed',
          description: 'changed presentation',
        })
      ).id
    ).toBe(first.id)
    await expect(supervisor.spawn({ ...options, args: ['-e', 'process.exit()'] })).rejects.toThrow(
      'different command or specification'
    )
    await expect(supervisor.spawn({ ...options, name: 'other-server' })).rejects.toThrow(
      'different command or specification'
    )
    await supervisor.stop(first.id)
    await Bun.sleep(25)
    await supervisor.flush()
  }
)

test.skipIf(process.platform === 'win32')(
  'PTY idempotency canonicalizes environment order and scopes by full owner identity',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-idempotency-scope-'))
    const otherRoot = await mkdtemp(join(tmpdir(), 'opencode-pty-idempotency-owner-'))
    roots.push(root)
    roots.push(otherRoot)
    const supervisor = new SessionSupervisor(new DaemonStorage(root))
    await supervisor.initialize()
    const base = {
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 5000)'],
      parentSessionId: 'owner',
      workdir: root,
      ownerProjectDirectory: root,
      ownerCapabilityHash: FIRST_OWNER_HASH,
      idempotencyKey: 'same',
      env: { A: '1', Z: '2' },
    }
    const first = await supervisor.spawn(base)
    expect((await supervisor.spawn({ ...base, env: { Z: '2', A: '1' } })).id).toBe(first.id)
    const other = await supervisor.spawn({
      ...base,
      ownerProjectDirectory: otherRoot,
      ownerCapabilityHash: SECOND_OWNER_HASH,
    })
    expect(other.id).not.toBe(first.id)
    await supervisor.stop(first.id)
    await supervisor.stop(other.id)
    await Bun.sleep(25)
    await supervisor.flush()
  }
)

test('PTY idempotency rejects a matching fingerprint with a different environment profile', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-idempotency-environment-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  await supervisor.initialize()
  const fingerprint = new Bun.CryptoHasher('sha256')
    .update(
      JSON.stringify(
        Object.entries(process.env).sort(([left], [right]) => left.localeCompare(right))
      )
    )
    .digest('hex')
  const existing = record(root, 'pty_existing')
  existing.idempotencyKey = 'same'
  existing.ownerCapabilityHash = IDEMPOTENCY_OWNER_HASH
  existing.environment = { kind: 'safe', keys: [], fingerprint, sensitive: false }
  const state = supervisor as unknown as {
    records: Map<string, SessionRecord>
    idempotentSession: (options: SpawnOptions, args: string[]) => SessionRecord | undefined
  }
  state.records.set(existing.id, existing)

  expect(() =>
    state.idempotentSession(
      {
        command: 'test',
        parentSessionId: 'parent',
        workdir: root,
        ownerProjectDirectory: root,
        ownerCapabilityHash: IDEMPOTENCY_OWNER_HASH,
        idempotencyKey: 'same',
        inheritEnv: true,
      },
      []
    )
  ).toThrow('different command or specification')
})

test('PTY idempotency does not cross owner capabilities', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-idempotency-capability-'))
  const otherRoot = await mkdtemp(join(tmpdir(), 'opencode-pty-idempotency-capability-owner-'))
  roots.push(root, otherRoot)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  const existing = record(root, 'pty_existing')
  const environment = runtimeEnvironment(undefined, false)
  existing.idempotencyKey = 'same'
  existing.ownerCapabilityHash = FIRST_OWNER_HASH
  existing.environment = {
    kind: 'safe',
    keys: [],
    fingerprint: new Bun.CryptoHasher('sha256')
      .update(
        JSON.stringify(
          Object.entries(environment).sort(([left], [right]) => left.localeCompare(right))
        )
      )
      .digest('hex'),
    sensitive: false,
  }
  const state = supervisor as unknown as {
    records: Map<string, SessionRecord>
    idempotentSession: (options: SpawnOptions, args: string[]) => SessionRecord | undefined
  }
  state.records.set(existing.id, existing)

  expect(
    state.idempotentSession(
      {
        command: 'test',
        parentSessionId: 'parent',
        workdir: root,
        ownerProjectDirectory: root,
        ownerCapabilityHash: FIRST_OWNER_HASH,
        idempotencyKey: 'same',
      },
      []
    )
  ).toBe(existing)
  expect(
    state.idempotentSession(
      {
        command: 'test',
        parentSessionId: 'parent',
        workdir: root,
        ownerProjectDirectory: otherRoot,
        ownerCapabilityHash: SECOND_OWNER_HASH,
        idempotencyKey: 'same',
      },
      []
    )
  ).toBeUndefined()
})

test.skipIf(process.platform === 'win32')(
  'daemon waits for output, exit, and deadline without plugin polling',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-wait-'))
    roots.push(root)
    const storage = new DaemonStorage(root)
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize()
    const session = await supervisor.spawn({
      command: process.execPath,
      args: [
        '-e',
        "setTimeout(() => console.log('ready'), 50); setTimeout(() => process.exit(3), 100)",
      ],
      parentSessionId: 'parent',
      ...directOwner(root),
      workdir: root,
    })
    await Bun.sleep(50)
    await expect(
      supervisor.wait(session.id, { kind: 'output', literal: 'ready' }, 2)
    ).resolves.toMatchObject({
      satisfied: true,
      reason: 'output',
      matched: 'ready',
    })
    await expect(supervisor.wait(session.id, { kind: 'exit' }, 2)).resolves.toMatchObject({
      satisfied: true,
      reason: 'exit',
      exitCode: 3,
    })
    const running = await supervisor.spawn({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 5000)'],
      parentSessionId: 'parent',
      ...directOwner(root),
      workdir: root,
    })
    await expect(
      supervisor.wait(running.id, { kind: 'output', regex: 'never' }, 1)
    ).resolves.toMatchObject({
      satisfied: false,
      reason: 'deadline',
    })
    await expect(
      supervisor.wait(running.id, { kind: 'output', regex: '(never)+' }, 1)
    ).rejects.toThrow('limited-safe')
    await supervisor.stop(running.id)
    await Bun.sleep(25)
    await supervisor.flush()
  }
)

test('native exec wait stops a running record after its deadline and requires terminal evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-wait-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  const session = record(root, 'exec_wait_deadline')
  session.mode = 'exec'
  const state = supervisor as unknown as {
    records: Map<string, SessionRecord>
    wait: (id: string, condition: unknown, timeoutSeconds: number) => Promise<{ reason: string }>
    stop: (id: string) => Promise<unknown>
  }
  state.records.set(session.id, session)
  const waits: number[] = []
  let stops = 0
  state.wait = async (_id, _condition, timeoutSeconds) => {
    waits.push(timeoutSeconds)
    if (waits.length === 1) return { reason: 'deadline' }
    session.status = 'exited'
    session.terminationConfirmed = true
    session.directChildExited = true
    session.containment = { ...workerSnapshot().containment, status: 'not_applicable' }
    return { reason: 'exit' }
  }
  state.stop = async () => {
    stops += 1
    session.status = 'stopping'
    return {}
  }

  await expect(supervisor.nativeExecWait(session.id, 1)).resolves.toMatchObject({
    session: { status: 'exited' },
    terminationConfirmed: true,
  })
  expect(waits).toEqual([1, 5])
  expect(stops).toBe(1)
})

test('native exec wait rejects a record still active after stop', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-wait-active-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  const session = record(root, 'exec_wait_active')
  session.mode = 'exec'
  const state = supervisor as unknown as {
    records: Map<string, SessionRecord>
    wait: () => Promise<{ reason: string }>
    stop: () => Promise<unknown>
  }
  state.records.set(session.id, session)
  state.wait = async () => ({ reason: 'deadline' })
  state.stop = async () => ({})

  await expect(supervisor.nativeExecWait(session.id, 1)).rejects.toThrow(
    'stop completed without terminal evidence'
  )
})

test('native exec wait returns its finalization storage failure', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-wait-storage-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  const session = record(root, 'exec_wait_storage')
  session.mode = 'exec'
  session.status = 'lost'
  const storageError = Object.assign(new Error('Native finalization failed: ENOENT'), {
    code: 'ESTORAGE',
  })
  const state = supervisor as unknown as {
    records: Map<string, SessionRecord>
    nativeFinalizations: Map<string, Promise<unknown>>
    wait: () => Promise<{ reason: string }>
  }
  const finalization = Promise.reject(storageError)
  void finalization.catch(() => undefined)
  state.records.set(session.id, session)
  state.nativeFinalizations.set(session.id, finalization)
  state.wait = async () => ({ reason: 'exit' })

  await expect(supervisor.nativeExecWait(session.id, 1)).rejects.toBe(storageError)
})

test('native exec allows the bounded terminal grace after maximum runtime', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-max-timeout-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  const state = supervisor as unknown as {
    nativeExecStart: () => Promise<{ id: string }>
    nativeExecWait: (id: string, timeoutSeconds: number) => Promise<unknown>
  }
  let timeout: number | undefined
  state.nativeExecStart = async () => ({ id: 'exec_max' })
  state.nativeExecWait = async (_id, timeoutSeconds) => {
    timeout = timeoutSeconds
    return {}
  }

  for (const [timeoutSeconds, expectedWait] of [
    [3596, 3601],
    [3600, 3605],
  ]) {
    await supervisor.nativeExec({
      command: 'test',
      parentSessionId: 'parent',
      ...directOwner(root),
      timeoutSeconds,
      workdir: root,
    })
    expect(timeout).toBe(expectedWait)
  }
})

test.skipIf(process.platform === 'win32')(
  'sendWait ignores output before input acceptance and waits for later output',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-send-wait-'))
    roots.push(root)
    const supervisor = new SessionSupervisor(new DaemonStorage(root))
    await supervisor.initialize()
    const session = await supervisor.spawn({
      command: process.execPath,
      args: [
        '-e',
        "process.stdin.setRawMode(true); console.log('ready'); process.stdin.once('data', (data) => { if (data.includes('go')) { console.log('ready'); process.exit(0) } })",
      ],
      parentSessionId: 'parent',
      ...directOwner(root),
      workdir: root,
    })
    try {
      await expect(
        supervisor.wait(session.id, { kind: 'output', literal: 'ready' }, 2)
      ).resolves.toMatchObject({ satisfied: true, reason: 'output', matched: 'ready' })
      expect((await supervisor.read(session.id)).lines.join('\n')).toContain('ready')
      const result = await supervisor.sendWait(
        session.id,
        'go\n',
        { kind: 'output', literal: 'ready' },
        2
      )
      expect(result).toMatchObject({ satisfied: true, reason: 'output', matched: 'ready' })
      const exit = await supervisor.wait(session.id, { kind: 'exit' }, 2)
      expect(exit).toMatchObject({ satisfied: true, reason: 'exit', exitCode: 0 })
      expect((await supervisor.get(session.id))?.lastWaitResult).toMatchObject({ reason: 'exit' })
    } finally {
      await supervisor.stop(session.id).catch(() => undefined)
      await supervisor.flush()
    }
  }
)

test.skipIf(process.platform === 'win32')(
  'sendWait observes an immediate response after accepted input',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-send-wait-immediate-'))
    roots.push(root)
    const supervisor = new SessionSupervisor(new DaemonStorage(root))
    await supervisor.initialize()
    const session = await supervisor.spawn({
      command: process.execPath,
      args: [
        '-e',
        "process.stdin.setRawMode(true); process.stdin.once('data', () => { process.stdout.write('immediate\\n') })",
      ],
      parentSessionId: 'parent',
      ...directOwner(root),
      workdir: root,
    })
    try {
      await expect(
        supervisor.sendWait(session.id, 'x', { kind: 'output', literal: 'immediate' }, 2)
      ).resolves.toMatchObject({ satisfied: true, reason: 'output', matched: 'immediate' })
    } finally {
      await supervisor.stop(session.id).catch(() => undefined)
      await supervisor.flush()
    }
  }
)

test.skipIf(process.platform === 'win32')(
  'sendWait excludes drained pre-acceptance output and observes its immediate reply',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-send-wait-buffered-'))
    roots.push(root)
    const marker = join(root, 'buffered')
    let watcher: ReturnType<typeof watch> | undefined
    const markerReady = new Promise<void>((resolve, reject) => {
      watcher = watch(root, (_event, filename) => {
        if (filename !== 'buffered') return
        watcher?.close()
        resolve()
      })
      watcher.on('error', reject)
    })
    const supervisor = new SessionSupervisor(new DaemonStorage(root))
    await supervisor.initialize()
    const session = await withProcessEnv(
      { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'pause_terminal_reader_until_write' },
      () =>
        supervisor.spawn({
          command: process.execPath,
          args: [
            '-e',
            `process.stdin.setRawMode(true); process.stdout.write('old\\n'); require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ready'); process.stdin.once('data', () => process.stdout.write('new\\n'))`,
          ],
          parentSessionId: 'parent',
          ...directOwner(root),
          workdir: root,
        })
    )
    try {
      await markerReady
      expect(existsSync(marker)).toBeTrue()
      await expect(
        supervisor.sendWait(session.id, 'x', { kind: 'output', regex: 'old|new' }, 1)
      ).resolves.toMatchObject({ satisfied: true, reason: 'output', matched: 'new' })
    } finally {
      watcher?.close()
      await supervisor.stop(session.id).catch(() => undefined)
      await supervisor.flush()
    }
  }
)

test.skipIf(process.platform === 'win32')(
  'sendWait flushes a held redaction tail before its input boundary',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-send-wait-redaction-tail-'))
    roots.push(root)
    const marker = join(root, 'buffered')
    let watcher: ReturnType<typeof watch> | undefined
    const markerReady = new Promise<void>((resolve, reject) => {
      watcher = watch(root, (_event, filename) => {
        if (filename !== 'buffered') return
        watcher?.close()
        resolve()
      })
      watcher.on('error', reject)
    })
    const supervisor = new SessionSupervisor(new DaemonStorage(root))
    await supervisor.initialize()
    const session = await withProcessEnv(
      { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'pause_terminal_reader_until_write' },
      () =>
        supervisor.spawn({
          command: process.execPath,
          args: [
            '-e',
            `process.stdin.setRawMode(true); process.stdout.write('old-match'); require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ready'); process.stdin.once('data', () => process.stdout.write('new-match\\n'))`,
          ],
          env: { API_TOKEN: 'tail-secret' },
          parentSessionId: 'parent',
          ...directOwner(root),
          workdir: root,
        })
    )
    try {
      await markerReady
      await expect(
        supervisor.sendWait(session.id, 'x', { kind: 'output', regex: 'old-match|new-match' }, 1)
      ).resolves.toMatchObject({ satisfied: true, reason: 'output', matched: 'new-match' })
      expect((await supervisor.read(session.id)).lines.join('\n')).not.toContain('tail-secret')
    } finally {
      watcher?.close()
      await supervisor.stop(session.id).catch(() => undefined)
      await supervisor.flush()
    }
  }
)

test('exec output remains separately recoverable after restart', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-record-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const result = await supervisor.nativeExec({
    command: process.execPath,
    args: ['-e', "process.stdout.write('out'); process.stderr.write('err')"],
    parentSessionId: 'parent',
    ...directOwner(root),
    workdir: root,
    timeoutSeconds: 2,
  })
  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  expect(await recovered.execOutput(result.session.id)).toMatchObject({
    stdout: 'out',
    stderr: 'err',
    stdoutBytes: 3,
    stderrBytes: 3,
    stdoutTruncated: false,
    stderrTruncated: false,
  })
})

test('native exec through the daemon drains both streams, reconnects, stops, and cleans up', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-integration-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-owner', root)
  const first = new DaemonServer(storage, new SessionSupervisor(storage), 'native-first')
  let restarted: DaemonServer | undefined
  try {
    const firstDescriptor = await first.start()
    const executing = rpc(
      firstDescriptor,
      'exec',
      {
        command: process.execPath,
        args: [
          '-e',
          "process.stdout.write('native-out'); process.stderr.write('native-err'); setTimeout(() => {}, 10000)",
        ],
        timeoutSeconds: 8,
        maxOutputBytes: 1024,
        lifecycle: 'persistent',
        workdir: root,
      },
      context
    )
    let id = ''
    for (let attempt = 0; attempt < 50 && !id; attempt += 1) {
      const sessions = await storage.loadSessions()
      id = sessions.find((session) => session.mode === 'exec')?.id ?? ''
      if (!id) await Bun.sleep(20)
    }
    expect(id).not.toBe('')
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if ((await storage.loadSessions()).find((session) => session.id === id)?.worker) break
      await Bun.sleep(20)
    }
    expect(
      (await storage.loadSessions()).find((session) => session.id === id)?.worker
    ).toBeDefined()
    const outputWait = await rpc(
      firstDescriptor,
      'wait',
      { id, condition: { kind: 'output', literal: 'native-out' }, timeoutSeconds: 5 },
      context
    ).then((response) => response.json())
    expect(outputWait).toMatchObject({
      result: { satisfied: true, reason: 'output', matched: 'native-out' },
    })
    await first.stop()
    restarted = new DaemonServer(storage, new SessionSupervisor(storage), 'native-second')
    const secondDescriptor = await restarted.start()
    let stopped: { result?: { requested: boolean; terminationConfirmed: boolean } } | undefined
    for (let attempt = 0; attempt < 50 && !stopped?.result?.requested; attempt += 1) {
      stopped = (await rpc(secondDescriptor, 'stop', { id }, context).then((response) =>
        response.json()
      )) as { result?: { requested: boolean; terminationConfirmed: boolean } }
      if (!stopped.result?.requested) await Bun.sleep(20)
    }
    expect(stopped).toMatchObject({
      result: { requested: true, terminationConfirmed: true },
    })
    const details = await rpc(secondDescriptor, 'get', { id }, context)
    expect(
      (await details.json()) as { result: { status: string; terminationConfirmed: boolean } }
    ).toMatchObject({
      result: {
        status: 'exited',
        terminationConfirmed: true,
        ...(process.platform === 'win32' ? { containment: { status: 'windows_job_empty' } } : {}),
      },
    })
    await expect(executing.then((response) => response.json())).resolves.toMatchObject({
      result: { stdout: 'native-out', stderr: 'native-err', terminationConfirmed: true },
    })
    const chunks = await storage.readOutputChunks(id)
    expect(chunks.map((chunk) => chunk.data).join('')).toContain('native-out')
    expect(chunks.every((chunk) => /^\d{4}-\d{2}-\d{2}T.*Z$/.test(chunk.timestamp))).toBeTrue()
    await expect(
      rpc(
        secondDescriptor,
        'cleanupByParentSession',
        { parentSessionId: context.parentSessionId },
        context
      ).then((response) => response.json())
    ).resolves.toMatchObject({ ok: true })
    await expect(stat(join(root, 'sessions', id, 'worker.json'))).rejects.toThrow()
  } finally {
    await restarted?.stop()
    await first.stop().catch(() => undefined)
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 10_000)

test('native exec uses a total stdout/stderr cap and persists terminal storage failure', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-limits-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-limits', root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-limits')
  try {
    const descriptor = await server.start()
    await Bun.sleep(100)
    const capped = await rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: ['-e', "process.stdout.write('x'.repeat(64)); process.stderr.write('y'.repeat(64))"],
        timeoutSeconds: 2,
        maxOutputBytes: 64,
        workdir: root,
      },
      context
    ).then((response) => response.json())
    expect(capped).toMatchObject({ result: { outputLimited: true } })
    expect(
      (capped as { result: { stdout: string; stderr: string } }).result.stdout +
        (capped as { result: { stdout: string; stderr: string } }).result.stderr
    ).toMatch(/^[xy]{64}$/)

    const failing = rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: ['-e', "setTimeout(() => process.stdout.write('will fail'), 200)"],
        timeoutSeconds: 3,
        workdir: root,
      },
      context
    )
    let id = ''
    for (let attempt = 0; attempt < 50 && !id; attempt += 1) {
      id =
        (await storage.loadSessions()).find(
          (session) => session.mode === 'exec' && !session.execOutput
        )?.id ?? ''
      if (!id) await Bun.sleep(20)
    }
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if ((await storage.loadSessions()).find((session) => session.id === id)?.worker) break
      await Bun.sleep(20)
    }
    expect(
      (await storage.loadSessions()).find((session) => session.id === id)?.worker
    ).toBeDefined()
    await rm(join(root, 'sessions', id, 'output'), { recursive: true, force: true })
    await writeFile(join(root, 'sessions', id, 'output'), 'not a directory')
    expect(await failing.then((response) => response.json())).toMatchObject({
      ok: false,
      error: { code: 'storage', message: expect.stringContaining('Native finalization failed') },
    })
    expect(
      await rpc(descriptor, 'get', { id }, context).then((response) => response.json())
    ).toMatchObject({
      result: { status: 'lost', terminationConfirmed: true },
    })
    await expect(stat(join(root, 'sessions', id, 'worker.json'))).rejects.toThrow()
  } finally {
    await server.stop()
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 10_000)

test('native startup failures retain unproven child state and report no-child outcomes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-startup-failure-'))
  roots.push(root)
  await stat(nativeWorkerPath)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_PATH = nativeWorkerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-startup-failure', root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-startup-failure')
  try {
    const descriptor = await server.start()
    const descriptorFailure = await withProcessEnv(
      { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'descriptor_write' },
      () =>
        rpc(
          descriptor,
          'exec',
          {
            command: process.execPath,
            args: ['-e', 'setInterval(() => {}, 1000)'],
            timeoutSeconds: 2,
            workdir: root,
          },
          context
        ).then((response) => response.json())
    )
    expect(descriptorFailure).toMatchObject({
      ok: false,
      error: { code: 'process', spawnFailure: { cleanup: { terminationConfirmed: true } } },
    })
    const descriptorRecord = (await storage.loadSessions()).at(-1)
    expect(descriptorRecord).toMatchObject({
      status: 'lost',
      lastKnown: 'creating',
      terminationConfirmed: true,
      exitReason: { kind: 'spawn_error', cleanup: { terminationConfirmed: true } },
    })

    const commandFailure = await rpc(
      descriptor,
      'exec',
      {
        command: join(root, 'does-not-exist'),
        args: [],
        timeoutSeconds: 2,
        workdir: root,
      },
      context
    ).then((response) => response.json())
    expect(commandFailure).toMatchObject({
      ok: false,
      error: {
        code: 'process',
        spawnFailure: {
          cleanup: {
            requested: false,
            terminationConfirmed: true,
            method: 'none',
            directChildStarted: false,
          },
        },
      },
    })
    const commandRecord = (await storage.loadSessions()).find(
      (record) =>
        record.command === join(root, 'does-not-exist') &&
        record.exitReason?.kind === 'spawn_error' &&
        record.exitReason.cleanup?.directChildStarted === false
    )
    expect(commandRecord).toMatchObject({
      status: 'spawn_failed',
      pid: 0,
      terminationRequested: false,
      terminationConfirmed: true,
      exitReason: { cleanup: { directChildStarted: false } },
    })
    if (!commandRecord) throw new Error('Expected command spawn failure record.')
    expect(commandRecord.workerStartAttempted).toBeTrue()
    expect(commandRecord.worker).toBeDefined()
    expect(
      await Bun.file(join(root, 'sessions', commandRecord.id, 'worker.json')).exists()
    ).toBeTrue()
    expect(
      await NativeWorkerClient.hasVerifiedNoChildSpawnFailureReceipt(
        join(root, 'sessions', commandRecord.id),
        commandRecord.worker!
      )
    ).toBeTrue()
    expect(
      await rpc(descriptor, 'cleanup', { id: commandRecord.id }, context).then((response) =>
        response.json()
      )
    ).toMatchObject({ result: true })
    expect(
      await Bun.file(join(root, 'sessions', commandRecord.id, 'session.json')).exists()
    ).toBeFalse()

    if (process.platform === 'win32') {
      const assignmentFailure = await withProcessEnv(
        { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'job_assign' },
        () =>
          rpc(
            descriptor,
            'exec',
            {
              command: process.execPath,
              args: ['-e', 'setInterval(() => {}, 1000)'],
              timeoutSeconds: 2,
              workdir: root,
            },
            context
          ).then((response) => response.json())
      )
      expect(assignmentFailure).toMatchObject({
        ok: false,
        error: {
          code: 'process',
          spawnFailure: {
            cleanup: {
              requested: true,
              method: 'rollback',
              directChildStarted: true,
              directChildPid: expect.any(Number),
              terminationConfirmed: expect.any(Boolean),
            },
          },
        },
      })
      const assignmentRecord = (await storage.loadSessions()).find(
        (record) =>
          record.exitReason?.kind === 'spawn_error' &&
          record.exitReason.message.includes('failed to assign suspended child to Job Object')
      )
      expect(assignmentRecord).toMatchObject({
        status: 'lost',
        lastKnown: 'creating',
        workerStartAttempted: true,
        exitReason: {
          cleanup: {
            directChildStarted: true,
            directChildPid: expect.any(Number),
          },
        },
      })
      if (!assignmentRecord?.worker) throw new Error('Expected Job-assignment failure record.')
      expect(
        await NativeWorkerClient.hasVerifiedNoChildSpawnFailureReceipt(
          join(root, 'sessions', assignmentRecord.id),
          assignmentRecord.worker
        )
      ).toBeFalse()
      expect(
        await rpc(descriptor, 'cleanup', { id: assignmentRecord.id }, context).then((response) =>
          response.json()
        )
      ).toMatchObject({ result: false })
      expect(
        await Bun.file(join(root, 'sessions', assignmentRecord.id, 'session.json')).exists()
      ).toBeTrue()
    }

    const readinessFailure = await withProcessEnv(
      {
        OPENCODE_PTY_NATIVE_WORKER_FAULT: 'missing_ready',
        OPENCODE_PTY_NATIVE_WORKER_READY_TIMEOUT_MS: '1000',
      },
      () =>
        rpc(
          descriptor,
          'exec',
          {
            command: process.execPath,
            args: ['-e', 'setInterval(() => {}, 1000)'],
            timeoutSeconds: 2,
            workdir: root,
          },
          context
        ).then((response) => response.json())
    )
    expect(readinessFailure).toMatchObject({
      ok: false,
      error: {
        code: 'process',
        spawnFailure: {
          cleanup: {
            requested: true,
            terminationConfirmed: true,
          },
        },
      },
    })
    const readinessRecord = (await storage.loadSessions()).find(
      (record) =>
        record.exitReason?.kind === 'spawn_error' &&
        record.exitReason.cleanup?.method === 'rollback'
    )
    expect(readinessRecord).toMatchObject({
      status: 'lost',
      lastKnown: 'creating',
      terminationRequested: true,
      terminationConfirmed: true,
      exitReason: {
        kind: 'spawn_error',
        cleanup: { requested: true, terminationConfirmed: true, method: 'rollback' },
      },
    })
    if (
      process.platform === 'linux' ||
      process.platform === 'darwin' ||
      process.platform === 'win32'
    ) {
      const containmentFailure = await withProcessEnv(
        { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'unverified_containment' },
        () =>
          rpc(
            descriptor,
            'exec',
            {
              command: process.execPath,
              args: ['-e', 'setInterval(() => {}, 1000)'],
              timeoutSeconds: 2,
              workdir: root,
            },
            context
          ).then((response) => response.json())
      )
      if (process.platform === 'linux' || process.platform === 'win32')
        expect(containmentFailure).toMatchObject({
          error: {
            spawnFailure: {
              cleanup: { requested: true, terminationConfirmed: true, method: 'rollback' },
            },
          },
        })
      else
        expect(containmentFailure).toMatchObject({
          error: {
            spawnFailure: {
              cleanup: { requested: true, terminationConfirmed: false, method: 'rollback' },
            },
          },
        })
      const containmentRecord = (await storage.loadSessions()).find(
        (record) =>
          record.exitReason?.kind === 'spawn_error' &&
          record.exitReason.message.includes('injected containment verification failure')
      )
      expect(containmentRecord).toMatchObject(
        process.platform === 'linux' || process.platform === 'win32'
          ? {
              status: 'lost',
              lastKnown: 'creating',
              terminationRequested: true,
              terminationConfirmed: true,
              exitReason: { cleanup: { directChildPid: expect.any(Number) } },
            }
          : {
              status: 'lost',
              terminationRequested: true,
              terminationConfirmed: false,
              exitReason: { cleanup: { directChildPid: expect.any(Number) } },
            }
      )
    }
  } finally {
    await server.stop()
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 10_000)

test('Windows Job-assignment failure reports a created direct child', async () => {
  if (process.platform !== 'win32') return
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-job-assignment-'))
  roots.push(root)
  await stat(nativeWorkerPath)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_PATH = nativeWorkerPath
  const sessionDirectory = join(root, 'session')
  let prepared: Awaited<ReturnType<typeof NativeWorkerClient.prepare>> | undefined
  try {
    prepared = await withProcessEnv({ OPENCODE_PTY_NATIVE_WORKER_FAULT: 'job_assign' }, () =>
      NativeWorkerClient.prepare({
        command: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000)'],
        workdir: root,
        env: { ...process.env } as Record<string, string>,
        redactionSecrets: [],
        sessionDirectory,
        timeoutSeconds: 2,
        maxOutputBytes: 1024,
        mode: 'exec',
      })
    )
    await expect(prepared.client.start()).rejects.toMatchObject({
      cleanup: {
        requested: true,
        method: 'rollback',
        directChildStarted: true,
        directChildPid: expect.any(Number),
        terminationConfirmed: expect.any(Boolean),
      },
    })
    expect(
      await NativeWorkerClient.hasVerifiedNoChildSpawnFailureReceipt(
        sessionDirectory,
        prepared.reference
      )
    ).toBeFalse()
    expect(await Bun.file(join(sessionDirectory, 'worker.json')).exists()).toBeTrue()
  } finally {
    if (prepared) await NativeWorkerClient.terminateOrphan(sessionDirectory)
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 30_000)

test('native worker identity and ready-output failures close the owned worker before command spawn', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-bootstrap-failure-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  const previousProbeFault = process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_FAIL
  const previousProbeThrow = process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-bootstrap-failure', root)
  const server = new DaemonServer(
    storage,
    new SessionSupervisor(storage),
    'native-bootstrap-failure'
  )
  try {
    const descriptor = await server.start()
    process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_FAIL = '1'
    const identityFailure = await rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000)'],
        timeoutSeconds: 2,
        workdir: root,
      },
      context
    ).then((response) => response.json())
    expect(identityFailure).toMatchObject({
      error: { spawnFailure: { cleanup: { requested: true, terminationConfirmed: true } } },
    })
    delete process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_FAIL
    const directChildMarker = join(root, 'identity-probe-direct-child')
    process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW = '1'
    const throwingProbeFailure = await rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: [
          '-e',
          `require('node:fs').writeFileSync(${JSON.stringify(directChildMarker)}, 'started')`,
        ],
        timeoutSeconds: 2,
        workdir: root,
      },
      context
    ).then((response) => response.json())
    expect(throwingProbeFailure).toMatchObject({
      error: { spawnFailure: { cleanup: { requested: true, terminationConfirmed: true } } },
    })
    await expect(stat(directChildMarker)).rejects.toThrow()
    delete process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW
    const readyFailure = await withProcessEnv(
      { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'ready_stdout' },
      () =>
        rpc(
          descriptor,
          'exec',
          {
            command: process.execPath,
            args: ['-e', 'setInterval(() => {}, 1000)'],
            timeoutSeconds: 2,
            workdir: root,
          },
          context
        ).then((response) => response.json())
    )
    expect(readyFailure).toMatchObject({
      error: { spawnFailure: { cleanup: { terminationConfirmed: true } } },
    })
  } finally {
    await server.stop()
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    if (previousProbeFault === undefined)
      delete process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_FAIL
    else process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_FAIL = previousProbeFault
    if (previousProbeThrow === undefined)
      delete process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW
    else process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW = previousProbeThrow
  }
}, 10_000)

test('unconfirmed worker startup cleanup retains its descriptor for orphan reaping', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-unconfirmed-worker-start-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const sessionDirectory = join(root, 'session')
  await mkdir(sessionDirectory, { recursive: true })
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  let workerPid: number | undefined
  try {
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    const error = await withProcessEnv(
      {
        OPENCODE_PTY_NATIVE_WORKER_FAULT: 'missing_ready',
        OPENCODE_PTY_NATIVE_WORKER_READY_TIMEOUT_MS: '100',
        OPENCODE_PTY_NATIVE_WORKER_READY_DELAY_MS: '60000',
      },
      async () => {
        try {
          await NativeWorkerClient.start({
            command: process.execPath,
            args: ['-e', 'setInterval(() => {}, 1000)'],
            workdir: root,
            env: runtimeEnvironment(undefined, false),
            redactionSecrets: [],
            sessionDirectory,
            timeoutSeconds: 2,
            maxOutputBytes: 1024,
            mode: 'exec',
          })
          throw new Error('Expected native worker startup to fail.')
        } catch (error) {
          return error
        }
      }
    )
    expect(error).toBeInstanceOf(WorkerStartError)
    expect((error as WorkerStartError).cleanup).toMatchObject({
      requested: true,
      terminationConfirmed: false,
      method: 'rollback',
    })

    const descriptorPath = join(sessionDirectory, 'worker.json')
    expect(await Bun.file(descriptorPath).exists()).toBeTrue()
    workerPid = (JSON.parse(await readFile(descriptorPath, 'utf8')) as { pid: number }).pid
    await expect(NativeWorkerClient.terminateOrphan(sessionDirectory)).resolves.toMatchObject({
      outcome: 'killed',
    })
    expect(await processGone(workerPid)).toBeTrue()
  } finally {
    if (workerPid && !(await processGone(workerPid))) process.kill(workerPid, 'SIGKILL')
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 30_000)

test('prepared workers do not start commands before the start frame', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-worker-prepare-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const sessionDirectory = join(root, 'session')
  const marker = join(root, 'command-started')
  await mkdir(sessionDirectory)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  let prepared: Awaited<ReturnType<typeof NativeWorkerClient.prepare>> | undefined
  try {
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    prepared = await NativeWorkerClient.prepare({
      command: process.execPath,
      args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`],
      workdir: root,
      env: runtimeEnvironment(undefined, false),
      redactionSecrets: [],
      sessionDirectory,
      timeoutSeconds: 2,
      maxOutputBytes: 1024,
      mode: 'exec',
    })
    expect(await Bun.file(marker).exists()).toBeFalse()
    await prepared.client.start()
    expect(await Bun.file(join(sessionDirectory, 'prestart-no-child.json')).exists()).toBeFalse()
    await prepared.client.wait(5000)
    expect(await Bun.file(marker).text()).toBe('started')
    await prepared.client.shutdown()
    prepared = undefined
  } finally {
    if (prepared) {
      await prepared.client.rollback().catch(() => undefined)
      await NativeWorkerClient.terminateOrphan(sessionDirectory).catch(() => undefined)
    }
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 30_000)

test('a verified pre-start receipt lets recovery remove a no-child worker', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-prestart-recovery-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_prestart', 'lost')
  session.lifecycle = 'persistent'
  const sessionDirectory = join(root, 'sessions', session.id)
  const marker = join(root, 'command-started')
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  await mkdir(sessionDirectory, { recursive: true })
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  let prepared: Awaited<ReturnType<typeof NativeWorkerClient.prepare>> | undefined
  try {
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    prepared = await NativeWorkerClient.prepare({
      command: process.execPath,
      args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`],
      workdir: root,
      env: runtimeEnvironment(undefined, false),
      redactionSecrets: [],
      sessionDirectory,
      timeoutSeconds: 2,
      maxOutputBytes: 1024,
      mode: 'exec',
    })
    session.worker = prepared.reference
    session.workerStartAttempted = false
    session.status = 'spawn_failed'
    await storage.writeSession(session)

    expect(await Bun.file(marker).exists()).toBeFalse()
    expect(await prepared.client.rollback()).toMatchObject({
      requested: false,
      terminationConfirmed: true,
      directChildStarted: false,
    })
    expect(await Bun.file(join(sessionDirectory, 'worker.json')).exists()).toBeTrue()
    expect(
      await NativeWorkerClient.hasVerifiedPrestartNoChildReceipt(
        sessionDirectory,
        prepared.reference
      )
    ).toBeTrue()

    const receiptPath = join(sessionDirectory, 'prestart-no-child.json')
    const receipt = JSON.parse(await readFile(receiptPath, 'utf8')) as Record<string, unknown>
    for (const invalid of [
      { ...receipt, workerEndpoint: 'http://127.0.0.1:9' },
      { ...receipt, receiptVersion: 2 },
      { ...receipt, kind: 'other' },
      { ...receipt, workerProcessIdentity: 'other-process' },
      { ...receipt, workerProtocolVersion: 4 },
      { ...receipt, workerControlToken: 'other-token' },
      { ...receipt, extra: true },
    ]) {
      await writeFile(receiptPath, JSON.stringify(invalid))
      expect(
        await NativeWorkerClient.hasVerifiedPrestartNoChildReceipt(
          sessionDirectory,
          prepared.reference
        )
      ).toBeFalse()
    }
    await writeFile(receiptPath, JSON.stringify(receipt))

    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize(false)
    await supervisor.reconcileWorkers()
    expect(await Bun.file(marker).exists()).toBeFalse()
    expect(existsSync(sessionDirectory)).toBeFalse()
    prepared = undefined
  } finally {
    if (prepared) {
      await prepared.client.rollback().catch(() => undefined)
      await NativeWorkerClient.terminateOrphan(sessionDirectory).catch(() => undefined)
    }
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 30_000)

test('a pre-start authority alone can reap only its matching no-child receipt', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-prestart-authority-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_prestart_authority', 'spawn_failed')
  session.lifecycle = 'persistent'
  session.workerStartAttempted = false
  const sessionDirectory = join(root, 'sessions', session.id)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  await mkdir(sessionDirectory, { recursive: true })
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  let prepared: Awaited<ReturnType<typeof NativeWorkerClient.prepare>> | undefined
  try {
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    prepared = await NativeWorkerClient.prepare({
      command: process.execPath,
      args: ['-e', 'process.exit(0)'],
      workdir: root,
      env: runtimeEnvironment(undefined, false),
      redactionSecrets: [],
      sessionDirectory,
      timeoutSeconds: 2,
      maxOutputBytes: 1024,
      mode: 'exec',
    })
    session.workerPrestart = {
      workerId: prepared.reference.startIdentity,
      tokenFingerprint: prepared.reference.tokenFingerprint!,
      protocolVersion: prepared.reference.protocolVersion,
    }
    await storage.writeSession(session)
    await prepared.client.rollback()

    for (const authority of [
      { ...session.workerPrestart, workerId: 'other-worker' },
      { ...session.workerPrestart, tokenFingerprint: '0'.repeat(64) },
      { ...session.workerPrestart, protocolVersion: 4 },
    ]) {
      expect(
        await NativeWorkerClient.hasVerifiedPrestartNoChildReceipt(sessionDirectory, authority)
      ).toBeFalse()
    }
    expect(
      await NativeWorkerClient.hasVerifiedPrestartNoChildReceipt(
        sessionDirectory,
        session.workerPrestart
      )
    ).toBeTrue()

    const missing = record(root, 'pty_prestart_authority_missing', 'spawn_failed')
    missing.lifecycle = 'persistent'
    missing.workerStartAttempted = false
    missing.workerPrestart = { ...session.workerPrestart, workerId: 'missing-worker' }
    await storage.writeSession(missing)

    const supervisor = new SessionSupervisor(storage, undefined, 1)
    await supervisor.initialize(false)
    await supervisor.reconcileWorkers()
    expect(existsSync(sessionDirectory)).toBeFalse()
    expect(existsSync(join(root, 'sessions', missing.id))).toBeTrue()
    expect(await supervisor.cleanup(missing.id)).toBeFalse()
    prepared = undefined
  } finally {
    if (prepared) {
      await prepared.client.rollback().catch(() => undefined)
      await NativeWorkerClient.terminateOrphan(sessionDirectory).catch(() => undefined)
    }
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 30_000)

test('pre-worker callback failures report confirmed no-worker evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-preworker-failure-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const sessionDirectory = join(root, 'session')
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  try {
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    const error = await NativeWorkerClient.prepare(
      {
        command: process.execPath,
        args: [
          '-e',
          `require('node:fs').writeFileSync(${JSON.stringify(join(root, 'marker'))}, 'x')`,
        ],
        workdir: root,
        env: runtimeEnvironment(undefined, false),
        redactionSecrets: [],
        sessionDirectory,
        timeoutSeconds: 2,
        maxOutputBytes: 1024,
        mode: 'exec',
      },
      async () => {
        throw Object.assign(new Error('disk full'), { code: 'ENOSPC' })
      }
    ).catch((error) => error)
    expect(error).toBeInstanceOf(WorkerStartError)
    expect(error as WorkerStartError).toMatchObject({
      noWorkerSpawned: true,
      cleanup: { requested: false, terminationConfirmed: true, directChildStarted: false },
    })
    expect(await Bun.file(join(sessionDirectory, 'worker.json')).exists()).toBeFalse()
    expect(await Bun.file(join(root, 'marker')).exists()).toBeFalse()
  } finally {
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
})

test('pre-worker payload and worker-resolution failures report confirmed no-worker evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-preworker-known-failure-'))
  roots.push(root)
  const marker = join(root, 'command-started')
  const sessionDirectory = join(root, 'session')
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  try {
    const oversized = await NativeWorkerClient.prepare({
      command: process.execPath,
      args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`],
      workdir: root,
      env: { PAYLOAD: 'x'.repeat(1024 * 1024) },
      redactionSecrets: [],
      sessionDirectory,
      timeoutSeconds: 2,
      maxOutputBytes: 1024,
      mode: 'exec',
    }).catch((error) => error)
    expect(oversized).toBeInstanceOf(WorkerStartError)
    expect(oversized as WorkerStartError).toMatchObject({
      noWorkerSpawned: true,
      cleanup: { requested: false, terminationConfirmed: true, directChildStarted: false },
    })
    expect(await Bun.file(join(sessionDirectory, 'worker.json')).exists()).toBeFalse()
    expect(await Bun.file(marker).exists()).toBeFalse()

    process.env.PTY_NATIVE_WORKER_PATH = join(root, 'missing-worker')
    const unavailable = await NativeWorkerClient.prepare({
      command: process.execPath,
      args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`],
      workdir: root,
      env: runtimeEnvironment(undefined, false),
      redactionSecrets: [],
      sessionDirectory: join(root, 'missing-session'),
      timeoutSeconds: 2,
      maxOutputBytes: 1024,
      mode: 'exec',
    }).catch((error) => error)
    expect(unavailable).toBeInstanceOf(WorkerStartError)
    expect(unavailable as WorkerStartError).toMatchObject({
      noWorkerSpawned: true,
      cleanup: { requested: false, terminationConfirmed: true, directChildStarted: false },
    })
    expect(await Bun.file(join(root, 'missing-session', 'worker.json')).exists()).toBeFalse()
    expect(await Bun.file(marker).exists()).toBeFalse()
  } finally {
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
})

test('ready-timeout failures retain a verified reference for no-child recovery', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-prestart-ready-timeout-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const marker = join(root, 'command-started')
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  try {
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    await expect(
      withProcessEnv(
        {
          OPENCODE_PTY_NATIVE_WORKER_FAULT: 'missing_ready',
          OPENCODE_PTY_NATIVE_WORKER_READY_TIMEOUT_MS: '100',
          OPENCODE_PTY_NATIVE_WORKER_READY_DELAY_MS: '500',
        },
        () =>
          supervisor.nativeExecStart({
            command: process.execPath,
            args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`],
            timeoutSeconds: 2,
            workdir: root,
            parentSessionId: 'parent',
            lifecycle: 'persistent',
            ...directOwner(root),
          })
      )
    ).rejects.toBeInstanceOf(ProcessError)

    const session = (await storage.loadSessions()).at(0)
    if (!session) throw new Error('Expected ready-timeout session record.')
    const sessionDirectory = join(root, 'sessions', session.id)
    expect(session).toMatchObject({
      status: 'lost',
      lastKnown: 'creating',
      workerStartAttempted: false,
      worker: { protocolVersion: 5 },
    })
    expect(await Bun.file(marker).exists()).toBeFalse()
    expect(
      await NativeWorkerClient.hasVerifiedPrestartNoChildReceipt(sessionDirectory, session.worker!)
    ).toBeTrue()

    await supervisor.initialize(false)
    await supervisor.reconcileWorkers()
    expect(existsSync(sessionDirectory)).toBeFalse()
  } finally {
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 30_000)

test('native sessions persist their worker reference before start', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-worker-reference-order-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const prepare = NativeWorkerClient.prepare
  const writeSession = storage.writeSession.bind(storage)
  let commandStarted = false
  const reference = {
    pid: 123,
    startIdentity: 'worker-id',
    processIdentity: 'worker-process',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  const client = {
    start: async () => {
      commandStarted = true
      return workerSnapshot()
    },
    wait: async () => new Promise<WorkerSnapshot>(() => undefined),
  }
  ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async (
    _bootstrap,
    persistPrestart
  ) => {
    await persistPrestart?.({
      workerId: reference.startIdentity,
      tokenFingerprint: reference.tokenFingerprint!,
      protocolVersion: reference.protocolVersion,
    })
    return {
      client,
      reference,
    } as unknown as Awaited<ReturnType<typeof NativeWorkerClient.prepare>>
  }
  let gate:
    | {
        arrived: Promise<void>
        notify: () => void
        released: Promise<void>
        release: () => void
      }
    | undefined
  storage.writeSession = async (entry) => {
    if (entry.workerStartAttempted === true && gate) {
      gate.notify()
      await gate.released
    }
    await writeSession(entry)
  }
  try {
    for (const mode of ['pty', 'exec'] as const) {
      commandStarted = false
      let notify!: () => void
      let releaseGate!: () => void
      gate = {
        arrived: new Promise<void>((resolve) => {
          notify = resolve
        }),
        notify,
        released: new Promise<void>((resolve) => {
          releaseGate = resolve
        }),
        release: releaseGate,
      }
      const currentGate = gate
      const operation =
        mode === 'pty'
          ? supervisor.spawn({
              command: 'prepared-command',
              workdir: root,
              parentSessionId: `parent-${mode}`,
              lifecycle: 'persistent',
              ...directOwner(root),
            })
          : supervisor.nativeExecStart({
              command: 'prepared-command',
              timeoutSeconds: 1,
              workdir: root,
              parentSessionId: `parent-${mode}`,
              lifecycle: 'persistent',
              ...directOwner(root),
            })
      await currentGate.arrived
      expect(commandStarted).toBeFalse()
      currentGate.release()
      await operation
      expect(commandStarted).toBeTrue()
      gate = undefined
    }
  } finally {
    storage.writeSession = writeSession
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = prepare
  }
})

test('native worker reference persistence failure rolls back before start', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-worker-reference-failure-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const prepare = NativeWorkerClient.prepare
  const writeSession = storage.writeSession.bind(storage)
  const reference = {
    pid: 123,
    startIdentity: 'worker-id',
    processIdentity: 'worker-process',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  let starts = 0
  let rollbacks = 0
  const client = {
    start: async () => {
      starts += 1
      return workerSnapshot()
    },
    rollback: async () => {
      rollbacks += 1
      return { requested: true, terminationConfirmed: false, method: 'rollback' as const }
    },
  }
  ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = async (
    _bootstrap,
    persistPrestart
  ) => {
    await persistPrestart?.({
      workerId: reference.startIdentity,
      tokenFingerprint: reference.tokenFingerprint!,
      protocolVersion: reference.protocolVersion,
    })
    return {
      client,
      reference,
    } as unknown as Awaited<ReturnType<typeof NativeWorkerClient.prepare>>
  }
  storage.writeSession = async (entry) => {
    if (entry.workerStartAttempted === true) {
      await mkdir(join(root, 'sessions', entry.id), { recursive: true })
      await writeFile(join(root, 'sessions', entry.id, 'worker.json'), JSON.stringify(reference))
      throw Object.assign(new Error('disk full'), { code: 'ENOSPC' })
    }
    await writeSession(entry)
  }
  try {
    for (const mode of ['pty', 'exec'] as const) {
      starts = 0
      rollbacks = 0
      const operation =
        mode === 'pty'
          ? supervisor.spawn({
              command: 'prepared-command',
              workdir: root,
              parentSessionId: `parent-${mode}`,
              ...directOwner(root),
            })
          : supervisor.nativeExecStart({
              command: 'prepared-command',
              timeoutSeconds: 1,
              workdir: root,
              parentSessionId: `parent-${mode}`,
              ...directOwner(root),
            })
      await expect(operation).rejects.toBeInstanceOf(ProcessError)
      expect(starts).toBe(0)
      expect(rollbacks).toBe(1)
      const persisted = (await storage.loadSessions()).find(
        (record) => record.parentSessionId === `parent-${mode}`
      )
      if (!persisted) throw new Error('Expected lost session after pre-start persistence failure.')
      expect(persisted).toMatchObject({
        status: 'lost',
        worker: reference,
        workerStartAttempted: false,
        terminationRequested: true,
        terminationConfirmed: false,
      })
      expect(
        await Bun.file(join(root, 'sessions', persisted.id, 'worker.json')).exists()
      ).toBeTrue()
    }
  } finally {
    storage.writeSession = writeSession
    ;(NativeWorkerClient as unknown as { prepare: typeof prepare }).prepare = prepare
  }
})

test('pre-start receipts cannot delete start-attempted or legacy records', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-prestart-fence-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_prestart_fence', 'spawn_failed')
  session.lifecycle = 'persistent'
  const sessionDirectory = join(root, 'sessions', session.id)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  await mkdir(sessionDirectory, { recursive: true })
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  let prepared: Awaited<ReturnType<typeof NativeWorkerClient.prepare>> | undefined
  try {
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    prepared = await NativeWorkerClient.prepare({
      command: process.execPath,
      args: ['-e', 'process.exit(0)'],
      workdir: root,
      env: runtimeEnvironment(undefined, false),
      redactionSecrets: [],
      sessionDirectory,
      timeoutSeconds: 2,
      maxOutputBytes: 1024,
      mode: 'exec',
    })
    session.worker = prepared.reference
    session.workerStartAttempted = true
    await storage.writeSession(session)
    await prepared.client.rollback()

    const beforeRecovery = (await storage.loadSessions()).find((entry) => entry.id === session.id)
    expect(beforeRecovery?.workerStartAttempted).toBeTrue()

    const supervisor = new SessionSupervisor(storage, undefined, 1)
    await supervisor.initialize(false)
    expect(existsSync(sessionDirectory)).toBeTrue()
    await supervisor.reconcileWorkers()
    expect(existsSync(sessionDirectory)).toBeTrue()
    expect(await supervisor.cleanup(session.id)).toBeFalse()

    const stored = (await storage.loadSessions()).find((entry) => entry.id === session.id)
    expect(stored?.workerStartAttempted).toBeTrue()
    prepared = undefined
  } finally {
    if (prepared) {
      await prepared.client.rollback().catch(() => undefined)
      await NativeWorkerClient.terminateOrphan(sessionDirectory).catch(() => undefined)
    }
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 30_000)

test('start-attempted and legacy records never consume a pre-start receipt', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-prestart-legacy-fence-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const reference = {
    pid: 123,
    startIdentity: 'worker-id',
    processIdentity: 'worker-process',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  const receipt = NativeWorkerClient.hasVerifiedPrestartNoChildReceipt
  const reconnect = NativeWorkerClient.reconnect
  let receiptReads = 0
  let reconnects = 0
  ;(
    NativeWorkerClient as unknown as {
      hasVerifiedPrestartNoChildReceipt: typeof receipt
    }
  ).hasVerifiedPrestartNoChildReceipt = async () => {
    receiptReads += 1
    return true
  }
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    reconnects += 1
    return null
  }
  try {
    for (const [id, workerStartAttempted] of [
      ['pty_start_attempted', true],
      ['pty_legacy_start', undefined],
    ] as const) {
      const session = record(root, id, 'lost')
      session.lifecycle = 'persistent'
      session.worker = reference
      if (workerStartAttempted !== undefined) session.workerStartAttempted = workerStartAttempted
      await storage.writeSession(session)
    }
    const supervisor = new SessionSupervisor(storage, undefined, 1)
    await supervisor.initialize(false)
    await supervisor.reconcileWorkers()

    expect(receiptReads).toBe(0)
    expect(reconnects).toBe(2)
    for (const id of ['pty_start_attempted', 'pty_legacy_start']) {
      expect(existsSync(join(root, 'sessions', id))).toBeTrue()
      expect(await supervisor.cleanup(id)).toBeFalse()
    }
    expect(receiptReads).toBe(0)
  } finally {
    ;(
      NativeWorkerClient as unknown as {
        hasVerifiedPrestartNoChildReceipt: typeof receipt
      }
    ).hasVerifiedPrestartNoChildReceipt = receipt
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
})

test('worker recovery rejects an authenticated health identity mismatch', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-worker-recovery-'))
  roots.push(root)
  const token = 'a'.repeat(32)
  const server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch: () =>
      Response.json({
        ok: true,
        result: { protocolVersion: 5, pid: 123, processIdentity: 'different-worker' },
      }),
  })
  const sessionDirectory = join(root, 'session')
  await mkdir(sessionDirectory)
  await writeFile(
    join(sessionDirectory, 'worker.json'),
    JSON.stringify({
      pid: 123,
      startIdentity: 'worker-id',
      processIdentity: 'expected-worker',
      endpoint: server.url.origin,
      token,
      protocolVersion: 5,
    })
  )
  try {
    expect(
      await NativeWorkerClient.reconnect(sessionDirectory, {
        pid: 123,
        startIdentity: 'worker-id',
        processIdentity: 'expected-worker',
        endpoint: server.url.origin,
        tokenFingerprint: new Bun.CryptoHasher('sha256').update(token).digest('hex'),
        protocolVersion: 5,
      })
    ).toBeNull()
  } finally {
    server.stop(true)
  }
})

test('native worker accepts a split readiness frame and immediate post-resume exit', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-split-ready-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-split-ready', root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-split-ready')
  try {
    const descriptor = await server.start()
    expect(
      await withProcessEnv({ OPENCODE_PTY_NATIVE_WORKER_FAULT: 'split_ready' }, () =>
        rpc(
          descriptor,
          'exec',
          {
            command: process.execPath,
            args: ['-e', 'process.exit(0)'],
            timeoutSeconds: 2,
            workdir: root,
          },
          context
        ).then((response) => response.json())
      )
    ).toMatchObject({ ok: true, result: { session: { status: 'exited' }, exitCode: 0 } })
  } finally {
    await server.stop()
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 10_000)

test.skipIf(process.platform !== 'win32')(
  'Windows native stop drains Job descendants',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-windows-job-'))
    roots.push(root)
    const workerPath = join(process.cwd(), 'target', 'debug', 'opencode-pty-worker.exe')
    await stat(workerPath)
    const previousPath = process.env.PTY_NATIVE_WORKER_PATH
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    const storage = new DaemonStorage(root)
    const context = await owner(storage, 'native-windows-job', root)
    const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-windows-job')
    const descendantMarker = join(root, 'job-descendant-started')
    try {
      const descriptor = await server.start()
      const executing = rpc(
        descriptor,
        'exec',
        {
          command: process.execPath,
          args: [
            '-e',
            `require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(`require('node:fs').writeFileSync(${JSON.stringify(descendantMarker)}, 'started'); setInterval(() => {}, 1000)`)}], { stdio: 'ignore' }); setInterval(() => {}, 1000)`,
          ],
          timeoutSeconds: 5,
          workdir: root,
        },
        context
      )
      let id = ''
      for (let attempt = 0; attempt < 50 && !id; attempt += 1) {
        id = (await storage.loadSessions()).find((session) => session.mode === 'exec')?.id ?? ''
        if (!id) await Bun.sleep(20)
      }
      expect(id).not.toBe('')
      for (let attempt = 0; attempt < 50; attempt += 1) {
        if (
          await stat(descendantMarker).then(
            () => true,
            () => false
          )
        )
          break
        await Bun.sleep(20)
      }
      await stat(descendantMarker)
      expect(
        await rpc(descriptor, 'stop', { id }, context).then((response) => response.json())
      ).toMatchObject({
        result: { terminationConfirmed: true, containment: { status: 'windows_job_empty' } },
      })
      await expect(executing.then((response) => response.json())).resolves.toMatchObject({
        result: { terminationConfirmed: true },
      })
    } finally {
      await server.stop()
      if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
      else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    }
  },
  10_000
)

test('native RPC loss after command start reaps the direct child before persisting unknown', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-rpc-loss-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-rpc-loss', root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-rpc-loss')
  try {
    const descriptor = await server.start()
    const result = await withProcessEnv(
      { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'rpc_loss_after_start' },
      () =>
        rpc(
          descriptor,
          'exec',
          {
            command: process.execPath,
            args: ['-e', 'setInterval(() => {}, 1000)'],
            timeoutSeconds: 2,
            workdir: root,
          },
          context
        ).then((response) => response.json())
    )
    expect(result.ok).toBeBoolean()
    const session = (await storage.loadSessions()).find((entry) => entry.mode === 'exec')
    expect(await processGone(session?.pid ?? 0)).toBeTrue()
    if (session?.terminationConfirmed) expect(session.status).toBe('exited')
    else expect(session).toMatchObject({ status: 'lost', exitReason: { kind: 'unknown' } })
  } finally {
    await server.stop()
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 30_000)

test('spawn payload fault knobs are stripped from session env and never trigger fault injection', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-fault-env-strip-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'fault-strip')
  const descriptor = await server.start()
  const context = await owner(storage, 'fault-strip', root)
  const marker = join(root, 'fault-env.txt')
  try {
    const spawned = (await rpc(
      descriptor,
      'spawn',
      {
        command: process.execPath,
        args: [
          '-e',
          `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'fault=' + String(process.env.OPENCODE_PTY_NATIVE_WORKER_FAULT)); setTimeout(() => {}, 250)`,
        ],
        env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'job_assign' },
        description: 'fault knob stripping',
        workdir: root,
      },
      context
    ).then((response) => response.json())) as { ok: boolean; result?: { id: string } }
    // A live job_assign fault would fail the native spawn outright; a successful
    // session with an unset variable proves the knob was stripped from session env.
    expect(spawned.ok).toBeTrue()
    const id = spawned.result?.id
    if (!id) throw new Error('Expected a spawned session despite the fault knob in session env.')
    let evidence = ''
    for (let attempt = 0; attempt < 200 && !evidence; attempt += 1) {
      evidence = await readFile(marker, 'utf8').catch(() => '')
      if (!evidence) await Bun.sleep(25)
    }
    expect(evidence).toBe('fault=undefined')
    const record = (await rpc(descriptor, 'get', { id }, context).then((response) =>
      response.json()
    )) as { result?: { status?: string } }
    expect(['running', 'exited']).toContain(record.result?.status ?? '')
    await rpc(descriptor, 'stop', { id }, context)
  } finally {
    await server.stop()
  }
}, 15_000)

test.skipIf(process.platform === 'win32')(
  'native exec POSIX containment creates a fresh session, drains groups, escalates, and reports escapes',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-posix-'))
    roots.push(root)
    const workerPath = join(process.cwd(), 'target', 'debug', 'opencode-pty-worker')
    await stat(workerPath)
    const previousPath = process.env.PTY_NATIVE_WORKER_PATH
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    const storage = new DaemonStorage(root)
    const context = await owner(storage, 'native-posix', root)
    const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-posix')
    const directChildPidFile = join(root, 'direct-child.pid')
    let directChildPid = 0
    let escapedPid = 0
    try {
      const descriptor = await server.start()
      const run = async (script: string) =>
        rpc(
          descriptor,
          'exec',
          { command: process.execPath, args: ['-e', script], timeoutSeconds: 3, workdir: root },
          context
        )
      const running = run(
        `const {spawn}=require('node:child_process');const {writeFileSync}=require('node:fs');const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});writeFileSync(${JSON.stringify(directChildPidFile)},String(child.pid));setInterval(()=>{},1000)`
      )
      let record: SessionRecord | undefined
      for (let attempt = 0; attempt < 50 && !record; attempt += 1) {
        record = (await storage.loadSessions()).find((entry) => entry.mode === 'exec')
        if (!record) await Bun.sleep(20)
      }
      expect(record?.containment).toMatchObject({
        platform: process.platform === 'linux' ? 'linux_proc' : 'posix_verification_unavailable',
        rootPid: record?.pid,
        processGroupId: record?.pid,
        sessionId: record?.pid,
      })
      for (let attempt = 0; attempt < 50 && !directChildPid; attempt += 1) {
        directChildPid = Number((await readFile(directChildPidFile, 'utf8').catch(() => '')).trim())
        if (!directChildPid) await Bun.sleep(20)
      }
      if (process.platform === 'darwin') expect(directChildPid).toBeGreaterThan(0)
      const stopped = await rpc(descriptor, 'stop', { id: record?.id }, context).then((response) =>
        response.json()
      )
      if (process.platform === 'linux') {
        expect(stopped).toMatchObject({
          result: {
            containment: { status: 'posix_processes_remaining' },
            terminationConfirmed: false,
          },
        })
      } else {
        expect(stopped).toMatchObject({
          result: {
            containment: { status: 'posix_containment_unknown', rootIdentityVerified: false },
            directChildExited: true,
            termination: { termSignalSent: true, killSignalSent: true, directChildExited: true },
          },
        })
      }
      await running

      const termIgnoring = await run("process.on('SIGTERM',()=>{});setInterval(()=>{},1000)").then(
        (response) => response.json()
      )
      expect(termIgnoring).toMatchObject(
        process.platform === 'linux'
          ? {
              result: {
                timedOut: true,
                termination: { termSignalSent: true, killSignalSent: true },
              },
            }
          : {
              result: {
                timedOut: true,
                containment: { status: 'posix_containment_unknown', rootIdentityVerified: false },
                termination: {
                  termSignalSent: true,
                  killSignalSent: true,
                  directChildExited: true,
                },
              },
            }
      )

      const escaped = run(
        "const {spawn}=require('node:child_process');const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});console.log(child.pid);setInterval(()=>{},1000)"
      )
      let escapedRecord: SessionRecord | undefined
      for (let attempt = 0; attempt < 50 && !escapedRecord; attempt += 1) {
        escapedRecord = (await storage.loadSessions()).find(
          (entry) => entry.mode === 'exec' && entry.id !== record?.id
        )
        if (!escapedRecord) await Bun.sleep(20)
      }
      for (let attempt = 0; attempt < 50 && !escapedPid; attempt += 1) {
        escapedPid = Number(
          (await storage.loadSessions())
            .find((entry) => entry.id === escapedRecord?.id)
            ?.execOutput?.stdout.trim()
        )
        if (!escapedPid) await Bun.sleep(20)
      }
      const escapedStop = await rpc(descriptor, 'stop', { id: escapedRecord?.id }, context).then(
        (response) => response.json()
      )
      if (process.platform === 'linux')
        expect(escapedStop).toMatchObject({
          result: { containment: { status: 'posix_escape_observed' } },
        })
      if (process.platform === 'darwin') {
        expect(await processGone(escapedPid)).toBeFalse()
        process.kill(escapedPid, 'SIGKILL')
        escapedPid = 0
      }
      await escaped
    } finally {
      try {
        if (directChildPid) {
          try {
            process.kill(directChildPid, 'SIGKILL')
          } catch (error) {
            expect((error as NodeJS.ErrnoException).code).toBe('ESRCH')
          }
          expect(await processGone(directChildPid)).toBeTrue()
        }
        if (escapedPid) process.kill(escapedPid, 'SIGKILL')
      } finally {
        await server.stop()
        if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
        else process.env.PTY_NATIVE_WORKER_PATH = previousPath
      }
    }
  },
  15_000
)

test.skipIf(process.platform !== 'darwin')(
  'macOS normal direct-child completion is readable and cleanable without descendant confirmation',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-macos-normal-'))
    roots.push(root)
    const previousPath = process.env.PTY_NATIVE_WORKER_PATH
    process.env.PTY_NATIVE_WORKER_PATH = nativeWorkerPath
    const supervisor = new SessionSupervisor(new DaemonStorage(root))
    await supervisor.initialize()
    try {
      const result = await supervisor.nativeExec({
        command: process.execPath,
        args: ['-e', "console.log('macos-normal')"],
        parentSessionId: 'macos',
        ...directOwner(root),
        timeoutSeconds: 2,
        workdir: root,
      })
      expect(result).toMatchObject({ stdout: 'macos-normal\n', terminationConfirmed: true })
      expect(await supervisor.get(result.session.id)).toMatchObject({
        status: 'exited',
        directChildExited: true,
        containment: { status: 'posix_containment_unknown' },
      })
      expect(await supervisor.cleanup(result.session.id)).toBeTrue()
    } finally {
      if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
      else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    }
  },
  10_000
)

test.skipIf(process.platform === 'win32')(
  'native PTY writes, resizes, rejects exec resize, and recovers after daemon restart',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-pty-'))
    roots.push(root)
    const workerPath = join(process.cwd(), 'target', 'debug', 'opencode-pty-worker')
    await stat(workerPath)
    const previousPath = process.env.PTY_NATIVE_WORKER_PATH
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    const storage = new DaemonStorage(root)
    const context = await owner(storage, 'native-pty', root)
    const first = new DaemonServer(storage, new SessionSupervisor(storage), 'native-pty-first')
    let restarted: DaemonServer | undefined
    try {
      const descriptor = await first.start()
      const spawned = await rpc(
        descriptor,
        'spawn',
        {
          command: process.execPath,
          args: ['-e', "process.stdin.on('data', value => process.stdout.write('echo:' + value))"],
          description: 'native pty integration',
          lifecycle: 'persistent',
          workdir: root,
        },
        context
      ).then((response) => response.json())
      const id = (spawned as { result: { id: string } }).result.id
      expect(
        await rpc(descriptor, 'resize', { id, cols: 100, rows: 30 }, context).then((response) =>
          response.json()
        )
      ).toMatchObject({ result: { cols: 100, rows: 30 } })
      await rpc(descriptor, 'write', { id, data: 'conpty-check\n' }, context)
      for (let attempt = 0; attempt < 50; attempt += 1) {
        const output = (await rpc(descriptor, 'rawOutput', { id }, context).then((response) =>
          response.json()
        )) as { result?: { raw?: string } }
        if (output.result?.raw?.includes('echo:conpty-check')) break
        await Bun.sleep(20)
      }
      expect(
        await rpc(descriptor, 'rawOutput', { id }, context).then((response) => response.json())
      ).toMatchObject({ result: { raw: expect.stringContaining('echo:conpty-check') } })
      await first.stop()
      restarted = new DaemonServer(storage, new SessionSupervisor(storage), 'native-pty-second')
      const restartedDescriptor = await restarted.start()
      expect(
        await rpc(restartedDescriptor, 'resize', { id, cols: 90, rows: 25 }, context).then(
          (response) => response.json()
        )
      ).toMatchObject({ result: { cols: 90, rows: 25 } })
      expect(
        await rpc(restartedDescriptor, 'stop', { id }, context).then((response) => response.json())
      ).toMatchObject({ result: {} })
    } finally {
      await restarted?.stop()
      await first.stop().catch(() => undefined)
      if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
      else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    }
  },
  15_000
)

test.skipIf(process.platform !== 'win32')(
  'Windows ConPTY cmd more accepts unique input, resizes, and cleans up',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-windows-conpty-'))
    roots.push(root)
    const previousPath = process.env.PTY_NATIVE_WORKER_PATH
    process.env.PTY_NATIVE_WORKER_PATH = nativeWorkerPath
    const storage = new DaemonStorage(root)
    const server = new DaemonServer(storage, new SessionSupervisor(storage), 'windows-conpty')
    let descriptor: { endpoint: string; token: string } | undefined
    let id: string | undefined
    let cmdPid: number | undefined
    let workerPid: number | undefined
    try {
      descriptor = await server.start()
      const context = await owner(storage, 'windows-conpty', root)
      const spawned = (await rpc(
        descriptor,
        'spawn',
        {
          command: 'cmd.exe',
          args: ['/d', '/c', 'more'],
          description: 'Windows ConPTY more',
          workdir: root,
        },
        context
      ).then((response) => response.json())) as {
        ok: boolean
        result?: { id: unknown }
        error?: unknown
      }
      expect(spawned.ok).toBeTrue()
      if (!spawned.result || typeof spawned.result.id !== 'string')
        throw new Error(JSON.stringify(spawned.error ?? spawned))
      id = spawned.result.id
      const running = (await rpc(descriptor, 'get', { id }, context).then((response) =>
        response.json()
      )) as { result?: { pid?: unknown } }
      if (typeof running.result?.pid !== 'number')
        throw new Error('Windows ConPTY cmd pid is invalid')
      cmdPid = running.result.pid
      const worker = JSON.parse(
        await readFile(join(root, 'sessions', id, 'worker.json'), 'utf8')
      ) as { pid?: unknown }
      if (typeof worker.pid !== 'number') throw new Error('Windows ConPTY worker pid is invalid')
      workerPid = worker.pid
      const marker = `conpty-more-${crypto.randomUUID()}`
      expect(
        await rpc(
          descriptor,
          'sendWait',
          {
            id,
            data: `${marker}\r\n`,
            condition: { kind: 'output', literal: marker },
            timeoutSeconds: 2,
          },
          context
        ).then((response) => response.json())
      ).toMatchObject({ result: { satisfied: true } })
      const resized = await rpc(descriptor, 'resize', { id, cols: 100, rows: 30 }, context).then(
        (response) => response.json()
      )
      expect(resized).toMatchObject({ result: { cols: 100, rows: 30 } })
      expect(
        await rpc(descriptor, 'list', {}, context).then((response) => response.json())
      ).toMatchObject({ result: [{ id, status: 'running' }] })
      expect(
        await rpc(descriptor, 'rawOutput', { id }, context).then((response) => response.json())
      ).toMatchObject({ result: { raw: expect.stringContaining(marker) } })
      const stopped = await rpc(descriptor, 'stop', { id }, context).then((response) =>
        response.json()
      )
      expect(stopped).toMatchObject({
        result: { terminationConfirmed: true, containment: { status: 'windows_job_empty' } },
      })
      expect(
        await rpc(descriptor, 'get', { id }, context).then((response) => response.json())
      ).toMatchObject({
        result: {
          status: 'exited',
          terminationConfirmed: true,
          containment: { status: 'windows_job_empty' },
        },
      })
      expect(
        await rpc(descriptor, 'cleanup', { id }, context).then((response) => response.json())
      ).toMatchObject({ result: true })
      id = undefined
      expect(await processGone(cmdPid)).toBeTrue()
      expect(await processGone(workerPid)).toBeTrue()
    } finally {
      if (descriptor && id) {
        const context = await owner(storage, 'windows-conpty', root).catch(() => undefined)
        if (context) {
          await rpc(descriptor, 'stop', { id }, context).catch(() => undefined)
          await rpc(descriptor, 'cleanup', { id }, context).catch(() => undefined)
        }
      }
      await server.stop().catch(() => undefined)
      if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
      else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    }
  },
  10_000
)

test.skipIf(process.platform !== 'win32')(
  'Windows ConPTY cmd echo drains terminal output and its Job',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-windows-conpty-finite-'))
    roots.push(root)
    const previousPath = process.env.PTY_NATIVE_WORKER_PATH
    process.env.PTY_NATIVE_WORKER_PATH = nativeWorkerPath
    const storage = new DaemonStorage(root)
    const server = new DaemonServer(
      storage,
      new SessionSupervisor(storage),
      'windows-conpty-finite'
    )
    let descriptor: { endpoint: string; token: string } | undefined
    let id: string | undefined
    try {
      descriptor = await server.start()
      const context = await owner(storage, 'windows-conpty-finite', root)
      const markerPath = join(root, 'marker.txt')
      const spawned = (await rpc(
        descriptor,
        'spawn',
        {
          command: 'cmd.exe',
          args: ['/d', '/c', `echo conpty-ok & echo conpty-ok > ${markerPath}`],
          description: 'Windows ConPTY echo',
          workdir: root,
        },
        context
      ).then((response) => response.json())) as { result?: { id?: unknown } }
      if (typeof spawned.result?.id !== 'string') throw new Error('finite ConPTY id is invalid')
      id = spawned.result.id
      for (let attempt = 0; attempt < 1500; attempt += 1) {
        const session = (await rpc(descriptor, 'get', { id }, context).then((response) =>
          response.json()
        )) as { result?: { status?: string } }
        if (session.result?.status !== 'running') break
        await Bun.sleep(20)
      }
      expect(existsSync(markerPath)).toBeTrue()
      expect(await readFile(markerPath, 'utf8')).toContain('conpty-ok')
      const output = await rpc(descriptor, 'rawOutput', { id }, context).then((response) =>
        response.json()
      )
      const session = await rpc(descriptor, 'get', { id }, context).then((response) =>
        response.json()
      )
      const raw = (output as { result?: { raw?: string } }).result?.raw
      const diagnostics = (session as { result?: { diagnostics?: string[] } }).result?.diagnostics
      if (!raw?.includes('conpty-ok'))
        throw new Error(
          `finite ConPTY output loss: raw=${JSON.stringify(raw)} diagnostics=${JSON.stringify(diagnostics)}`
        )
      expect(session).toMatchObject({
        result: {
          status: 'exited',
          terminationConfirmed: true,
          containment: { status: 'windows_job_empty' },
        },
      })
      const diagnosticPresent = diagnostics?.some((diagnostic) => {
        try {
          const value = JSON.parse(diagnostic) as {
            hpconNonzero?: boolean
            readerStarted?: boolean
          }
          return value.hpconNonzero === true && value.readerStarted === true
        } catch {
          return false
        }
      })
      if (!diagnosticPresent)
        throw new Error(`finite ConPTY diagnostics: ${JSON.stringify(session)}`)
      expect(
        await rpc(descriptor, 'cleanup', { id }, context).then((response) => response.json())
      ).toMatchObject({ result: true })
      id = undefined
    } finally {
      if (descriptor && id) {
        const context = await owner(storage, 'windows-conpty-finite', root).catch(() => undefined)
        if (context) {
          await rpc(descriptor, 'stop', { id }, context).catch(() => undefined)
          await rpc(descriptor, 'cleanup', { id }, context).catch(() => undefined)
        }
      }
      await server.stop().catch(() => undefined)
      if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
      else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    }
  },
  30_000
)

test('tool output XML escaping covers text and attributes', () => {
  expect(escapeXml(`<&>"'`)).toBe('&lt;&amp;&gt;&quot;&apos;')
  expect(escapeXml(`ok\u0000\u001f\ud800😀`)).toBe('ok���😀')
  expect(formatLine('<output>', 1)).toContain('&lt;output&gt;')
  expect(formatLine('😀x', 1, 1)).toContain('😀...')
})

test.skipIf(process.platform === 'win32')(
  'native PTY has no implicit worker deadline',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-pty-no-timeout-'))
    roots.push(root)
    const previousPath = process.env.PTY_NATIVE_WORKER_PATH
    process.env.PTY_NATIVE_WORKER_PATH = nativeWorkerPath
    const supervisor = new SessionSupervisor(new DaemonStorage(root))
    await supervisor.initialize()
    try {
      const session = await supervisor.spawn({
        command: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000)'],
        parentSessionId: 'parent',
        ...directOwner(root),
        workdir: root,
      })
      expect(session.timeoutSeconds).toBeUndefined()
      expect((await supervisor.get(session.id))?.timeoutSeconds).toBeUndefined()
      await supervisor.stop(session.id)
    } finally {
      if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
      else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    }
  }
)

test('tool session rendering preserves containment survivors and unknown verification', () => {
  const root = process.cwd()
  const session = record(root, 'exec_survivor', 'lost')
  session.mode = 'exec'
  session.terminationRequested = true
  session.terminationConfirmed = false
  session.containment = {
    platform: 'linux_proc',
    status: 'posix_processes_remaining',
    rootPid: 1,
    processGroupId: 1,
    sessionId: 1,
    rootStartIdentity: 'posix:1:1',
    rootIdentityVerified: false,
    observedGroupPids: [2],
    observedSessionPids: [2],
    observedEscapedDescendantPids: [],
    verifiedAt: new Date().toISOString(),
  }
  expect(formatSessionInfo(session).join('\n')).toContain('Containment: posix_processes_remaining')
  session.containment.status = 'posix_containment_unknown'
  expect(formatSessionInfo(session).join('\n')).toContain('Containment: posix_containment_unknown')
})

test('cleanup retains a terminal record with unverified containment', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-containment-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  await storage.initialize()
  const session = record(root, 'exec_unverified', 'exited')
  session.mode = 'exec'
  session.containment = {
    platform: 'linux_proc',
    status: 'posix_containment_unknown',
    rootPid: 1,
    processGroupId: 1,
    sessionId: 1,
    rootStartIdentity: 'posix:1:1',
    rootIdentityVerified: false,
    observedGroupPids: [],
    observedSessionPids: [],
    observedEscapedDescendantPids: [],
    verifiedAt: new Date().toISOString(),
  }
  await storage.writeSession(session)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  expect(await supervisor.cleanup(session.id)).toBeFalse()
  expect((await storage.loadSessions()).map((entry) => entry.id)).toContain(session.id)
})

test('client does not contact a live incompatible daemon descriptor', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-incompatible-'))
  roots.push(root)
  const processIdentity = (await processStartIdentity(process.pid)) ?? 'unavailable'
  let requests = 0
  const server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch: () => {
      requests += 1
      return Response.json({
        id: 'health',
        ok: true,
        result: {
          protocolVersion: DAEMON_PROTOCOL_VERSION + 1,
          pid: process.pid,
          processIdentity,
        },
      })
    },
  })
  const previousDirectory = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  const storage = new DaemonStorage(root)
  await storage.initialize()
  await storage.writeDescriptor({
    pid: process.pid,
    processIdentity,
    endpoint: server.url.origin,
    protocolVersion: DAEMON_PROTOCOL_VERSION + 1,
    token: 'test-token',
  })

  try {
    await expect(new DaemonClient().list()).rejects.toThrow('incompatible')
    expect(requests).toBe(0)
    expect((await storage.readDescriptor())?.protocolVersion).toBe(DAEMON_PROTOCOL_VERSION + 1)
  } finally {
    server.stop(true)
    if (previousDirectory === undefined) delete process.env.PTY_DAEMON_DIR
    else process.env.PTY_DAEMON_DIR = previousDirectory
  }
})

test('daemon launcher resolves Bun instead of a non-Bun plugin host', () => {
  const pluginHost = 'C:\\Program Files\\OpenCode\\opencode.exe'
  const bun = 'C:\\Program Files\\Bun\\bun.exe'
  const command = daemonLaunchCommand(
    (name) => (name === 'bun' ? bun : null),
    'daemon-entry.js',
    'launch-options'
  )
  expect(command).toEqual([bun, 'daemon-entry.js', 'launch-options'])
  expect(command).not.toContain(pluginHost)
  expect(() => resolveDaemonLauncher(() => null)).toThrow('Bun executable')
})

test('daemon launcher detaches without a Windows console window', () => {
  const options = daemonLaunchOptions(() => 'bun.exe', 'daemon-entry.js', 'launch-options')
  expect(options).toMatchObject({
    cmd: ['bun.exe', 'daemon-entry.js', 'launch-options'],
    detached: true,
    windowsHide: true,
    stdin: 'ignore',
    stdout: 'ignore',
    stderr: 'pipe',
  })
})

test('Windows worker launcher isolates native workers without a console window', () => {
  expect(workerLaunchOptions(['worker.exe'])).toMatchObject({
    cmd: ['worker.exe'],
    detached: true,
    windowsHide: true,
    stdin: 'pipe',
    stdout: 'pipe',
    stderr: 'inherit',
  })
})

test('daemon readiness budget starts after launch', () => {
  const startupStartedAt = 0
  const spawnedAt = startupStartedAt + 6_000
  expect(daemonReadinessDeadline(spawnedAt)).toBe(26_000)
})

test('daemon storage protects private paths', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-modes-'))
  roots.push(root)
  const previousDirectory = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  if (process.platform === 'win32') {
    const foreignAcl = Bun.spawn({
      cmd: [
        'powershell.exe',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `$acl = Get-Acl -LiteralPath $env:PTY_DAEMON_ACL_PATH
$everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($everyone, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit', [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $env:PTY_DAEMON_ACL_PATH -AclObject $acl`,
      ],
      cwd: root,
      stdout: 'ignore',
      stderr: 'pipe',
      windowsHide: true,
      env: { ...process.env, PTY_DAEMON_ACL_PATH: root },
    })
    expect(await foreignAcl.exited).toBe(0)
    process.env.PTY_DAEMON_DIR = root
  }
  const storage = new DaemonStorage()
  try {
    await storage.initialize()
    await storage.writeDescriptor({
      pid: process.pid,
      processIdentity: 'stale',
      endpoint: 'http://127.0.0.1:1',
      protocolVersion: DAEMON_PROTOCOL_VERSION - 1,
      token: 'x',
    })
    await storage.writeSession(record(root, 'pty_test', 'exited'))
    await storage.appendOutput('pty_test', [
      { startSequence: 0, endSequence: 6, timestamp: new Date().toISOString(), data: 'output' },
    ])
    if (process.platform !== 'win32') {
      expect((await stat(root)).mode & 0o777).toBe(0o700)
      expect((await stat(join(root, 'daemon.json'))).mode & 0o777).toBe(0o600)
      expect((await stat(join(root, 'sessions', 'pty_test'))).mode & 0o777).toBe(0o700)
      expect((await stat(join(root, 'sessions', 'pty_test', 'session.json'))).mode & 0o777).toBe(
        0o600
      )
      expect(
        (await stat(join(root, 'sessions', 'pty_test', 'output', '00000000000000000000.json')))
          .mode & 0o777
      ).toBe(0o600)
    } else {
      const sidProcess = Bun.spawn({
        cmd: [
          'powershell.exe',
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
        ],
        cwd: root,
        stdout: 'pipe',
        stderr: 'pipe',
        windowsHide: true,
      })
      const sid = (await new Response(sidProcess.stdout).text()).trim()
      expect(await sidProcess.exited).toBe(0)
      const acl = Bun.spawn({
        cmd: [
          'powershell.exe',
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `$items = @(Get-Item -LiteralPath $env:PTY_DAEMON_ACL_PATH -Force) + @(Get-ChildItem -LiteralPath $env:PTY_DAEMON_ACL_PATH -Force -Recurse)
foreach ($item in $items) {
  $rules = @($item.GetAccessControl().GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne 2 -or @($rules | Where-Object { $_.IdentityReference.Value -notin @($env:PTY_DAEMON_ACL_USER_SID, 'S-1-5-18') }).Count -ne 0) { throw "Foreign ACE survived daemon storage initialization: $($item.FullName): $($rules.IdentityReference.Value -join ',')." }
}`,
        ],
        cwd: root,
        stdout: 'pipe',
        stderr: 'pipe',
        windowsHide: true,
        env: {
          ...process.env,
          PTY_DAEMON_ACL_PATH: root,
          PTY_DAEMON_ACL_USER_SID: sid,
        },
      })
      const error = `${await new Response(acl.stdout).text()}${await new Response(acl.stderr).text()}`
      if ((await acl.exited) !== 0) throw new Error(error)
    }
  } finally {
    if (previousDirectory === undefined) delete process.env.PTY_DAEMON_DIR
    else process.env.PTY_DAEMON_DIR = previousDirectory
  }
})

test('lost sessions without terminal evidence are retained', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-lost-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await storage.writeSession(record(root, 'pty_lost', 'lost'))
  await supervisor.initialize()

  expect(await supervisor.cleanup('pty_lost')).toBeFalse()
  expect(await storage.loadSessions()).toMatchObject([{ id: 'pty_lost', status: 'lost' }])
})

test('lost persistent sessions remain retry-eligible without becoming runnable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-persistent-retry-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_persistent_retry')
  session.lifecycle = 'persistent'
  session.worker = {
    pid: 1,
    startIdentity: 'start',
    processIdentity: 'identity',
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: 5,
  }
  await storage.writeSession(session)
  const reconnect = NativeWorkerClient.reconnect
  let attempts = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    attempts += 1
    return null
  }
  try {
    const supervisor = new SessionSupervisor(storage, undefined, 1)
    await supervisor.initialize()
    await supervisor.initialize()

    expect(attempts).toBe(2)
    expect(await supervisor.get(session.id)).toMatchObject({ status: 'lost' })
    await expect(supervisor.wait(session.id, { kind: 'exit' }, 1)).rejects.toMatchObject({
      code: 'session_closed',
    })
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
}, 30_000)

test('a fresh authenticated snapshot restores a retryable persistent session', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-persistent-recovered-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_persistent_recovered')
  session.lifecycle = 'persistent'
  session.worker = {
    pid: 1,
    startIdentity: 'start',
    processIdentity: 'identity',
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: 5,
  }
  await storage.writeSession(session)
  const running = workerSnapshot()
  const terminal = workerSnapshot({
    status: 'exited',
    exitReason: 'stopped',
    exitedAt: new Date().toISOString(),
    terminationRequested: true,
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
  })
  let releaseWait!: () => void
  const waitGate = new Promise<WorkerSnapshot>((resolve) => {
    releaseWait = () => resolve(terminal)
  })
  let writes = 0
  const worker = {
    snapshot: async () => running,
    write: async () => {
      writes += 1
      return { arrivalSequence: 0 }
    },
    wait: async () => waitGate,
    stop: async () => terminal,
    finalSnapshot: async () => terminal,
    shutdown: async () => terminal,
  }
  const reconnect = NativeWorkerClient.reconnect
  let attempts = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    attempts += 1
    return attempts === 1 ? null : (worker as never)
  }
  try {
    const supervisor = new SessionSupervisor(storage, undefined, 1)
    await supervisor.initialize()
    expect(await supervisor.get(session.id)).toMatchObject({ status: 'lost' })

    await supervisor.initialize()
    expect(await supervisor.get(session.id)).toMatchObject({ status: 'running' })
    await supervisor.write(session.id, 'resumed input')
    expect(writes).toBe(1)
    await supervisor.stop(session.id)
  } finally {
    releaseWait()
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
}, 30_000)

test('host cleanup retries a lost conversation tombstone without deleting evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-conversation-tombstone-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_conversation_tombstone', 'lost')
  session.pendingCleanup = true
  session.nextSequence = 5
  session.outputBytes = 5
  session.lineCount = 1
  session.worker = {
    pid: 1,
    startIdentity: 'start',
    processIdentity: 'identity',
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: 5,
  }
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 5, timestamp: session.updatedAt, data: 'kept\n' },
  ])
  const reconnect = NativeWorkerClient.reconnect
  let attempts = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    attempts += 1
    return { shutdown: async () => workerSnapshot({ status: 'lost' }) } as never
  }
  try {
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize(false)
    await supervisor.cleanupByParentSession('parent', root, OWNER_HASH)
    await supervisor.cleanupByParentSession('parent', root, OWNER_HASH)

    expect(attempts).toBe(2)
    expect(await supervisor.get(session.id)).toMatchObject({ status: 'lost' })
    expect(await storage.loadSessions()).toMatchObject([
      {
        id: session.id,
        status: 'lost',
        pendingCleanup: true,
      },
    ])
    expect(await supervisor.rawOutput(session.id)).toEqual({ raw: 'kept\n', byteLength: 5 })
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
}, 30_000)

test('restart cleanup removes a terminal conversation record with proof', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-terminal-conversation-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_terminal_conversation', 'exited')
  markTerminalProof(session)
  session.nextSequence = 5
  session.outputBytes = 5
  session.lineCount = 1
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 5, timestamp: session.updatedAt, data: 'done\n' },
  ])
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize(false)
  await supervisor.markConversationRecoveryCleanup()

  expect(await storage.loadSessions()).toEqual([])
})

test('restart cleanup retains a terminal conversation record without proof', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-terminal-conversation-unproven-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_terminal_conversation_unproven', 'exited')
  session.nextSequence = 5
  session.outputBytes = 5
  session.lineCount = 1
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 5, timestamp: session.updatedAt, data: 'done\n' },
  ])
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize(false)
  await supervisor.markConversationRecoveryCleanup()

  const [stored] = await storage.loadSessions()
  expect(stored).toMatchObject({
    id: session.id,
    status: 'lost',
    lastKnown: 'terminal',
    pendingCleanup: true,
    terminationConfirmed: true,
  })
  expect(stored?.directChildExited).toBeUndefined()
  expect(await storage.readOutput(session.id)).toBe('done\n')
})

test('restart cleanup requires fresh shutdown proof for a terminal conversation worker', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-terminal-conversation-worker-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_terminal_conversation_worker', 'exited')
  markTerminalProof(session)
  session.worker = {
    pid: 7,
    startIdentity: 'worker-start',
    processIdentity: 'worker-process',
    endpoint: 'http://127.0.0.1:7',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  session.nextSequence = 5
  session.outputBytes = 5
  session.lineCount = 1
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 5, timestamp: session.updatedAt, data: 'done\n' },
  ])
  const terminal = workerSnapshot({
    status: 'exited',
    exitReason: 'stopped',
    exitedAt: new Date().toISOString(),
    terminationRequested: true,
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
  })
  const reconnect = NativeWorkerClient.reconnect
  let reconnects = 0
  let shutdowns = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    reconnects += 1
    return {
      shutdown: async () => {
        shutdowns += 1
        return terminal
      },
    } as never
  }
  try {
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize(false)
    await supervisor.markConversationRecoveryCleanup()

    expect(reconnects).toBe(1)
    expect(shutdowns).toBe(1)
    expect(await storage.loadSessions()).toEqual([])
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
})

test('restart cleanup retains a terminal conversation worker without fresh proof', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-terminal-conversation-worker-retain-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_terminal_conversation_worker_retain', 'exited')
  markTerminalProof(session)
  session.worker = {
    pid: 7,
    startIdentity: 'worker-start',
    processIdentity: 'worker-process',
    endpoint: 'http://127.0.0.1:7',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  session.nextSequence = 5
  session.outputBytes = 5
  session.lineCount = 1
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 5, timestamp: session.updatedAt, data: 'done\n' },
  ])
  const reconnect = NativeWorkerClient.reconnect
  let reconnects = 0
  let shutdowns = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    reconnects += 1
    return {
      shutdown: async () => {
        shutdowns += 1
        return workerSnapshot({
          status: 'exited',
          exitReason: 'stopped',
          exitedAt: new Date().toISOString(),
          terminationRequested: true,
          terminationConfirmed: false,
          directChildExited: true,
          stdoutEof: true,
          stderrEof: true,
          outputComplete: true,
        })
      },
    } as never
  }
  try {
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize(false)
    await supervisor.markConversationRecoveryCleanup()

    expect(reconnects).toBe(1)
    expect(shutdowns).toBe(1)
    expect(await storage.loadSessions()).toMatchObject([
      { id: session.id, status: 'exited', pendingCleanup: true, worker: session.worker },
    ])
    expect(await storage.readOutput(session.id)).toBe('done\n')
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
})

test('restart cleanup retains a terminal conversation worker when reconnect fails', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-terminal-conversation-worker-missing-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_terminal_conversation_worker_missing', 'exited')
  markTerminalProof(session)
  session.worker = {
    pid: 7,
    startIdentity: 'worker-start',
    processIdentity: 'worker-process',
    endpoint: 'http://127.0.0.1:7',
    tokenFingerprint: 'f'.repeat(64),
    protocolVersion: 5,
  }
  await storage.writeSession(session)
  const reconnect = NativeWorkerClient.reconnect
  let reconnects = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    reconnects += 1
    return null
  }
  try {
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize(false)
    await supervisor.markConversationRecoveryCleanup()

    expect(reconnects).toBe(1)
    expect(await storage.loadSessions()).toMatchObject([
      { id: session.id, status: 'exited', pendingCleanup: true, worker: session.worker },
    ])
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
})

test('recovery reaps a post-start no-child conversation failure without reconnecting', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-poststart-conversation-recovery-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_poststart_conversation', 'spawn_failed')
  const token = 'post-start-conversation-token'
  session.worker = {
    pid: 7,
    startIdentity: 'worker-start',
    processIdentity: 'worker-process',
    endpoint: 'http://127.0.0.1:7',
    tokenFingerprint: new Bun.CryptoHasher('sha256').update(token).digest('hex'),
    protocolVersion: 5,
  }
  session.workerStartAttempted = true
  await storage.writeSession(session)
  const sessionDirectory = join(root, 'sessions', session.id)
  await writeFile(
    join(sessionDirectory, 'worker.json'),
    JSON.stringify({
      pid: session.worker.pid,
      startIdentity: session.worker.startIdentity,
      processIdentity: session.worker.processIdentity,
      endpoint: session.worker.endpoint,
      token,
      protocolVersion: session.worker.protocolVersion,
    })
  )
  await writeFile(
    join(sessionDirectory, 'spawn-failure.json'),
    JSON.stringify({
      workerId: session.worker.startIdentity,
      workerPid: session.worker.pid,
      workerProcessIdentity: session.worker.processIdentity,
      workerControlToken: token,
      directChildStarted: false,
      directChildPid: null,
      terminationConfirmed: true,
      message: 'command was unavailable',
    })
  )
  const reconnect = NativeWorkerClient.reconnect
  let reconnects = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    reconnects += 1
    return null
  }
  try {
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize(false)
    await supervisor.reconcileWorkers()

    expect(reconnects).toBe(0)
    expect(existsSync(sessionDirectory)).toBeFalse()
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
})

test('restart marks and reaps a lost conversation tombstone', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-lost-conversation-recovery-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_lost_conversation_recovery', 'lost')
  session.worker = {
    pid: 1,
    startIdentity: 'start',
    processIdentity: 'identity',
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: 5,
  }
  await storage.writeSession(session)
  const terminal = workerSnapshot({
    status: 'exited',
    exitReason: 'stopped',
    exitedAt: new Date().toISOString(),
    terminationRequested: true,
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
  })
  const reconnect = NativeWorkerClient.reconnect
  let shutdowns = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () =>
    ({
      finalSnapshot: async () => terminal,
      shutdown: async () => {
        shutdowns += 1
        return terminal
      },
    }) as never
  try {
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize(false)
    await supervisor.markConversationRecoveryCleanup()
    await supervisor.reconcileWorkers()

    expect(shutdowns).toBe(1)
    expect(await storage.loadSessions()).toEqual([])
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
}, 30_000)

test('native monitor snapshots exclude journal output and persist terminal output interleaving', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-finalize-race-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const session = record(root, 'pty_native_finalization_race')
  await storage.writeSession(session)
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )
  const running = workerSnapshot()
  const terminal = workerSnapshot({
    status: 'exited',
    nextSequence: 11,
    outputLineCount: 2,
    exitedAt: new Date().toISOString(),
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
  })
  let waits = 0
  const worker = {
    wait: async () => {
      waits += 1
      if (waits === 1) return running
      await storage.appendOutput(session.id, [
        { startSequence: 0, endSequence: 6, timestamp: session.updatedAt, data: 'early\n' },
      ])
      return terminal
    },
    finalSnapshot: async () => {
      await storage.appendOutput(session.id, [
        { startSequence: 6, endSequence: 11, timestamp: session.updatedAt, data: 'late\n' },
      ])
      return terminal
    },
    shutdown: async () => terminal,
  }
  ;(supervisor as unknown as { nativeWorkers: Map<string, unknown> }).nativeWorkers.set(
    session.id,
    worker
  )

  await (
    supervisor as unknown as {
      monitorNative: (record: SessionRecord, worker: unknown) => Promise<unknown>
    }
  ).monitorNative(session, worker)

  expect(JSON.stringify(running)).not.toContain('journalOutput')
  expect(session).toMatchObject({ nextSequence: 11, outputBytes: 11, lineCount: 2 })
  expect(await storage.readOutput(session.id)).toBe('early\nlate\n')
  expect(await storage.loadSessions()).toMatchObject([
    { id: session.id, nextSequence: 11, outputBytes: 11, lineCount: 2, status: 'exited' },
  ])
})

test('a stale running worker snapshot cannot revive a stopping session', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-stale-running-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const session = record(root, 'pty_stale_running', 'stopping')
  session.terminationRequested = true
  session.exitCode = 42
  session.nextSequence = 7
  session.outputBytes = 7
  session.containment = {
    platform: 'not_applicable',
    status: 'not_applicable',
    rootPid: 42,
    rootStartIdentity: 'stopped',
    rootIdentityVerified: true,
    observedGroupPids: [],
    observedSessionPids: [],
    observedEscapedDescendantPids: [],
    verifiedAt: new Date().toISOString(),
  }
  await storage.writeSession(session)
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )

  await (
    supervisor as unknown as {
      finishNative: (record: SessionRecord, result: WorkerSnapshot) => Promise<unknown>
    }
  ).finishNative(session, workerSnapshot())

  expect(session.status).toBe('stopping')
  expect(session).toMatchObject({
    terminationRequested: true,
    exitCode: 42,
    outputBytes: 7,
    containment: { rootPid: 42 },
  })
  expect((await storage.loadSessions())[0]).toMatchObject({
    status: 'stopping',
    terminationRequested: true,
    exitCode: 42,
    containment: { rootPid: 42 },
  })
})

test('metadata-only list does not snapshot workers or overwrite monitor finalization', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-snapshot-race-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const session = record(root, 'pty_native_snapshot_race')
  session.worker = {
    pid: 1,
    startIdentity: 'start',
    processIdentity: 'process',
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: 5,
  }
  await storage.writeSession(session)
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )
  const running = workerSnapshot()
  const terminal = workerSnapshot({
    status: 'exited',
    exitedAt: new Date().toISOString(),
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
  })
  let snapshots = 0
  let snapshotStarted!: () => void
  let releaseSnapshots!: () => void
  let finalizationStarted!: () => void
  const started = new Promise<void>((resolve) => {
    snapshotStarted = resolve
  })
  const release = new Promise<void>((resolve) => {
    releaseSnapshots = resolve
  })
  const finalizing = new Promise<void>((resolve) => {
    finalizationStarted = resolve
  })
  const worker = {
    snapshot: async () => {
      snapshots += 1
      snapshotStarted()
      await release
      return running
    },
    wait: async () => {
      await started
      return terminal
    },
    finalSnapshot: async () => {
      finalizationStarted()
      return terminal
    },
    shutdown: async () => terminal,
  }
  ;(supervisor as unknown as { nativeWorkers: Map<string, unknown> }).nativeWorkers.set(
    session.id,
    worker
  )

  const reconnect = NativeWorkerClient.reconnect
  let reconnects = 0
  NativeWorkerClient.reconnect = async () => {
    reconnects += 1
    return null
  }

  try {
    const list = await supervisor.list()
    expect(snapshots).toBe(0)
    const get = supervisor.get(session.id)
    await started
    const monitor = (
      supervisor as unknown as {
        monitorNative: (record: SessionRecord, worker: unknown) => Promise<unknown>
      }
    ).monitorNative(session, worker)
    await finalizing
    releaseSnapshots()

    await monitor
    expect(await get).toMatchObject({ status: 'exited' })
    expect(list).toMatchObject([{ id: session.id, status: 'running' }])
    expect(await storage.loadSessions()).toMatchObject([{ id: session.id, status: 'exited' }])
    expect(await supervisor.cleanup(session.id)).toBeTrue()
    expect(reconnects).toBe(0)
  } finally {
    NativeWorkerClient.reconnect = reconnect
  }
})

test('cleanup waits for a native terminal write before deleting its session', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-cleanup-race-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const session = record(root, 'pty_native_cleanup_race')
  await storage.writeSession(session)
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )
  const terminal = workerSnapshot({
    status: 'exited',
    exitedAt: new Date().toISOString(),
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
  })
  let terminalWriteStarted!: () => void
  let releaseTerminalWrite!: () => void
  const started = new Promise<void>((resolve) => {
    terminalWriteStarted = resolve
  })
  const release = new Promise<void>((resolve) => {
    releaseTerminalWrite = resolve
  })
  const writeSession = storage.writeSession.bind(storage)
  const deleteSession = storage.deleteSession.bind(storage)
  let deletionStarted!: () => void
  const deletion = new Promise<void>((resolve) => {
    deletionStarted = resolve
  })
  storage.writeSession = async (entry) => {
    if (entry.id === session.id && entry.status === 'exited') {
      terminalWriteStarted()
      await release
    }
    await writeSession(entry)
  }
  storage.deleteSession = async (id) => {
    deletionStarted()
    await deleteSession(id)
  }
  const worker = {
    finalSnapshot: async () => terminal,
    shutdown: async () => terminal,
  }
  ;(supervisor as unknown as { nativeWorkers: Map<string, unknown> }).nativeWorkers.set(
    session.id,
    worker
  )

  const finalization = (
    supervisor as unknown as {
      finalizeNative: (
        record: SessionRecord,
        worker: unknown,
        result: WorkerSnapshot
      ) => Promise<unknown>
    }
  ).finalizeNative(session, worker, terminal)
  await started
  const cleanup = supervisor.cleanup(session.id)
  expect(
    await Promise.race([deletion.then(() => true), Bun.sleep(25).then(() => false)])
  ).toBeFalse()
  releaseTerminalWrite()

  expect(await cleanup).toBeTrue()
  await finalization
  expect(existsSync(join(root, 'sessions', session.id))).toBeFalse()
  expect(await storage.loadSessions()).toEqual([])
})

test('native finalization persists a lost storage failure', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-finalize-failure-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const session = record(root, 'pty_native_finalization_failure')
  await storage.writeSession(session)
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )
  await expect(
    (
      supervisor as unknown as {
        finishNative: (record: SessionRecord, result: WorkerSnapshot) => Promise<unknown>
      }
    ).finishNative(session, workerSnapshot({ exitCode: -1 }))
  ).rejects.toMatchObject({ code: 'ESTORAGE' })
  expect(await storage.loadSessions()).toMatchObject([
    {
      id: session.id,
      status: 'lost',
      exitReason: { kind: 'unknown', message: expect.stringContaining('invalid PTY session') },
    },
  ])
})

test('native finalization reports worker storage failure before containment is confirmed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-storage-failure-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  const session = record(root, 'pty_native_storage_failure')
  await storage.writeSession(session)
  ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
    session.id,
    session
  )
  await expect(
    (
      supervisor as unknown as {
        finishNative: (record: SessionRecord, result: WorkerSnapshot) => Promise<unknown>
      }
    ).finishNative(
      session,
      workerSnapshot({
        status: 'lost',
        storageFailure: 'output directory is unavailable',
        terminationConfirmed: false,
      })
    )
  ).rejects.toMatchObject({ code: 'ESTORAGE' })
  expect(session).toMatchObject({
    status: 'lost',
    storageFailure: 'output directory is unavailable',
  })
})

test.skipIf(process.platform !== 'win32')(
  'Windows native high exit status persists as an unsigned code',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-windows-exit-code-'))
    roots.push(root)
    const storage = new DaemonStorage(root)
    const supervisor = new SessionSupervisor(storage)
    const session = record(root, 'pty_windows_high_exit')
    await storage.writeSession(session)
    ;(supervisor as unknown as { records: Map<string, SessionRecord> }).records.set(
      session.id,
      session
    )
    const exited = workerSnapshot({
      status: 'exited',
      exitCode: 0xc0000005,
      exitReason: 'code',
      exitedAt: new Date().toISOString(),
      terminationConfirmed: true,
      directChildExited: true,
      stdoutEof: true,
      stderrEof: true,
      outputComplete: true,
    })

    await (
      supervisor as unknown as {
        finishNative: (record: SessionRecord, result: WorkerSnapshot) => Promise<unknown>
      }
    ).finishNative(session, exited)

    expect(await storage.loadSessions()).toMatchObject([
      {
        id: session.id,
        status: 'exited',
        exitCode: 0xc0000005,
        exitReason: { kind: 'code', code: 0xc0000005 },
      },
    ])
  }
)

test('stale worker recovery is bounded and parallel', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-parallel-recovery-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  for (let index = 0; index < 6; index += 1) {
    const session = record(root, `pty_stale_${index}`)
    session.lifecycle = 'persistent'
    session.worker = {
      pid: 1,
      startIdentity: 'start',
      processIdentity: 'identity',
      endpoint: 'http://127.0.0.1:1',
      protocolVersion: 5,
    }
    await storage.writeSession(session)
  }
  const reconnect = NativeWorkerClient.reconnect
  let active = 0
  let maximum = 0
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    active += 1
    maximum = Math.max(maximum, active)
    await Bun.sleep(50)
    active -= 1
    return null
  }
  try {
    const started = Date.now()
    await new SessionSupervisor(storage, undefined, 1).initialize()
    expect(Date.now() - started).toBeLessThan(3_000)
    expect(maximum).toBe(4)
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
  }
}, 30_000)

test('restart marks a conversation worker before publication and reaps it after reconnect', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-restart-cleanup-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'parent', root)
  const session = record(root, 'pty_reconnect_cleanup')
  session.ownerCapabilityHash = context.capability
  session.worker = {
    pid: 1,
    startIdentity: 'start',
    processIdentity: 'identity',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: 'fingerprint',
    protocolVersion: 5,
  }
  await storage.writeSession(session)
  let allowReconnect: () => void = () => {}
  let reconnecting: () => void = () => {}
  const reconnectGate = new Promise<void>((resolve) => {
    allowReconnect = resolve
  })
  const reconnectStarted = new Promise<void>((resolve) => {
    reconnecting = resolve
  })
  const terminal: WorkerSnapshot = {
    status: 'exited',
    pid: 1,
    mode: 'pty',
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    nextSequence: 0,
    firstRetainedSequence: 0,
    outputTruncated: false,
    outputLineCount: 0,
    outputHasPartialLine: false,
    exitReason: 'stopped',
    startedAt: session.createdAt,
    exitedAt: new Date().toISOString(),
    timedOut: false,
    terminationRequested: true,
    terminationConfirmed: true,
    directChildExited: true,
    stdoutEof: true,
    stderrEof: true,
    outputComplete: true,
    outputIncomplete: false,
    containment: {
      platform: 'not_applicable',
      status: 'not_applicable',
      rootPid: 1,
      rootStartIdentity: 'start',
      rootIdentityVerified: true,
      observedGroupPids: [],
      observedSessionPids: [],
      observedEscapedDescendantPids: [],
      verifiedAt: new Date().toISOString(),
    },
  }
  let stops = 0
  const worker = {
    stop: async () => {
      stops += 1
      return terminal
    },
    finalSnapshot: async () => terminal,
    shutdown: async () => terminal,
  }
  const reconnect = NativeWorkerClient.reconnect
  const writeDescriptor = storage.writeDescriptor.bind(storage)
  let markedBeforePublication = false
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => {
    reconnecting()
    await reconnectGate
    return worker as never
  }
  storage.writeDescriptor = async (nextDescriptor) => {
    markedBeforePublication = (await storage.loadSessions()).some(
      (entry) => entry.id === session.id && entry.pendingCleanup === true
    )
    await writeDescriptor(nextDescriptor)
  }
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  try {
    const descriptor = await server.start()
    expect(markedBeforePublication).toBeTrue()
    await reconnectStarted
    const markedOperations = await Promise.all(
      [
        rpc(descriptor, 'write', { id: session.id, data: 'late input' }, context),
        rpc(descriptor, 'resize', { id: session.id, cols: 80, rows: 24 }, context),
        rpc(
          descriptor,
          'sendWait',
          {
            id: session.id,
            data: 'late input',
            condition: { kind: 'exit' },
            timeoutSeconds: 1,
          },
          context
        ),
        rpc(
          descriptor,
          'wait',
          { id: session.id, condition: { kind: 'exit' }, timeoutSeconds: 1 },
          context
        ),
      ].map(async (request) => {
        const response = await request
        return { status: response.status, body: await response.json() }
      })
    )
    for (const operation of markedOperations) {
      expect(operation.status).toBe(400)
      expect(operation.body).toMatchObject({ error: { code: 'session_closed' } })
    }
    expect(
      await rpc(descriptor, 'get', { id: session.id }, context).then((response) => response.status)
    ).toBe(200)
    expect(
      await rpc(descriptor, 'read', { id: session.id }, context).then((response) => response.status)
    ).toBe(200)
    allowReconnect()
    for (let attempt = 0; attempt < 40 && (await storage.loadSessions()).length; attempt += 1) {
      await Bun.sleep(10)
    }
    expect(stops).toBe(1)
    expect(await storage.loadSessions()).toHaveLength(0)
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
    storage.writeDescriptor = writeDescriptor
    await server.stop().catch(() => undefined)
  }
}, 30_000)

test('failed conversation recovery retains a lost tombstone', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-recovery-tombstone-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'parent', root)
  const session = record(root, 'pty_recovery_tombstone')
  session.ownerCapabilityHash = context.capability
  session.worker = {
    pid: 1,
    startIdentity: 'start',
    processIdentity: 'identity',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: 'fingerprint',
    protocolVersion: 5,
  }
  await storage.writeSession(session)
  const reconnect = NativeWorkerClient.reconnect
  ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = async () => null
  const server = new DaemonServer(
    storage,
    new SessionSupervisor(storage, undefined, 1),
    'test-token'
  )
  try {
    const descriptor = await server.start()
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if ((await storage.loadSessions())[0]?.status === 'lost') break
      await Bun.sleep(10)
    }
    expect(
      await rpc(descriptor, 'get', { id: session.id }, context).then((response) => response.json())
    ).toMatchObject({
      result: { status: 'lost' },
    })
    expect(
      await rpc(descriptor, 'cleanup', { id: session.id }, context).then((response) =>
        response.json()
      )
    ).toMatchObject({
      result: false,
    })
    expect(await storage.loadSessions()).toMatchObject([
      { id: session.id, status: 'lost', pendingCleanup: true },
    ])
  } finally {
    ;(NativeWorkerClient as unknown as { reconnect: typeof reconnect }).reconnect = reconnect
    await server.stop().catch(() => undefined)
  }
}, 30_000)

test('Windows rename retries only transient contention', async () => {
  let attempts = 0
  await renameWithWindowsRetry(
    'source',
    'destination',
    async () => {
      attempts += 1
      if (attempts < 3) throw Object.assign(new Error('busy'), { code: 'EPERM' })
    },
    true
  )
  expect(attempts).toBe(3)
  await expect(
    renameWithWindowsRetry(
      'source',
      'destination',
      async () => {
        throw Object.assign(new Error('denied'), { code: 'EACCES' })
      },
      true
    )
  ).rejects.toThrow('denied')
})

test('journal orders chunks, retains complete UTF-8 chunks, and paginates by stable sequence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-journal-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_journal', 'exited')
  session.nextSequence = 11
  session.outputBytes = 11
  session.lineCount = 3
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 7, endSequence: 11, timestamp: '2026-01-01T00:00:02.000Z', data: 'end\n' },
    { startSequence: 0, endSequence: 2, timestamp: '2026-01-01T00:00:00.000Z', data: 'a\n' },
    { startSequence: 2, endSequence: 7, timestamp: '2026-01-01T00:00:01.000Z', data: '😀\n' },
  ])

  expect(await storage.readOutput(session.id)).toBe('a\n😀\nend\n')
  expect(await storage.trimOutput(session.id, 9)).toEqual({
    outputBytes: 9,
    firstRetainedSequence: 2,
    outputTruncated: true,
  })
  expect(await storage.readOutput(session.id)).toBe('😀\nend\n')

  session.firstRetainedSequence = 2
  session.outputBytes = 9
  session.outputTruncated = true
  session.lineCount = 2
  await storage.writeSession(session)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  expect(await supervisor.read(session.id, 0, 1)).toMatchObject({
    lines: ['😀'],
    sequences: [2],
    totalLines: 2,
    hasMore: true,
    firstRetainedSequence: 2,
    nextSequence: 11,
    truncated: true,
  })
  expect(await supervisor.read(session.id, 0, 1, 6)).toMatchObject({
    lines: ['end'],
    sequences: [7],
    totalLines: 1,
    hasMore: false,
  })
  expect(await supervisor.search(session.id, 'end')).toMatchObject({
    matches: [{ lineNumber: 2, sequence: 7, text: 'end' }],
    firstRetainedSequence: 2,
    nextSequence: 11,
  })
})

test('journal recovery reconciles a stale retention cursor from retained chunks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-reconcile-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_reconcile', 'exited')
  session.nextSequence = 11
  session.outputBytes = 11
  session.lineCount = 3
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 7, endSequence: 11, timestamp: new Date().toISOString(), data: 'end\n' },
  ])

  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  expect(await recovered.read(session.id)).toMatchObject({
    lines: ['end'],
    sequences: [7],
    firstRetainedSequence: 7,
    nextSequence: 11,
    truncated: true,
  })
  expect((await storage.loadSessions())[0]).toMatchObject({
    firstRetainedSequence: 7,
    outputBytes: 4,
    outputTruncated: true,
  })
})

test('journal recovery marks output truncated when retention removes every chunk', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-empty-retention-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_empty_retention', 'exited')
  session.nextSequence = 4
  session.outputBytes = 4
  session.lineCount = 1
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 4, timestamp: new Date().toISOString(), data: 'one\n' },
  ])
  await storage.trimOutput(session.id, 0)

  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  expect(await recovered.read(session.id)).toMatchObject({
    lines: [],
    firstRetainedSequence: 4,
    nextSequence: 4,
    truncated: true,
  })
})

test('journal recovery completes retention recorded before chunk deletion', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-pending-retention-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_pending_retention', 'exited')
  session.nextSequence = 4
  session.firstRetainedSequence = 4
  session.outputTruncated = true
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 4, timestamp: new Date().toISOString(), data: 'one\n' },
  ])

  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  expect(await recovered.read(session.id)).toMatchObject({
    lines: [],
    firstRetainedSequence: 4,
    nextSequence: 4,
    truncated: true,
  })
  expect(await storage.readOutput(session.id)).toBe('')
})

test('restart migrates V0 output and marks active sessions lost without losing it', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v0-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v1')
  session.nextSequence = 10
  session.outputBytes = 10
  session.lineCount = 1
  await storage.writeSession(session)
  await writeFile(
    join(root, 'sessions', session.id, 'session.json'),
    JSON.stringify(
      Object.fromEntries(
        Object.entries(session).filter(
          ([key]) => key !== 'recordVersion' && key !== 'outputJournalVersion'
        )
      )
    )
  )
  await writeFile(join(root, 'sessions', session.id, 'output.log'), 'lost 😀\n', 'utf8')

  const recovered = new SessionSupervisor(storage)
  await recovered.initialize(false)
  await recovered.markConversationRecoveryCleanup()
  await recovered.reconcileWorkers()
  expect(await recovered.get(session.id)).toMatchObject({ status: 'lost', outputSequence: 10 })
  expect(await recovered.rawOutput(session.id)).toEqual({ raw: 'lost 😀\n', byteLength: 10 })
  expect(await recovered.read(session.id)).toMatchObject({ lines: ['lost 😀'], sequences: [0] })
  expect(await Bun.file(join(root, 'sessions', session.id, 'output.log')).exists()).toBeTrue()
})

test('obsolete worker terminal records remain readable and owner-cleanable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-obsolete-worker-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_obsolete_worker', 'exited')
  markTerminalProof(session)
  session.lifecycle = 'persistent'
  session.worker = {
    pid: 123,
    startIdentity: 'old',
    processIdentity: 'old',
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: 1,
  }
  session.nextSequence = 6
  session.outputBytes = 6
  session.lineCount = 1
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 0, endSequence: 6, timestamp: new Date().toISOString(), data: 'saved\n' },
  ])
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  expect(await supervisor.get(session.id)).toMatchObject({ status: 'exited' })
  expect(await supervisor.rawOutput(session.id)).toMatchObject({ raw: 'saved\n', byteLength: 6 })
  expect(await supervisor.cleanup(session.id)).toBeTrue()
})

test('V0 migration keeps output.log until V2 metadata is durable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v0-recovery-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v1_recovery', 'exited')
  markTerminalProof(session)
  session.nextSequence = 7
  session.outputBytes = 7
  session.lineCount = 1
  await storage.writeSession(session)
  await writeFile(
    join(root, 'sessions', session.id, 'session.json'),
    JSON.stringify(
      Object.fromEntries(
        Object.entries(session).filter(
          ([key]) => key !== 'recordVersion' && key !== 'outputJournalVersion'
        )
      )
    )
  )
  const legacyPath = join(root, 'sessions', session.id, 'output.log')
  await writeFile(legacyPath, 'legacy\n', 'utf8')

  const writeSession = storage.writeSession.bind(storage)
  storage.writeSession = async () => {
    throw Object.assign(new Error('disk full'), { code: 'ENOSPC' })
  }
  await expect(storage.loadSessions()).rejects.toThrow('disk full')
  expect(await Bun.file(legacyPath).exists()).toBeTrue()
  storage.writeSession = writeSession

  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  expect(await recovered.rawOutput(session.id)).toMatchObject({ raw: 'legacy\n', byteLength: 7 })
  expect(await Bun.file(legacyPath).exists()).toBeFalse()
})

test('daemon classifies storage failures', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-storage-error-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = {
    initialize: async () => {},
    markConversationRecoveryCleanup: async () => {},
    reconcileWorkers: async () => {},
    flush: async () => {},
    shutdown: async () => {},
    list: async () => {
      throw Object.assign(new Error('disk full'), { code: 'ENOSPC' })
    },
  } as unknown as SessionSupervisor
  const server = new DaemonServer(storage, supervisor, 'test-token')
  const descriptor = await server.start()
  try {
    const response = await fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: 'list',
        version: DAEMON_PROTOCOL_VERSION,
        operation: 'list',
        owner: {
          parentSessionId: 'parent',
          projectDirectory: root,
          capability: (await owner(storage, 'parent', root)).capability,
        },
      }),
    })
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe('storage')
  } finally {
    await server.stop()
  }
})

test('daemon classifies PTY failures as process failures', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-process-error-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = {
    initialize: async () => {},
    markConversationRecoveryCleanup: async () => {},
    reconcileWorkers: async () => {},
    flush: async () => {},
    shutdown: async () => {},
    list: async () => [],
    spawn: async () => {
      throw new ProcessError('spawn failed')
    },
  } as unknown as SessionSupervisor
  const server = new DaemonServer(storage, supervisor, 'test-token')
  const descriptor = await server.start()
  try {
    const response = await fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: 'spawn',
        version: DAEMON_PROTOCOL_VERSION,
        operation: 'spawn',
        owner: {
          parentSessionId: 'parent',
          projectDirectory: root,
          capability: (await owner(storage, 'parent', root)).capability,
        },
        payload: { command: 'test', parentSessionId: 'parent', description: 'test' },
      }),
    })
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe('process')
  } finally {
    await server.stop()
  }
})

test('supervisor preserves terminal cleanup state and output cursors', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-supervisor-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await storage.initialize()
  const terminal = record(root, 'pty_terminal', 'exited')
  markTerminalProof(terminal)
  terminal.worker = {
    pid: 1,
    startIdentity: 'start',
    processIdentity: 'identity',
    endpoint: 'http://127.0.0.1:1',
    tokenFingerprint: new Bun.CryptoHasher('sha256').update('terminal-token').digest('hex'),
    protocolVersion: 5,
  }
  const output = record(root, 'pty_output', 'exited')
  output.nextSequence = 8
  output.outputBytes = 8
  output.lineCount = 2
  await supervisor.initialize()
  const state = supervisor as unknown as {
    records: Map<string, SessionRecord>
  }
  for (const entry of [terminal, output]) {
    state.records.set(entry.id, entry)
    await storage.writeSession(entry)
  }
  const descriptorPath = join(root, 'sessions', terminal.id, 'worker.json')
  await writeFile(
    descriptorPath,
    JSON.stringify({
      pid: terminal.worker.pid,
      startIdentity: terminal.worker.startIdentity,
      processIdentity: terminal.worker.processIdentity,
      endpoint: terminal.worker.endpoint,
      token: 'terminal-token',
      protocolVersion: terminal.worker.protocolVersion,
    })
  )
  await storage.appendOutput('pty_output', [
    { startSequence: 0, endSequence: 8, timestamp: new Date().toISOString(), data: 'one\nhit\n' },
  ])

  const read = await supervisor.read('pty_output')
  const search = await supervisor.search('pty_output', 'hit')
  expect(read.sequences).toEqual([0, 4])
  expect(search.matches).toEqual([{ lineNumber: 2, sequence: 4, text: 'hit' }])
  expect(formatLine('hit', 2, 2000, 4)).toBe('00002@4| hit')

  const deleteSession = storage.deleteSession.bind(storage)
  const reconnect = NativeWorkerClient.reconnect
  let reconnects = 0
  let shutdowns = 0
  NativeWorkerClient.reconnect = async () => {
    reconnects += 1
    return {
      shutdown: async () => {
        shutdowns += 1
        return workerSnapshot({
          status: 'exited',
          terminationRequested: true,
          terminationConfirmed: true,
          directChildExited: true,
          stdoutEof: true,
          stderrEof: true,
          outputComplete: true,
        })
      },
    } as unknown as WorkerClient
  }
  storage.deleteSession = async () => {
    throw Object.assign(new Error('disk full'), { code: 'ENOSPC' })
  }
  try {
    await expect(supervisor.cleanup('pty_terminal')).rejects.toThrow('disk full')
    expect(await supervisor.get('pty_terminal')).not.toBeNull()
    expect(await Bun.file(descriptorPath).exists()).toBeTrue()
    storage.deleteSession = deleteSession
    expect(await supervisor.cleanup('pty_terminal')).toBeTrue()
    expect(reconnects).toBe(1)
    expect(shutdowns).toBe(1)
  } finally {
    storage.deleteSession = deleteSession
    NativeWorkerClient.reconnect = reconnect
  }
})

test('plugin client starts its daemon from the configured data directory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-client-'))
  roots.push(root)
  const previousDirectory = process.env.PTY_DAEMON_DIR
  const previousWorkerPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_DAEMON_DIR = root
  process.env.PTY_NATIVE_WORKER_PATH = nativeWorkerPath
  const storage = new DaemonStorage(root)
  let pid: number | undefined
  try {
    await storage.initialize()
    await storage.writeDescriptor({
      pid: process.pid,
      processIdentity: 'stale',
      endpoint: 'http://127.0.0.1:1',
      protocolVersion: DAEMON_PROTOCOL_VERSION,
      token: 'stale-token',
    })
    const client = new DaemonClient()
    const owner = ownerContext('test-session', root)
    expect(await client.list(owner)).toEqual([])
    pid = (await storage.readDescriptor())?.pid
    expect(pid).toBeNumber()
    expect((await storage.readDescriptor())?.token).not.toBe('stale-token')
    const recreated = new DaemonClient()
    expect(await recreated.list(owner)).toEqual([])
  } finally {
    if (pid) process.kill(pid)
    if (pid) expect(await processGone(pid)).toBeTrue()
    if (previousDirectory === undefined) delete process.env.PTY_DAEMON_DIR
    else process.env.PTY_DAEMON_DIR = previousDirectory
    if (previousWorkerPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousWorkerPath
  }
}, 15_000)

test('daemon client returns RPC sequence cursor and truncation metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-client-read-'))
  roots.push(root)
  const previousDirectory = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_client_read', 'exited')
  session.lifecycle = 'persistent'
  session.ownerCapabilityHash = (await owner(storage, 'parent', root)).capability
  session.nextSequence = 11
  session.firstRetainedSequence = 2
  session.outputBytes = 9
  session.outputTruncated = true
  session.lineCount = 2
  await storage.writeSession(session)
  await storage.appendOutput(session.id, [
    { startSequence: 2, endSequence: 7, timestamp: new Date().toISOString(), data: '😀\n' },
    { startSequence: 7, endSequence: 11, timestamp: new Date().toISOString(), data: 'end\n' },
  ])
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  await server.start()
  try {
    expect(
      await new DaemonClient().read(session.id, 0, 1, 7, ownerContext('parent', root))
    ).toEqual({
      lines: ['end'],
      sequences: [7],
      totalLines: 1,
      offset: 0,
      hasMore: false,
      firstRetainedSequence: 2,
      nextSequence: 11,
      truncated: true,
    })
  } finally {
    await server.stop()
    if (previousDirectory === undefined) delete process.env.PTY_DAEMON_DIR
    else process.env.PTY_DAEMON_DIR = previousDirectory
  }
})
