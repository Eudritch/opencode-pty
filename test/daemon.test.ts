import { afterEach, expect, test } from 'bun:test'
import { existsSync, realpathSync, watch } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DaemonServer } from '../src/daemon/server.ts'
import {
  DaemonStorage,
  parseWindowsProcessIdentity,
  processIdentityProbe,
  processStartIdentity,
  requiredProcessStartIdentity,
  windowsProcessIdentityCommand,
} from '../src/daemon/storage.ts'
import { WorkerClient as NativeWorkerClient } from '../src/daemon/worker-client.ts'
import {
  effectiveMaxOutputBytes,
  OutputRedactor,
  ProcessError,
  runtimeEnvironment,
  SessionSupervisor,
} from '../src/daemon/supervisor.ts'
import { DAEMON_PROTOCOL_VERSION, type SessionRecord } from '../src/daemon/types.ts'
import type { SpawnOptions } from '../src/plugin/pty/types.ts'
import {
  daemonLaunchCommand,
  daemonReadinessDeadline,
  DaemonClient,
  ownerContext,
  resolveDaemonLauncher,
  safeStartupStderrTail,
} from '../src/plugin/pty/daemon-client.ts'
import { formatLine, formatSessionInfo } from '../src/plugin/pty/formatters.ts'
import { createSpawnAuthorizer } from '../src/plugin/pty/permissions.ts'
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
const nativeWorkerPath = join(
  process.cwd(),
  'target',
  'debug',
  `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
)
if (existsSync(nativeWorkerPath)) process.env.PTY_NATIVE_WORKER_PATH ??= nativeWorkerPath

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

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

function record(
  root: string,
  id: string,
  status: SessionRecord['status'] = 'running'
): SessionRecord {
  const now = new Date().toISOString()
  return {
    id,
    title: id,
    command: 'test',
    args: [],
    mode: 'pty',
    workdir: root,
    ownerProjectDirectory: root,
    ownerCapabilityHash: '',
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

test('daemon authenticates RPC and retains PTY output', async () => {
  if (process.platform === 'win32') return
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
      exited = ((await details.json()) as { result: { status: string } }).result.status === 'exited'
    }
    expect(output).toContain('durable output')
    expect(exited).toBeTrue()
  } finally {
    await server.stop()
  }
})

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

test('daemon denies other owners and reports bounded diagnostics', async () => {
  if (process.platform === 'win32') return
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
    })
    const id = ((await spawned.json()) as { result: { id: string } }).result.id
    const denied = await rpc('read', { id }, two)
    expect(((await denied.json()) as { error: { code: string } }).error.code).toBe('authorization')
    const invalidCapability = await rpc('list', {}, { ...one, capability: 'x'.repeat(64) })
    expect(((await invalidCapability.json()) as { error: { code: string } }).error.code).toBe(
      'authorization'
    )
    const diagnostics = (await (await rpc('diagnostics', {})).json()) as {
      result: { limits: { maxSessionsPerOwner: number }; platform: { nativeContainment: boolean } }
    }
    expect(diagnostics.result.limits.maxSessionsPerOwner).toBe(32)
    expect(diagnostics.result.platform.nativeContainment).toBeTrue()
    await rpc('stop', { id })
  } finally {
    await server.stop()
  }
})

test('a new client retains owned output, list, and cleanup access after daemon restart', async () => {
  if (process.platform === 'win32') return
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
    process.env.PTY_DAEMON_DIR = previousDirectory
  }
})

test('server canonicalizes project owners and limits only active PTY and exec sessions', async () => {
  if (process.platform === 'win32') return
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
        { command: process.execPath, args: ['-e', 'setTimeout(() => {}, 100)'], timeoutSeconds: 1 },
        canonical
      ),
      rpc(
        descriptor,
        'exec',
        { command: process.execPath, args: ['-e', 'setTimeout(() => {}, 100)'], timeoutSeconds: 1 },
        canonical
      ),
    ])
    const results = [await firstExec.json(), await secondExec.json()] as Array<{
      result?: { session: { id: string } }
      error?: { code: string }
    }>
    expect(results.filter((result) => result.error?.code === 'limit')).toHaveLength(1)
    const exec = results.find((result) => result.result) as { result: { session: { id: string } } }
    expect(exec.result.session.id).toStartWith('exec_')
  } finally {
    await server.stop()
  }
})

test('conversation cleanup excludes persistent sessions and environment values stay out of records', async () => {
  if (process.platform === 'win32') return
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
    ownerCapabilityHash: 'capability',
    workdir: root,
    env: { API_TOKEN: 'test-secret-value' },
  }
  const conversation = await supervisor.spawn(common)
  const persistent = await supervisor.spawn({ ...common, lifecycle: 'persistent' })
  const other = await supervisor.spawn({
    ...common,
    ownerProjectDirectory: otherProject,
    ownerCapabilityHash: 'other-capability',
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
      await supervisor.exec({
        ...common,
        args: ['-e', 'console.log(process.env.API_TOKEN)'],
        timeoutSeconds: 2,
      })
    ).stdout
  ).toBe('[REDACTED]\n')
  await supervisor.cleanupByParentSession('owner', root, 'capability')
  expect((await supervisor.get(conversation.id))?.terminationRequested).toBeTrue()
  expect((await supervisor.get(persistent.id))?.terminationRequested).toBeFalse()
  expect((await supervisor.get(other.id))?.terminationRequested).toBeFalse()
  await supervisor.stop(persistent.id)
  await supervisor.stop(other.id)
  await Bun.sleep(50)
  await supervisor.flush()
})

test('spawn permission adapter fails closed, applies agent overrides, and isolates plugin contexts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-permissions-'))
  const external = await mkdtemp(join(tmpdir(), 'opencode-pty-permissions-external-'))
  roots.push(root, external)
  const authorizer = (permission: unknown, directory = root, agent?: unknown) =>
    createSpawnAuthorizer(
      {
        config: { get: async () => ({ data: { permission, agent } }) },
        tui: { showToast: async () => {} },
      } as never,
      directory
    )
  const allow = authorizer({ bash: { '*': 'deny', [`${process.execPath} *`]: 'allow' } })
  expect(await allow(process.execPath, ['-e', 'process.exit()'], root)).toBe(root)
  await expect(authorizer({})(process.execPath, [], root)).rejects.toThrow('no explicit allow')
  await expect(authorizer({ bash: { '*': 'allow' } })('other-command', [], root)).resolves.toBe(
    root
  )
  await expect(
    authorizer({ bash: { '*': 'allow' } })(process.execPath, [], external)
  ).rejects.toThrow('external_directory allow')
  expect(
    await authorizer({ bash: { '*': 'allow' }, external_directory: 'allow' })(
      process.execPath,
      [],
      external
    )
  ).toBe(external)
  await expect(authorizer({ bash: 'ask' })(process.execPath, [], root)).rejects.toThrow(
    'no explicit allow'
  )
  await expect(authorizer('allow')(process.execPath, [], root)).resolves.toBe(root)
  await expect(
    authorizer(
      {
        bash: { '*': 'allow' },
      },
      root,
      { reviewer: { permission: { bash: { '*': 'deny' } } } }
    )(process.execPath, [], root, 'reviewer')
  ).rejects.toThrow('no explicit allow')
  await expect(
    authorizer(
      {
        bash: { '*': 'deny' },
      },
      root,
      { builder: { permission: { bash: { '*': 'allow' } } } }
    )(process.execPath, [], root, 'builder')
  ).resolves.toBe(root)
  const git = authorizer({ bash: { '*': 'deny', 'git status': 'allow' } })
  await expect(git('git', ['status'], root)).resolves.toBe(root)
  await expect(git('git', ['reset', '--hard', 'status'], root)).rejects.toThrow('no explicit allow')
  await expect(
    authorizer({ bash: { '*': 'deny', 'git *': 'allow' } })('git', ['status'], root)
  ).resolves.toBe(root)
  await expect(
    authorizer({ bash: { '*': 'allow', 'git *': 'deny' } })('git', ['status'], root)
  ).rejects.toThrow('no explicit allow')
  const secondRoot = await mkdtemp(join(tmpdir(), 'opencode-pty-permissions-second-'))
  roots.push(secondRoot)
  await Promise.all([
    expect(allow(process.execPath, ['-e', 'process.exit()'], root)).resolves.toBe(root),
    expect(
      authorizer({ bash: 'deny' }, secondRoot)(process.execPath, [], secondRoot)
    ).rejects.toThrow('no explicit allow'),
  ])
})

test('streaming redaction keeps split secrets out of PTY journals and exec streams', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-redaction-stream-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const exec = await supervisor.exec({
    command: process.execPath,
    args: [
      '-e',
      "process.stdout.write('before split-sec'); setTimeout(() => process.stdout.write('ret-value after\\n'), 20)",
    ],
    env: { API_TOKEN: 'split-secret-value' },
    parentSessionId: 'parent',
    timeoutSeconds: 2,
  })
  expect(exec.stdout).toBe('before [REDACTED] after\n')
  expect(exec.stdout).not.toContain('split-secret-value')
  expect((await supervisor.execOutput(exec.session.id))?.stdout).not.toContain('split-secret-value')
})

test('private and signing key environment values are redacted across chunks', () => {
  for (const key of ['SSH_PRIVATE_KEY', 'PRIVATE_KEY', 'TLS_PRIVATE_KEY', 'SIGNING_KEY']) {
    const redactor = new OutputRedactor({ [key]: 'private-key-value' })
    expect(
      `${redactor.write('before private-')}${redactor.write('key-value after')}${redactor.finish()}`
    ).toBe('before [REDACTED] after')
  }
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

test('Windows process identity probe identifies the current process', async () => {
  if (process.platform !== 'win32') return
  expect(await processStartIdentity(process.pid)).toMatch(
    new RegExp(`^windows:${process.pid}:\\d+$`)
  )
})

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
})

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
})

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
})

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
})

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
})

test('startup stderr never reports a three-character environment secret', () => {
  expect(safeStartupStderrTail('daemon failed: abc', 'token', 'options')).toBeNull()
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
  legacy.nextSequence = 7
  legacy.outputBytes = 7
  legacy.lineCount = 1
  await storage.writeSession(legacy)
  await writeFile(
    join(root, 'sessions', legacy.id, 'session.json'),
    JSON.stringify(
      Object.fromEntries(Object.entries(legacy).filter(([key]) => key !== 'outputJournalVersion'))
    )
  )
  await writeFile(join(root, 'sessions', legacy.id, 'output.log'), 'legacy\n', 'utf8')

  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()

  expect((await supervisor.list()).map((item) => item.id)).toEqual([legacy.id])
  expect(await supervisor.rawOutput(legacy.id)).toEqual({ raw: 'legacy\n', byteLength: 7 })
  expect(await readdir(join(root, 'quarantine'))).toHaveLength(invalid.length)
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

  const success = await supervisor.exec({
    command: process.execPath,
    args: ['-e', "console.log('out'); console.error('err')"],
    parentSessionId: 'parent',
    timeoutSeconds: 2,
  })
  expect(success).toMatchObject({ stdout: 'out\n', stderr: 'err\n', exitCode: 0, timedOut: false })

  const failure = await supervisor.exec({
    command: process.execPath,
    args: ['-e', "console.error('failed'); process.exit(7)"],
    parentSessionId: 'parent',
    timeoutSeconds: 2,
  })
  expect(failure).toMatchObject({ stderr: 'failed\n', exitCode: 7, timedOut: false })

  const timeout = await supervisor.exec({
    command: process.execPath,
    args: ['-e', 'setTimeout(() => {}, 5000)'],
    parentSessionId: 'parent',
    timeoutSeconds: 1,
  })
  expect(timeout.timedOut).toBeTrue()

  const limited = await supervisor.exec({
    command: process.execPath,
    args: ['-e', "process.stdout.write('x'.repeat(100))"],
    parentSessionId: 'parent',
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
})

test('exec force-kills after grace and reports bounded, truthful termination state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-kill-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  await supervisor.initialize()
  const started = Date.now()
  const result = await supervisor.exec({
    command: process.execPath,
    args: [
      '-e',
      process.platform === 'win32'
        ? 'setInterval(() => {}, 1000)'
        : "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)",
    ],
    parentSessionId: 'parent',
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
  const result = await supervisor.exec({
    command: process.execPath,
    args: ['-e', "process.stdout.write('A😀B')"],
    parentSessionId: 'parent',
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
  const result = await supervisor.exec({
    command: process.execPath,
    args: ['-e', "process.stdout.write('before-super-secret-value-after')"],
    env: { API_TOKEN: 'super-secret-value' },
    parentSessionId: 'parent',
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

test('PTY idempotency reuses only an active matching owner and spec', async () => {
  if (process.platform === 'win32') return
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-idempotency-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const options = {
    command: process.execPath,
    args: ['-e', 'setTimeout(() => {}, 5000)'],
    parentSessionId: 'owner',
    workdir: root,
    name: 'server',
    idempotencyKey: 'deploy-1',
  }
  const first = await supervisor.spawn(options)
  const reused = await supervisor.spawn(options)
  expect(reused.id).toBe(first.id)
  expect(
    (await supervisor.spawn({ ...options, title: 'renamed', description: 'changed presentation' }))
      .id
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
})

test('PTY idempotency canonicalizes environment order and scopes only by parent and workdir', async () => {
  if (process.platform === 'win32') return
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-idempotency-scope-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  await supervisor.initialize()
  const base = {
    command: process.execPath,
    args: ['-e', 'setTimeout(() => {}, 5000)'],
    parentSessionId: 'owner',
    workdir: root,
    idempotencyKey: 'same',
    env: { A: '1', Z: '2' },
  }
  const first = await supervisor.spawn(base)
  expect((await supervisor.spawn({ ...base, env: { Z: '2', A: '1' } })).id).toBe(first.id)
  const other = await supervisor.spawn({ ...base, parentSessionId: 'other' })
  expect(other.id).not.toBe(first.id)
  await supervisor.stop(first.id)
  await supervisor.stop(other.id)
  await Bun.sleep(25)
  await supervisor.flush()
})

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
        idempotencyKey: 'same',
        inheritEnv: true,
      },
      []
    )
  ).toThrow('different command or specification')
})

test('daemon waits for output, exit, and deadline without plugin polling', async () => {
  if (process.platform === 'win32') return
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
})

test('sendWait ignores output before input acceptance and waits for later output', async () => {
  if (process.platform === 'win32') return
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
})

test('sendWait observes an immediate response after accepted input', async () => {
  if (process.platform === 'win32') return
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
})

test('sendWait excludes drained pre-acceptance output and observes its immediate reply', async () => {
  if (process.platform === 'win32') return
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
  const session = await supervisor.spawn({
    command: process.execPath,
    args: [
      '-e',
      `process.stdin.setRawMode(true); process.stdout.write('old\\n'); require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ready'); process.stdin.once('data', () => process.stdout.write('new\\n'))`,
    ],
    env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'pause_terminal_reader_until_write' },
    parentSessionId: 'parent',
    workdir: root,
  })
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
})

test('sendWait flushes a held redaction tail before its input boundary', async () => {
  if (process.platform === 'win32') return
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
  const session = await supervisor.spawn({
    command: process.execPath,
    args: [
      '-e',
      `process.stdin.setRawMode(true); process.stdout.write('old-match'); require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ready'); process.stdin.once('data', () => process.stdout.write('new-match\\n'))`,
    ],
    env: {
      API_TOKEN: 'tail-secret',
      OPENCODE_PTY_NATIVE_WORKER_FAULT: 'pause_terminal_reader_until_write',
    },
    parentSessionId: 'parent',
    workdir: root,
  })
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
})

test('exec output remains separately recoverable after restart', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-exec-record-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()
  const result = await supervisor.exec({
    command: process.execPath,
    args: ['-e', "process.stdout.write('out'); process.stderr.write('err')"],
    parentSessionId: 'parent',
    timeoutSeconds: 2,
  })
  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  expect(await recovered.execOutput(result.session.id)).toEqual({
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
  const previousEnabled = process.env.PTY_NATIVE_WORKER_ENABLED
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_ENABLED = '1'
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
    await Bun.sleep(100)
    await first.stop()
    restarted = new DaemonServer(storage, new SessionSupervisor(storage), 'native-second')
    const secondDescriptor = await restarted.start()
    const stopped = await rpc(secondDescriptor, 'stop', { id }, context)
    expect((await stopped.json()) as { result: { terminationConfirmed: boolean } }).toMatchObject({
      result: { terminationConfirmed: true },
    })
    const details = await rpc(secondDescriptor, 'get', { id }, context)
    expect(
      (await details.json()) as { result: { status: string; terminationConfirmed: boolean } }
    ).toMatchObject({ result: { status: 'exited', terminationConfirmed: true } })
    await expect(executing.then((response) => response.json())).resolves.toMatchObject({
      result: { stdout: 'native-out', stderr: 'native-err', terminationConfirmed: true },
    })
    const chunks = await storage.readOutputChunks(id)
    expect(chunks.map((chunk) => chunk.data).join('')).toContain('native-out')
    expect(chunks.every((chunk) => /^\d{4}-\d{2}-\d{2}T.*Z$/.test(chunk.timestamp))).toBeTrue()
    expect(
      await rpc(
        secondDescriptor,
        'cleanupByParentSession',
        { parentSessionId: context.parentSessionId },
        context
      ).then((response) => response.json())
    ).toMatchObject({ ok: true })
    await expect(stat(join(root, 'sessions', id, 'worker.json'))).rejects.toThrow()
  } finally {
    await restarted?.stop()
    await first.stop().catch(() => undefined)
    if (previousEnabled === undefined) delete process.env.PTY_NATIVE_WORKER_ENABLED
    else process.env.PTY_NATIVE_WORKER_ENABLED = previousEnabled
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
})

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
  const previousEnabled = process.env.PTY_NATIVE_WORKER_ENABLED
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_ENABLED = '1'
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-limits', root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-limits')
  try {
    const descriptor = await server.start()
    const capped = await rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: ['-e', "process.stdout.write('x'.repeat(64)); process.stderr.write('y'.repeat(64))"],
        timeoutSeconds: 2,
        maxOutputBytes: 64,
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
      error: { code: 'storage' },
    })
    expect(
      await rpc(descriptor, 'get', { id }, context).then((response) => response.json())
    ).toMatchObject({
      result: { status: 'lost', terminationConfirmed: true },
    })
    await expect(stat(join(root, 'sessions', id, 'worker.json'))).rejects.toThrow()
  } finally {
    await server.stop()
    if (previousEnabled === undefined) delete process.env.PTY_NATIVE_WORKER_ENABLED
    else process.env.PTY_NATIVE_WORKER_ENABLED = previousEnabled
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
})

test('native startup failures clean up the direct child and report the proven outcome', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-startup-failure-'))
  roots.push(root)
  const workerPath = join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  await stat(workerPath)
  const previousEnabled = process.env.PTY_NATIVE_WORKER_ENABLED
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_ENABLED = '1'
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-startup-failure', root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-startup-failure')
  try {
    const descriptor = await server.start()
    const descriptorFailure = await rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000)'],
        env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'descriptor_write' },
        timeoutSeconds: 2,
      },
      context
    ).then((response) => response.json())
    expect(descriptorFailure).toMatchObject({
      ok: false,
      error: { code: 'process', spawnFailure: { cleanup: { terminationConfirmed: true } } },
    })
    const descriptorRecord = (await storage.loadSessions()).at(-1)
    expect(descriptorRecord).toMatchObject({
      status: 'spawn_failed',
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

    if (process.platform === 'win32') {
      const assignmentFailure = await rpc(
        descriptor,
        'exec',
        {
          command: process.execPath,
          args: ['-e', 'setInterval(() => {}, 1000)'],
          env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'job_assign' },
          timeoutSeconds: 2,
        },
        context
      ).then((response) => response.json())
      expect(assignmentFailure).toMatchObject({ ok: false, error: { code: 'process' } })
    }

    const readinessFailure = await rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000)'],
        env: {
          OPENCODE_PTY_NATIVE_WORKER_FAULT: 'missing_ready',
          OPENCODE_PTY_NATIVE_WORKER_READY_TIMEOUT_MS: '1000',
        },
        timeoutSeconds: 2,
      },
      context
    ).then((response) => response.json())
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
      status: 'spawn_failed',
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
      const containmentFailure = await rpc(
        descriptor,
        'exec',
        {
          command: process.execPath,
          args: ['-e', 'setInterval(() => {}, 1000)'],
          env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'unverified_containment' },
          timeoutSeconds: 2,
        },
        context
      ).then((response) => response.json())
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
              status: 'spawn_failed',
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
    if (previousEnabled === undefined) delete process.env.PTY_NATIVE_WORKER_ENABLED
    else process.env.PTY_NATIVE_WORKER_ENABLED = previousEnabled
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 10_000)

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
  const previousEnabled = process.env.PTY_NATIVE_WORKER_ENABLED
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  const previousProbeFault = process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_FAIL
  const previousProbeThrow = process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW
  process.env.PTY_NATIVE_WORKER_ENABLED = '1'
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
      { command: process.execPath, args: ['-e', 'setInterval(() => {}, 1000)'], timeoutSeconds: 2 },
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
      },
      context
    ).then((response) => response.json())
    expect(throwingProbeFailure).toMatchObject({
      error: { spawnFailure: { cleanup: { requested: true, terminationConfirmed: true } } },
    })
    await expect(stat(directChildMarker)).rejects.toThrow()
    delete process.env.OPENCODE_PTY_NATIVE_WORKER_IDENTITY_PROBE_THROW
    const readyFailure = await rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000)'],
        env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'ready_stdout' },
        timeoutSeconds: 2,
      },
      context
    ).then((response) => response.json())
    expect(readyFailure).toMatchObject({
      error: { spawnFailure: { cleanup: { terminationConfirmed: true } } },
    })
  } finally {
    await server.stop()
    if (previousEnabled === undefined) delete process.env.PTY_NATIVE_WORKER_ENABLED
    else process.env.PTY_NATIVE_WORKER_ENABLED = previousEnabled
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
        result: { protocolVersion: 4, pid: 123, processIdentity: 'different-worker' },
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
      protocolVersion: 4,
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
        protocolVersion: 4,
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
  const previousEnabled = process.env.PTY_NATIVE_WORKER_ENABLED
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_ENABLED = '1'
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-split-ready', root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-split-ready')
  try {
    const descriptor = await server.start()
    expect(
      await rpc(
        descriptor,
        'exec',
        {
          command: process.execPath,
          args: ['-e', 'process.exit(0)'],
          env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'split_ready' },
          timeoutSeconds: 2,
        },
        context
      ).then((response) => response.json())
    ).toMatchObject({ ok: true, result: { session: { status: 'exited' }, exitCode: 0 } })
  } finally {
    await server.stop()
    if (previousEnabled === undefined) delete process.env.PTY_NATIVE_WORKER_ENABLED
    else process.env.PTY_NATIVE_WORKER_ENABLED = previousEnabled
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 10_000)

test('Windows native stop drains Job descendants', async () => {
  if (process.platform !== 'win32') return
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
}, 10_000)

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
  const previousEnabled = process.env.PTY_NATIVE_WORKER_ENABLED
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_ENABLED = '1'
  process.env.PTY_NATIVE_WORKER_PATH = workerPath
  const storage = new DaemonStorage(root)
  const context = await owner(storage, 'native-rpc-loss', root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'native-rpc-loss')
  try {
    const descriptor = await server.start()
    const result = await rpc(
      descriptor,
      'exec',
      {
        command: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000)'],
        env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'rpc_loss_after_start' },
        timeoutSeconds: 2,
      },
      context
    ).then((response) => response.json())
    expect(result.ok).toBeBoolean()
    const session = (await storage.loadSessions()).find((entry) => entry.mode === 'exec')
    expect(await processGone(session?.pid ?? 0)).toBeTrue()
    if (session?.terminationConfirmed) expect(session.status).toBe('exited')
    else expect(session).toMatchObject({ status: 'lost', exitReason: { kind: 'unknown' } })
  } finally {
    await server.stop()
    if (previousEnabled === undefined) delete process.env.PTY_NATIVE_WORKER_ENABLED
    else process.env.PTY_NATIVE_WORKER_ENABLED = previousEnabled
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
}, 10_000)

test('native exec POSIX containment creates a fresh session, drains groups, escalates, and reports escapes', async () => {
  if (process.platform === 'win32') return
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-native-posix-'))
  roots.push(root)
  const workerPath = join(process.cwd(), 'target', 'debug', 'opencode-pty-worker')
  await stat(workerPath)
  const previousEnabled = process.env.PTY_NATIVE_WORKER_ENABLED
  const previousPath = process.env.PTY_NATIVE_WORKER_PATH
  process.env.PTY_NATIVE_WORKER_ENABLED = '1'
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
        { command: process.execPath, args: ['-e', script], timeoutSeconds: 3 },
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
            result: { timedOut: true, termination: { termSignalSent: true, killSignalSent: true } },
          }
        : {
            result: {
              timedOut: true,
              containment: { status: 'posix_containment_unknown', rootIdentityVerified: false },
              termination: { termSignalSent: true, killSignalSent: true, directChildExited: true },
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
      if (previousEnabled === undefined) delete process.env.PTY_NATIVE_WORKER_ENABLED
      else process.env.PTY_NATIVE_WORKER_ENABLED = previousEnabled
      if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
      else process.env.PTY_NATIVE_WORKER_PATH = previousPath
    }
  }
}, 15_000)

test('macOS normal direct-child completion is readable and cleanable without descendant confirmation', async () => {
  if (process.platform !== 'darwin') return
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
}, 10_000)

test('native PTY writes, resizes, rejects exec resize, and recovers after daemon restart', async () => {
  if (process.platform === 'win32') return
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
}, 15_000)

test('tool output XML escaping covers text and attributes', () => {
  expect(escapeXml(`<&>"'`)).toBe('&lt;&amp;&gt;&quot;&apos;')
  expect(escapeXml(`ok\u0000\u001f\ud800😀`)).toBe('ok���😀')
  expect(formatLine('<output>', 1)).toContain('&lt;output&gt;')
  expect(formatLine('😀x', 1, 1)).toContain('😀...')
})

test('native PTY has no implicit worker deadline', async () => {
  if (process.platform === 'win32') return
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
      workdir: root,
    })
    expect(session.timeoutSeconds).toBeUndefined()
    expect((await supervisor.get(session.id))?.timeoutSeconds).toBeUndefined()
    await supervisor.stop(session.id)
  } finally {
    if (previousPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousPath
  }
})

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

test('client preserves a healthy incompatible daemon descriptor', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-incompatible-'))
  roots.push(root)
  const processIdentity = (await processStartIdentity(process.pid)) ?? 'unavailable'
  const server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch: () =>
      Response.json({
        id: 'health',
        ok: true,
        result: {
          protocolVersion: DAEMON_PROTOCOL_VERSION + 1,
          pid: process.pid,
          processIdentity,
        },
      }),
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
    expect((await storage.readDescriptor())?.protocolVersion).toBe(DAEMON_PROTOCOL_VERSION + 1)
  } finally {
    server.stop(true)
    process.env.PTY_DAEMON_DIR = previousDirectory
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
      stdout: 'ignore',
      stderr: 'pipe',
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
      protocolVersion: DAEMON_PROTOCOL_VERSION,
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
        stdout: 'pipe',
        stderr: 'pipe',
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
        stdout: 'pipe',
        stderr: 'pipe',
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

test('lost sessions cannot be cleaned up', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-lost-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await storage.writeSession(record(root, 'pty_lost', 'lost'))
  await supervisor.initialize()

  expect(await supervisor.cleanup('pty_lost')).toBeFalse()
  expect(await storage.loadSessions()).toHaveLength(1)
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

test('restart migrates v1 output and marks active sessions lost without losing it', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v1-'))
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
      Object.fromEntries(Object.entries(session).filter(([key]) => key !== 'outputJournalVersion'))
    )
  )
  await writeFile(join(root, 'sessions', session.id, 'output.log'), 'lost 😀\n', 'utf8')

  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  expect(await recovered.get(session.id)).toMatchObject({ status: 'lost', outputSequence: 10 })
  expect(await recovered.rawOutput(session.id)).toEqual({ raw: 'lost 😀\n', byteLength: 10 })
  expect(await recovered.read(session.id)).toMatchObject({ lines: ['lost 😀'], sequences: [0] })
})

test('obsolete worker records remain readable, lost, and owner-cleanable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-obsolete-worker-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_obsolete_worker', 'exited')
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
  expect(await supervisor.get(session.id)).toMatchObject({ status: 'lost' })
  expect(await supervisor.rawOutput(session.id)).toEqual({ raw: 'saved\n', byteLength: 6 })
  expect(await supervisor.cleanup(session.id)).toBeTrue()
})

test('v1 migration keeps output.log until journal metadata is durable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v1-recovery-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v1_recovery', 'exited')
  session.nextSequence = 7
  session.outputBytes = 7
  session.lineCount = 1
  await storage.writeSession(session)
  await writeFile(
    join(root, 'sessions', session.id, 'session.json'),
    JSON.stringify(
      Object.fromEntries(Object.entries(session).filter(([key]) => key !== 'outputJournalVersion'))
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
  expect(await recovered.rawOutput(session.id)).toEqual({ raw: 'legacy\n', byteLength: 7 })
  expect(await Bun.file(legacyPath).exists()).toBeFalse()
})

test('daemon classifies storage failures', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-storage-error-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = {
    initialize: async () => {},
    flush: async () => {},
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
    flush: async () => {},
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
  await storage.appendOutput('pty_output', [
    { startSequence: 0, endSequence: 8, timestamp: new Date().toISOString(), data: 'one\nhit\n' },
  ])

  const read = await supervisor.read('pty_output')
  const search = await supervisor.search('pty_output', 'hit')
  expect(read.sequences).toEqual([0, 4])
  expect(search.matches).toEqual([{ lineNumber: 2, sequence: 4, text: 'hit' }])
  expect(formatLine('hit', 2, 2000, 4)).toBe('00002@4| hit')

  const deleteSession = storage.deleteSession.bind(storage)
  storage.deleteSession = async () => {
    throw Object.assign(new Error('disk full'), { code: 'ENOSPC' })
  }
  await expect(supervisor.cleanup('pty_terminal')).rejects.toThrow('disk full')
  expect(await supervisor.get('pty_terminal')).not.toBeNull()
  storage.deleteSession = deleteSession
  expect(await supervisor.cleanup('pty_terminal')).toBeTrue()
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
    process.env.PTY_DAEMON_DIR = previousDirectory
    if (previousWorkerPath === undefined) delete process.env.PTY_NATIVE_WORKER_PATH
    else process.env.PTY_NATIVE_WORKER_PATH = previousWorkerPath
  }
})

test('daemon client returns RPC sequence cursor and truncation metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-client-read-'))
  roots.push(root)
  const previousDirectory = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_client_read', 'exited')
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
    process.env.PTY_DAEMON_DIR = previousDirectory
  }
})
