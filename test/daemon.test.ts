import { afterEach, expect, test } from 'bun:test'
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DaemonServer } from '../src/daemon/server.ts'
import { DaemonStorage } from '../src/daemon/storage.ts'
import { ProcessError, SessionSupervisor } from '../src/daemon/supervisor.ts'
import { DAEMON_PROTOCOL_VERSION, type SessionRecord } from '../src/daemon/types.ts'
import { DaemonClient } from '../src/plugin/pty/daemon-client.ts'
import { ownerContext } from '../src/plugin/pty/daemon-client.ts'
import { formatLine } from '../src/plugin/pty/formatters.ts'
import { authorizeSpawn, initPermissions } from '../src/plugin/pty/permissions.ts'
import { escapeXml } from '../src/plugin/pty/xml.ts'

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
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

test('daemon authenticates RPC and retains PTY output', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  const descriptor = await server.start()
  const rpc = async (operation: string, payload?: unknown, token = 'test-token') =>
    fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation,
        owner: {
          parentSessionId: 'test-session',
          projectDirectory: root,
          capability: new Bun.CryptoHasher('sha256')
            .update(`test-token\0test-session\0${root}`)
            .digest('hex'),
        },
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
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-owner-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token')
  const descriptor = await server.start()
  const owner = (parentSessionId: string) => ({
    parentSessionId,
    projectDirectory: root,
    capability: new Bun.CryptoHasher('sha256')
      .update(`test-token\0${parentSessionId}\0${root}`)
      .digest('hex'),
  })
  const rpc = async (operation: string, payload: unknown, context = owner('one')) =>
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
    const denied = await rpc('read', { id }, owner('two'))
    expect(((await denied.json()) as { error: { code: string } }).error.code).toBe('authorization')
    const invalidCapability = await rpc('list', {}, { ...owner('one'), capability: 'x'.repeat(64) })
    expect(((await invalidCapability.json()) as { error: { code: string } }).error.code).toBe(
      'authorization'
    )
    const diagnostics = (await (await rpc('diagnostics', {})).json()) as {
      result: { limits: { maxSessionsPerOwner: number }; platform: { nativeContainment: boolean } }
    }
    expect(diagnostics.result.limits.maxSessionsPerOwner).toBe(32)
    expect(diagnostics.result.platform.nativeContainment).toBeFalse()
    await rpc('stop', { id })
  } finally {
    await server.stop()
  }
})

test('conversation cleanup excludes persistent sessions and environment values stay out of records', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-lifecycle-'))
  roots.push(root)
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
  await supervisor.cleanupByParentSession('owner')
  expect((await supervisor.get(conversation.id))?.terminationRequested).toBeTrue()
  expect((await supervisor.get(persistent.id))?.terminationRequested).toBeFalse()
  await supervisor.stop(persistent.id)
  await Bun.sleep(50)
  await supervisor.flush()
})

test('spawn permission adapter checks argv and returns a canonical workdir', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-permissions-'))
  roots.push(root)
  let configReads = 0
  initPermissions(
    {
      config: {
        get: async () => {
          configReads += 1
          return { data: { permission: { bash: { [process.execPath]: 'allow' } } } }
        },
      },
      tui: { showToast: async () => {} },
    } as never,
    root
  )

  expect(await authorizeSpawn(process.execPath, ['-e', 'process.exit()'], root)).toBe(root)
  expect(configReads).toBe(1)

  initPermissions(
    {
      config: { get: async () => ({ data: { permission: { bash: 'deny' } } }) },
      tui: { showToast: async () => {} },
    } as never,
    root
  )
  await expect(authorizeSpawn(process.execPath, [], root)).rejects.toThrow('disabled')
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

test('PTY idempotency reuses only an active matching owner and spec', async () => {
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
  await supervisor.stop(first.id)
  await Bun.sleep(25)
  await supervisor.flush()
})

test('PTY idempotency canonicalizes environment order and scopes only by parent and workdir', async () => {
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

test('daemon waits for output, exit, and deadline without plugin polling', async () => {
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

test('sendWait ignores output before its durable write cursor and wait settles one race winner', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-send-wait-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  await supervisor.initialize()
  const session = await supervisor.spawn({
    command: process.execPath,
    args: [
      '-e',
      "setTimeout(() => console.log('old ready'), 50); setTimeout(() => console.log('new ready'), 500); setTimeout(() => process.exit(0), 800)",
    ],
    parentSessionId: 'parent',
    workdir: root,
  })
  await Bun.sleep(200)
  const result = await supervisor.sendWait(
    session.id,
    'go\n',
    { kind: 'output', literal: 'new ready' },
    2
  )
  expect(result).toMatchObject({ satisfied: true, reason: 'output', matched: 'new ready' })
  const exit = await supervisor.wait(session.id, { kind: 'exit' }, 2)
  expect(exit).toMatchObject({ satisfied: true, reason: 'exit', exitCode: 0 })
  expect((await supervisor.get(session.id))?.lastWaitResult).toMatchObject({ reason: 'exit' })
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

test('tool output XML escaping covers text and attributes', () => {
  expect(escapeXml(`<&>"'`)).toBe('&lt;&amp;&gt;&quot;&apos;')
  expect(formatLine('<output>', 1)).toContain('&lt;output&gt;')
})

test('client preserves a healthy incompatible daemon descriptor', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-incompatible-'))
  roots.push(root)
  const server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch: () =>
      Response.json({
        id: 'health',
        ok: true,
        result: { protocolVersion: DAEMON_PROTOCOL_VERSION + 1, pid: process.pid },
      }),
  })
  const previousDirectory = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  const storage = new DaemonStorage(root)
  await storage.initialize()
  await storage.writeDescriptor({
    pid: process.pid,
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

test('daemon storage protects private paths on POSIX', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-modes-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  await storage.initialize()
  await storage.writeDescriptor({
    pid: process.pid,
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
      (await stat(join(root, 'sessions', 'pty_test', 'output', '00000000000000000000.json'))).mode &
        0o777
    ).toBe(0o600)
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
          capability: new Bun.CryptoHasher('sha256')
            .update(`test-token\0parent\0${root}`)
            .digest('hex'),
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
          capability: new Bun.CryptoHasher('sha256')
            .update(`test-token\0parent\0${root}`)
            .digest('hex'),
        },
        payload: { command: 'test', parentSessionId: 'parent', description: 'test' },
      }),
    })
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe('process')
  } finally {
    await server.stop()
  }
})

test('supervisor preserves timeout diagnostics, stop state, cleanup state, and output cursors', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-supervisor-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await storage.initialize()
  const timedOut = record(root, 'pty_timeout')
  const stopped = record(root, 'pty_stop')
  const terminal = record(root, 'pty_terminal', 'exited')
  const output = record(root, 'pty_output', 'exited')
  const writable = record(root, 'pty_write')
  const parent = record(root, 'pty_parent')
  parent.parentSessionId = 'parent-cleanup'
  output.nextSequence = 8
  output.outputBytes = 8
  output.lineCount = 2
  await supervisor.initialize()
  const state = supervisor as unknown as {
    active: Map<
      string,
      { record: SessionRecord; process: { kill(): void; write(data: string): void } }
    >
    records: Map<string, SessionRecord>
    timeout(id: string): Promise<void>
  }
  for (const entry of [timedOut, stopped, terminal, output, writable, parent]) {
    state.records.set(entry.id, entry)
    await storage.writeSession(entry)
  }
  await storage.appendOutput('pty_output', [
    { startSequence: 0, endSequence: 8, timestamp: new Date().toISOString(), data: 'one\nhit\n' },
  ])
  state.active.set('pty_timeout', {
    record: timedOut,
    process: {
      kill: () => {
        throw new Error('permission denied')
      },
      write: () => {},
    },
  })
  await state.timeout('pty_timeout')
  expect(await supervisor.get('pty_timeout')).toMatchObject({
    status: 'timed_out',
    timedOut: true,
    terminationRequested: false,
    exitReason: { kind: 'timeout', message: 'Failed to stop PTY: permission denied' },
  })
  const recovered = new SessionSupervisor(storage)
  await recovered.initialize()
  expect((await recovered.get('pty_timeout'))?.status).toBe('timed_out')

  let kills = 0
  state.active.set('pty_stop', {
    record: stopped,
    process: {
      kill: () => {
        kills += 1
      },
      write: () => {},
    },
  })
  expect(await supervisor.stop('pty_stop')).toMatchObject({
    requested: true,
    terminationConfirmed: false,
  })
  expect(kills).toBe(1)
  expect(await recovered.stop('pty_timeout')).toMatchObject({
    requested: false,
    terminationConfirmed: false,
  })

  let written = ''
  state.active.set('pty_write', {
    record: writable,
    process: {
      kill: () => {},
      write: (data) => {
        written = data
      },
    },
  })
  expect(await supervisor.write('pty_write', 'A😀')).toEqual({
    acceptedBytes: 5,
    acceptedCharacters: 2,
  })
  expect(written).toBe('A😀')
  state.active.set('pty_write', {
    record: writable,
    process: {
      kill: () => {},
      write: () => {
        throw new Error('closed')
      },
    },
  })
  await expect(supervisor.write('pty_write', 'x')).rejects.toBeInstanceOf(ProcessError)

  state.active.set('pty_parent', {
    record: parent,
    process: {
      kill: () => {
        kills += 1
      },
      write: () => {},
    },
  })
  await supervisor.cleanupByParentSession('parent-cleanup')
  expect(kills).toBe(2)

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
  process.env.PTY_DAEMON_DIR = root
  const storage = new DaemonStorage(root)
  let pid: number | undefined
  try {
    await storage.initialize()
    await storage.writeDescriptor({
      pid: process.pid,
      endpoint: 'http://127.0.0.1:1',
      protocolVersion: DAEMON_PROTOCOL_VERSION,
      token: 'stale-token',
    })
    const client = new DaemonClient()
    const owner = ownerContext('test-session', root)
    const session = await client.spawn(
      {
        command: process.execPath,
        args: ['-e', "console.log('client daemon output')"],
        description: 'test client daemon',
        parentSessionId: 'test-session',
      },
      owner
    )
    let output = ''
    for (let attempt = 0; attempt < 40 && !output.includes('client daemon output'); attempt += 1) {
      await Bun.sleep(25)
      output = (await client.getRawBuffer(session.id, owner))?.raw ?? ''
    }
    expect(output).toContain('client daemon output')
    pid = (await storage.readDescriptor())?.pid
    expect(pid).toBeNumber()
    expect((await storage.readDescriptor())?.token).not.toBe('stale-token')
    const recreated = new DaemonClient()
    const read = await recreated.read(session.id, 0, undefined, undefined, owner)
    expect(read.sequences[0]).toBe(0)
    expect(read.lines.join('\n')).toContain('client daemon output')
  } finally {
    if (pid) process.kill(pid)
    await Bun.sleep(100)
    process.env.PTY_DAEMON_DIR = previousDirectory
  }
})

test('daemon client returns RPC sequence cursor and truncation metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-client-read-'))
  roots.push(root)
  const previousDirectory = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_client_read', 'exited')
  session.ownerCapabilityHash = new Bun.CryptoHasher('sha256')
    .update(`test-token\0parent\0${root}`)
    .digest('hex')
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
