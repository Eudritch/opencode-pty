import { afterEach, expect, test } from 'bun:test'
import { mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DaemonServer } from '../src/daemon/server.ts'
import { DaemonStorage } from '../src/daemon/storage.ts'
import { SessionSupervisor } from '../src/daemon/supervisor.ts'
import { DaemonClient } from '../src/plugin/pty/daemon-client.ts'

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

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
      body: JSON.stringify({ id: crypto.randomUUID(), version: 1, operation, payload }),
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
      body: JSON.stringify({ id: crypto.randomUUID(), version: 1, operation, payload }),
    })

  try {
    const invalid = await rpc('search', { id: 'pty_test', pattern: 'x', flags: 'g' })
    expect(((await invalid.json()) as { error: { code: string } }).error.code).toBe('validation')
  } finally {
    await server.stop()
  }
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
        result: { protocolVersion: 2, pid: process.pid },
      }),
  })
  const previousDirectory = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  const storage = new DaemonStorage(root)
  await storage.initialize()
  await storage.writeDescriptor({
    pid: process.pid,
    endpoint: server.url.origin,
    protocolVersion: 2,
    token: 'test-token',
  })

  try {
    await expect(new DaemonClient().list()).rejects.toThrow('incompatible')
    expect((await storage.readDescriptor())?.protocolVersion).toBe(2)
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
    protocolVersion: 1,
    token: 'x',
  })
  await storage.writeSession({
    id: 'pty_test',
    title: 'test',
    command: 'test',
    args: [],
    workdir: root,
    status: 'exited',
    pid: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    parentSessionId: 'test',
    timedOut: false,
    nextSequence: 0,
    firstRetainedSequence: 0,
    outputBytes: 0,
    outputTruncated: false,
    lineCount: 0,
    outputHasPartialLine: false,
  })
  await storage.appendOutput('pty_test', 'output')
  if (process.platform !== 'win32') {
    expect((await stat(root)).mode & 0o777).toBe(0o700)
    expect((await stat(join(root, 'daemon.json'))).mode & 0o777).toBe(0o600)
    expect((await stat(join(root, 'sessions', 'pty_test'))).mode & 0o777).toBe(0o700)
    expect((await stat(join(root, 'sessions', 'pty_test', 'session.json'))).mode & 0o777).toBe(
      0o600
    )
    expect((await stat(join(root, 'sessions', 'pty_test', 'output.log'))).mode & 0o777).toBe(0o600)
  }
})

test('lost sessions cannot be cleaned up', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-lost-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = new SessionSupervisor(storage)
  await storage.writeSession({
    id: 'pty_lost',
    title: 'lost',
    command: 'test',
    args: [],
    workdir: root,
    status: 'lost',
    pid: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    parentSessionId: 'test',
    timedOut: false,
    nextSequence: 0,
    firstRetainedSequence: 0,
    outputBytes: 0,
    outputTruncated: false,
    lineCount: 0,
    outputHasPartialLine: false,
  })
  await supervisor.initialize()

  expect(await supervisor.cleanup('pty_lost')).toBeFalse()
  expect(await storage.loadSessions()).toHaveLength(1)
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
      body: JSON.stringify({ id: 'list', version: 1, operation: 'list' }),
    })
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe('storage')
  } finally {
    await server.stop()
  }
})

test('plugin client starts its daemon from the configured data directory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-client-'))
  roots.push(root)
  const previousDirectory = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  const storage = new DaemonStorage(root)
  let pid: number | undefined
  try {
    const client = new DaemonClient()
    const session = await client.spawn({
      command: process.execPath,
      args: ['-e', "console.log('client daemon output')"],
      description: 'test client daemon',
      parentSessionId: 'test-session',
    })
    let output = ''
    for (let attempt = 0; attempt < 40 && !output.includes('client daemon output'); attempt += 1) {
      await Bun.sleep(25)
      output = (await client.getRawBuffer(session.id))?.raw ?? ''
    }
    expect(output).toContain('client daemon output')
    pid = (await storage.readDescriptor())?.pid
    expect(pid).toBeNumber()
  } finally {
    if (pid) process.kill(pid)
    await Bun.sleep(100)
    process.env.PTY_DAEMON_DIR = previousDirectory
  }
})
