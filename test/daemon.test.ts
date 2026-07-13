import { afterEach, expect, test } from 'bun:test'
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DaemonServer } from '../src/daemon/server.ts'
import { DaemonStorage } from '../src/daemon/storage.ts'
import { ProcessError, SessionSupervisor } from '../src/daemon/supervisor.ts'
import type { SessionRecord } from '../src/daemon/types.ts'
import { DaemonClient } from '../src/plugin/pty/daemon-client.ts'
import { formatLine } from '../src/plugin/pty/formatters.ts'

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
    workdir: root,
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

test('daemon classifies PTY failures as process failures', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-process-error-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const supervisor = {
    initialize: async () => {},
    flush: async () => {},
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
        version: 1,
        operation: 'spawn',
        payload: { command: 'test', parentSessionId: 'parent' },
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
      protocolVersion: 1,
      token: 'stale-token',
    })
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
    expect((await storage.readDescriptor())?.token).not.toBe('stale-token')
    const recreated = new DaemonClient()
    const read = await recreated.read(session.id)
    expect(read.sequences[0]).toBe(0)
    expect(read.lines.join('\n')).toContain('client daemon output')
  } finally {
    if (pid) process.kill(pid)
    await Bun.sleep(100)
    process.env.PTY_DAEMON_DIR = previousDirectory
  }
})
