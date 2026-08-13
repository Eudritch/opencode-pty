import { afterEach, expect, test } from 'bun:test'
import { existsSync, realpathSync } from 'node:fs'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DaemonError } from '../src/daemon/errors.ts'
import { classifyRpcFailure, DaemonServer } from '../src/daemon/server.ts'
import { DaemonStorage } from '../src/daemon/storage.ts'
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
import { NATIVE_WORKER_PROTOCOL_VERSION } from '../src/shared/native-worker-targets.ts'

const roots: string[] = []
const OWNER_HASH = 'a'.repeat(64)
const RUNTIME_OWNER_HASH = 'b'.repeat(64)
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

function record(
  root: string,
  id: string,
  status: SessionRecord['status'] = 'running'
): SessionRecord {
  const now = new Date().toISOString()
  return {
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

test('safe environment includes Windows machine locations and strips native worker knobs', () => {
  const environment = runtimeEnvironment(
    { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'descriptor_write', CUSTOM: 'kept' },
    false,
    {
      ProgramData: 'C:\\ProgramData',
      ALLUSERSPROFILE: 'C:\\ProgramData',
      PATHEXT: '.COM;.EXE;.BAT;.CMD',
      PUBLIC: 'C:\\Users\\Public',
      Path: 'trusted-path',
      ARBITRARY: 'excluded',
      GH_TOKEN: 'secret',
      OPENCODE_PTY_NATIVE_WORKER_READY_DELAY_MS: '10',
    },
    true
  )

  expect(environment).toEqual({
    ProgramData: 'C:\\ProgramData',
    ALLUSERSPROFILE: 'C:\\ProgramData',
    PATHEXT: '.COM;.EXE;.BAT;.CMD',
    PUBLIC: 'C:\\Users\\Public',
    PATH: 'trusted-path',
    CUSTOM: 'kept',
  })
})

test('inherited environments also exclude native worker knobs', () => {
  const environment = runtimeEnvironment(
    { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'missing_ready' },
    true,
    { PATH: 'trusted-path', OPENCODE_PTY_NATIVE_WORKER_READY_TIMEOUT_MS: '1', KEPT: 'inherited' },
    false
  )

  expect(environment).toEqual({ PATH: 'trusted-path', KEPT: 'inherited' })
})

test('the effective output cap is 64 MiB', () => {
  expect(effectiveMaxOutputBytes(String(512 * 1024 * 1024))).toBe(64 * 1024 * 1024)
  expect(effectiveMaxOutputBytes(String(64 * 1024 * 1024 + 1))).toBe(64 * 1024 * 1024)
  expect(effectiveMaxOutputBytes('1000')).toBe(1000)
})

test('DaemonError codes win over legacy substring classification', () => {
  expect(classifyRpcFailure(new DaemonError('hit the rate limit of foo', 'not_found'))).toBe(
    'not_found'
  )
  expect(classifyRpcFailure(new DaemonError('Session limit exceeded.', 'limit'))).toBe('limit')
  expect(classifyRpcFailure(new DaemonError("PTY session 'x' is closed.", 'session_closed'))).toBe(
    'session_closed'
  )
  expect(classifyRpcFailure(new DaemonError('Owner is not authorized.', 'authorization'))).toBe(
    'authorization'
  )
  // Legacy fallback order is preserved for errors not yet raised as DaemonError.
  expect(classifyRpcFailure(new Error('hit the rate limit of foo'))).toBe('limit')
  expect(classifyRpcFailure(new ProcessError('spawn failed'))).toBe('process')
  expect(classifyRpcFailure(new Error('nothing recognizable'))).toBe('internal')
})

test('server RPC reports the limit code for deliberate session limits', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-runtime-limit-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const server = new DaemonServer(storage, new SessionSupervisor(storage), 'test-token', 0)
  const descriptor = await server.start()
  try {
    const response = await fetch(`${descriptor.endpoint}/rpc`, {
      method: 'POST',
      headers: { authorization: 'Bearer test-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        version: DAEMON_PROTOCOL_VERSION,
        operation: 'spawn',
        owner: await owner(storage, 'parent', root),
        payload: { command: 'test', parentSessionId: 'parent' },
      }),
    })
    const body = (await response.json()) as { error: { code: string; message: string } }
    expect(body.error).toMatchObject({ code: 'limit', message: 'Session limit exceeded.' })
  } finally {
    await server.stop()
  }
}, 20_000)

test('sessions without an explicit workdir run in the owner project directory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-runtime-workdir-'))
  roots.push(root)
  const ownerProjectDirectory = join(root, 'owner-project')
  await mkdir(ownerProjectDirectory, { recursive: true })
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  await supervisor.initialize()
  const result = await supervisor.exec({
    command: process.execPath,
    args: ['-e', 'console.log(process.cwd())'],
    parentSessionId: 'parent',
    ownerProjectDirectory,
    ownerCapabilityHash: RUNTIME_OWNER_HASH,
    timeoutSeconds: 30,
  })
  const info = await supervisor.get(result.session.id)
  expect(info?.workdir).toBe(realpathSync(ownerProjectDirectory))
  expect(info?.workdir).not.toBe(realpathSync(process.cwd()))
  expect(result.stdout.trim()).toBe(realpathSync(ownerProjectDirectory))
}, 20_000)

test('worker fault injection is daemon-controlled, never caller-controlled', async () => {
  if (!process.env.PTY_NATIVE_WORKER_PATH) return
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-runtime-fault-'))
  roots.push(root)
  const supervisor = new SessionSupervisor(new DaemonStorage(root))
  await supervisor.initialize()
  const printFault =
    process.platform === 'win32'
      ? { command: 'cmd.exe', args: ['/d', '/c', 'echo %OPENCODE_PTY_NATIVE_WORKER_FAULT%'] }
      : { command: '/bin/sh', args: ['-c', 'echo "fault=$OPENCODE_PTY_NATIVE_WORKER_FAULT"'] }

  // A caller-supplied session fault knob must neither trigger the fault path nor reach the child.
  const benign = await supervisor.nativeExec({
    ...printFault,
    env: { OPENCODE_PTY_NATIVE_WORKER_FAULT: 'descriptor_write' },
    parentSessionId: 'parent',
    workdir: root,
    ownerProjectDirectory: root,
    ownerCapabilityHash: RUNTIME_OWNER_HASH,
    timeoutSeconds: 30,
  })
  expect(benign.exitCode).toBe(0)
  expect(benign.stdout).not.toContain('descriptor_write')

  // The daemon's own environment is the only fault source.
  const previousFault = process.env.OPENCODE_PTY_NATIVE_WORKER_FAULT
  process.env.OPENCODE_PTY_NATIVE_WORKER_FAULT = 'descriptor_write'
  try {
    await expect(
      supervisor.nativeExec({
        ...printFault,
        parentSessionId: 'parent',
        workdir: root,
        ownerProjectDirectory: root,
        ownerCapabilityHash: RUNTIME_OWNER_HASH,
        timeoutSeconds: 30,
      })
    ).rejects.toThrow('native_worker_unavailable')
  } finally {
    if (previousFault === undefined) delete process.env.OPENCODE_PTY_NATIVE_WORKER_FAULT
    else process.env.OPENCODE_PTY_NATIVE_WORKER_FAULT = previousFault
  }
}, 30_000)

test('cleanup retains a lost native worker without terminal evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-runtime-orphan-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const operations: Array<{ operation: string; authorization: string | null }> = []
  const workerEndpoint = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch: async (request) => {
      operations.push({
        operation: ((await request.json()) as { operation: string }).operation,
        authorization: request.headers.get('authorization'),
      })
      return Response.json({ ok: true, result: { status: 'exited' } })
    },
  })
  try {
    const token = 'orphan-worker-control-token'
    const session = record(root, 'pty_orphan', 'lost')
    session.worker = {
      pid: process.pid,
      startIdentity: 'start',
      processIdentity: 'identity',
      endpoint: workerEndpoint.url.origin,
      tokenFingerprint: 'fingerprint',
      protocolVersion: NATIVE_WORKER_PROTOCOL_VERSION,
    }
    await storage.writeSession(session)
    await writeFile(
      join(root, 'sessions', 'pty_orphan', 'worker.json'),
      JSON.stringify({
        pid: process.pid,
        startIdentity: 'start',
        processIdentity: 'identity',
        endpoint: workerEndpoint.url.origin,
        token,
        protocolVersion: NATIVE_WORKER_PROTOCOL_VERSION,
      })
    )
    const supervisor = new SessionSupervisor(storage)
    await supervisor.initialize(false)

    expect(await supervisor.cleanup('pty_orphan')).toBeFalse()
    expect(operations).toEqual([{ operation: 'shutdown', authorization: `Bearer ${token}` }])
    expect(existsSync(join(root, 'sessions', 'pty_orphan'))).toBeTrue()
  } finally {
    workerEndpoint.stop(true)
  }
}, 20_000)
