import { afterEach, expect, test } from 'bun:test'
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DaemonStorage } from '../src/daemon/storage.ts'
import { SessionSupervisor } from '../src/daemon/supervisor.ts'
import { sessionStateFromCompatibility } from '../src/daemon/lifecycle.ts'
import {
  OUTPUT_JOURNAL_VERSION,
  SESSION_RECORD_VERSION,
  type SessionRecord,
} from '../src/daemon/types.ts'

const roots: string[] = []
const OWNER_HASH = 'a'.repeat(64)

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

function record(
  root: string,
  id: string,
  status: SessionRecord['status'] = 'running'
): SessionRecord {
  const now = new Date().toISOString()
  const terminal = ['exited', 'timed_out', 'output_limited'].includes(status)
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
    lifecycle: 'persistent',
    environment: { kind: 'safe', keys: [], fingerprint: '', sensitive: false },
    status,
    pid: 1,
    createdAt: now,
    updatedAt: now,
    parentSessionId: 'parent',
    timedOut: status === 'timed_out',
    terminationRequested: false,
    terminationConfirmed: status !== 'running',
    ...(terminal
      ? {
          directChildExited: true,
          containment: {
            platform: 'not_applicable' as const,
            status: 'not_applicable' as const,
            rootPid: 1,
            rootStartIdentity: 'test-root',
            rootIdentityVerified: true,
            observedGroupPids: [],
            observedSessionPids: [],
            observedEscapedDescendantPids: [],
            verifiedAt: now,
          },
        }
      : { directChildExited: false }),
    nextSequence: 0,
    firstRetainedSequence: 0,
    outputBytes: 0,
    outputTruncated: false,
    lineCount: 0,
    outputHasPartialLine: false,
    outputJournalVersion: OUTPUT_JOURNAL_VERSION,
  }
  return { ...flat, state: sessionStateFromCompatibility(flat) }
}

function terminalProof(session: SessionRecord): void {
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

function legacyV0(session: SessionRecord): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(session).filter(
      ([key]) => key !== 'recordVersion' && key !== 'outputJournalVersion'
    )
  )
}

async function overwrite(storage: DaemonStorage, id: string, value: unknown): Promise<string> {
  const path = join(storage.rootDirectory, 'sessions', id, 'session.json')
  const bytes = JSON.stringify(value)
  await writeFile(path, bytes)
  return bytes
}

test('V2 writes one lifecycle state and decodes it back to the flat record', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v2-codec-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v2')

  await storage.writeSession(session)
  const path = join(root, 'sessions', session.id, 'session.json')
  const disk = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>

  expect(disk).toMatchObject({
    recordVersion: 2,
    state: {
      kind: 'running',
      child: { pid: 1 },
      termination: { requested: false, confirmed: false },
      streamDrain: 'unknown',
    },
  })
  for (const field of [
    'status',
    'pid',
    'worker',
    'workerPrestart',
    'pendingCleanup',
    'containment',
    'terminationConfirmed',
  ]) {
    expect(disk).not.toHaveProperty(field)
  }
  expect((await storage.loadSessions())[0]).toMatchObject({
    status: 'running',
    pid: 1,
    state: { kind: 'running' },
  })
})

test('V2 cleaning preserves an unreachable terminal payload', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v2-cleaning-terminal-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v2_cleaning_terminal', 'exited')
  session.directChildExited = false
  session.containment = undefined
  session.state = sessionStateFromCompatibility(session)
  session.pendingCleanup = true

  await storage.writeSession(session)

  const disk = JSON.parse(
    await readFile(join(root, 'sessions', session.id, 'session.json'), 'utf8')
  ) as { state: Record<string, unknown> }
  expect(disk.state).toMatchObject({
    kind: 'cleaning',
    target: 'unreachable',
    lastKnown: 'terminal',
    terminal: { outcome: 'exited' },
  })
  expect((await storage.loadSessions())[0]).toMatchObject({
    status: 'lost',
    pendingCleanup: true,
    state: {
      kind: 'cleaning',
      target: 'unreachable',
      lastKnown: 'terminal',
      terminal: { outcome: 'exited' },
    },
  })
})

test('V0 terminal records import output and become V2 terminal state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v0-codec-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v0', 'exited')
  terminalProof(session)
  session.nextSequence = 7
  session.outputBytes = 7
  session.lineCount = 1
  await storage.writeSession(session)
  await overwrite(storage, session.id, legacyV0(session))
  await writeFile(join(root, 'sessions', session.id, 'output.log'), 'legacy\n')

  expect((await storage.loadSessions())[0]).toMatchObject({
    status: 'exited',
    streamDrain: 'unknown',
  })
  const disk = JSON.parse(
    await readFile(join(root, 'sessions', session.id, 'session.json'), 'utf8')
  )
  expect(disk.state).toMatchObject({ kind: 'terminal', outcome: 'exited', streamDrain: 'unknown' })
  expect(await storage.readOutput(session.id)).toBe('legacy\n')
  expect(await Bun.file(join(root, 'sessions', session.id, 'output.log')).exists()).toBeFalse()
})

test('V1 terminal records become V2 terminal state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v1-codec-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v1', 'exited')
  terminalProof(session)
  await storage.writeSession(session)
  await overwrite(storage, session.id, { ...session, recordVersion: 1 })

  expect((await storage.loadSessions())[0]).toMatchObject({
    status: 'exited',
    streamDrain: 'unknown',
  })
  const disk = JSON.parse(
    await readFile(join(root, 'sessions', session.id, 'session.json'), 'utf8')
  )
  expect(disk.state).toMatchObject({ kind: 'terminal', outcome: 'exited', streamDrain: 'unknown' })
})

test('an unproven V1 terminal becomes a source-1 cleanup-only tombstone', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v1-unproven-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_v1_unproven', 'exited')
  session.directChildExited = false
  session.containment = undefined
  const legacy = { ...session, recordVersion: 1 }
  delete (legacy as Partial<SessionRecord>).state
  await storage.writeSession(session)
  await overwrite(storage, session.id, legacy)

  expect((await storage.loadSessions())[0]).toMatchObject({
    status: 'lost',
    lifecycle: 'conversation',
    pendingCleanup: true,
    legacyTombstone: { sourceRecordVersion: 1, lastKnown: 'terminal' },
  })
  const disk = JSON.parse(
    await readFile(join(root, 'sessions', session.id, 'session.json'), 'utf8')
  )
  expect(disk.state).toMatchObject({
    kind: 'cleaning',
    target: 'unreachable',
    lastKnown: 'terminal',
    legacy: { tombstone: { sourceRecordVersion: 1, lastKnown: 'terminal' } },
  })
})

test('restart removes a persisted no-child spawn failure', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-no-child-recovery-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_no_child', 'spawn_failed')
  session.exitReason = {
    kind: 'spawn_error',
    message: 'worker did not start',
    cleanup: {
      requested: false,
      terminationConfirmed: true,
      method: 'none',
      directChildStarted: false,
    },
  }
  await storage.writeSession(session)

  const supervisor = new SessionSupervisor(storage)
  await supervisor.initialize()

  expect(await supervisor.list()).toEqual([])
  expect(await Bun.file(join(root, 'sessions', session.id)).exists()).toBeFalse()
})

test('malformed V2 metadata is quarantined', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-v2-malformed-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const session = record(root, 'pty_bad_v2')
  const malformedState = record(root, 'pty_bad_v2_state')
  await storage.writeSession(session)
  await storage.writeSession(malformedState)
  const disk = JSON.parse(
    await readFile(join(root, 'sessions', session.id, 'session.json'), 'utf8')
  )
  disk.status = 'running'
  await overwrite(storage, session.id, disk)
  const stateDisk = JSON.parse(
    await readFile(join(root, 'sessions', malformedState.id, 'session.json'), 'utf8')
  ) as { state: Record<string, unknown> }
  stateDisk.state.kind = 'terminal'
  await overwrite(storage, malformedState.id, stateDisk)

  expect(await storage.loadSessions()).toEqual([])
  expect(await readdir(join(root, 'quarantine'))).toHaveLength(2)
})

test('explicit V0 and future versions remain byte-for-byte inert', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-inert-codec-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const explicitV0 = record(root, 'pty_explicit_v0')
  const future = record(root, 'pty_future')
  await storage.writeSession(explicitV0)
  await storage.writeSession(future)
  const v0Bytes = await overwrite(storage, explicitV0.id, { ...explicitV0, recordVersion: 0 })
  const futureBytes = await overwrite(storage, future.id, { ...future, recordVersion: 99 })

  expect(await storage.loadSessions()).toEqual([])
  expect(await readFile(join(root, 'sessions', explicitV0.id, 'session.json'), 'utf8')).toBe(
    v0Bytes
  )
  expect(await readFile(join(root, 'sessions', future.id, 'session.json'), 'utf8')).toBe(
    futureBytes
  )
  expect(await Bun.file(join(root, 'quarantine')).exists()).toBeFalse()
})
