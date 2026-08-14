import { afterEach, expect, test } from 'bun:test'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { sessionStateFromCompatibility } from '../src/daemon/lifecycle.ts'
import { DEFAULT_SESSION_LIMITS, type SessionLimits } from '../src/daemon/limits.ts'
import { SessionRegistry } from '../src/daemon/session-registry.ts'
import { DaemonStorage } from '../src/daemon/storage.ts'
import { SessionSupervisor } from '../src/daemon/supervisor.ts'
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

function limits(overrides: Partial<SessionLimits>): SessionLimits {
  return { ...DEFAULT_SESSION_LIMITS, ...overrides }
}

function record(root: string, id: string): SessionRecord {
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
    status: 'running',
    pid: 1,
    createdAt: now,
    updatedAt: now,
    parentSessionId: 'parent',
    timedOut: false,
    terminationRequested: false,
    terminationConfirmed: false,
    nextSequence: 0,
    firstRetainedSequence: 0,
    outputBytes: 0,
    outputLimitBytes: 6,
    outputTruncated: false,
    lineCount: 0,
    outputHasPartialLine: false,
    outputJournalVersion: OUTPUT_JOURNAL_VERSION,
  }
  return { ...flat, state: sessionStateFromCompatibility(flat) }
}

test('registry atomically budgets active sessions, records, and retained output', () => {
  const root = tmpdir()
  const active = new SessionRegistry(limits({ maxActiveSessions: 1 }))
  const first = record(root, 'first')
  active.commit(active.reserve(first, 32))
  expect(() => active.reserve(record(root, 'second'), 32)).toThrow('Session limit exceeded.')

  const records = new SessionRegistry(limits({ maxRecordsPerOwner: 1, maxRecords: 1 }))
  records.commit(records.reserve(first, 32))
  records.releaseIfSettled(first)
  expect(() => records.reserve(record(root, 'second'), 32)).toThrow(
    'Session record limit exceeded.'
  )

  const output = new SessionRegistry(
    limits({ maxActiveSessions: 2, maxRetainedOutputBytesPerOwner: 10, maxRetainedOutputBytes: 10 })
  )
  output.commit(output.reserve(first, 32))
  expect(() => output.reserve(record(root, 'second'), 32)).toThrow(
    'Retained output limit exceeded.'
  )

  first.directChildExited = true
  first.terminationConfirmed = true
  first.containment = {
    platform: 'not_applicable',
    status: 'not_applicable',
    rootPid: 1,
    rootStartIdentity: 'test',
    rootIdentityVerified: true,
    observedGroupPids: [],
    observedSessionPids: [],
    observedEscapedDescendantPids: [],
    verifiedAt: first.updatedAt,
  }
  first.outputBytes = 3
  output.releaseIfSettled(first)
  expect(output.totalUsage()).toMatchObject({
    activeSessions: 0,
    records: 1,
    retainedOutputBytes: 3,
  })
})

test('registry releases wait and queued-input permits', () => {
  const root = tmpdir()
  const registry = new SessionRegistry(
    limits({
      maxPendingWaitsPerSession: 1,
      maxPendingWaitsPerOwner: 1,
      maxPendingWaits: 1,
      maxQueuedInputBytesPerSession: 2,
      maxQueuedInputBytesPerOwner: 2,
      maxQueuedInputBytes: 2,
    })
  )
  const session = record(root, 'session')
  const wait = registry.reserveWait(session)
  expect(() => registry.reserveWait(session)).toThrow('Pending wait limit exceeded.')
  registry.releaseWait(wait)
  expect(registry.reserveWait(session)).toMatchObject({ sessionId: session.id })

  const input = registry.reserveInput(session, 2)
  expect(() => registry.reserveInput(session, 1)).toThrow('Queued input limit exceeded.')
  registry.releaseInput(input)
  expect(registry.reserveInput(session, 2)).toMatchObject({ bytes: 2 })
})

test('recovery rebuilds persisted retained-output reservations', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-budget-recovery-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  await storage.initialize()
  const persisted = record(root, 'pty_persisted_budget')
  persisted.outputLimitBytes = 10
  await storage.writeSession(persisted)
  const supervisor = new SessionSupervisor(
    storage,
    10,
    undefined,
    undefined,
    limits({ maxActiveSessions: 2, maxRetainedOutputBytesPerOwner: 10, maxRetainedOutputBytes: 10 })
  )
  await supervisor.initialize(false)
  await expect(
    supervisor.spawn({
      command: 'must-not-start',
      parentSessionId: 'parent',
      ownerProjectDirectory: root,
      ownerCapabilityHash: OWNER_HASH,
      workdir: root,
    })
  ).rejects.toMatchObject({ code: 'limit', message: 'Retained output limit exceeded.' })
})

test('supervisor rejects queued input and send-wait capacity before worker input', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-budget-input-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  await storage.initialize()
  const supervisor = new SessionSupervisor(
    storage,
    undefined,
    undefined,
    undefined,
    limits({
      maxPendingWaitsPerSession: 0,
      maxPendingWaitsPerOwner: 0,
      maxPendingWaits: 0,
      maxQueuedInputBytesPerSession: 0,
      maxQueuedInputBytesPerOwner: 0,
      maxQueuedInputBytes: 0,
    })
  )
  const session = record(root, 'pty_budget')
  const internals = supervisor as unknown as {
    records: Map<string, SessionRecord>
    nativeWorkers: Map<string, { write: (data: string) => Promise<{ arrivalSequence: number }> }>
  }
  internals.records.set(session.id, session)
  let writes = 0
  internals.nativeWorkers.set(session.id, {
    write: async () => {
      writes += 1
      return { arrivalSequence: 0 }
    },
  })

  await expect(supervisor.write(session.id, 'x')).rejects.toMatchObject({ code: 'limit' })
  await expect(supervisor.sendWait(session.id, 'x', { kind: 'exit' }, 1)).rejects.toMatchObject({
    code: 'limit',
  })
  expect(writes).toBe(0)
})
