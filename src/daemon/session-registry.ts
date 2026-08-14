import { DaemonError } from './errors.ts'
import { DEFAULT_SESSION_LIMITS, MAX_OUTPUT_BYTES, type SessionLimits } from './limits.ts'
import type { SessionRecord } from './types.ts'

export interface SessionReservation {
  id: string
  ownerKey: string
  state: 'reserved' | 'committed' | 'released'
}

export interface WaitReservation {
  id: number
  sessionId: string
  ownerKey: string
  released: boolean
}

export interface InputReservation {
  sessionId: string
  ownerKey: string
  bytes: number
  released: boolean
}

export interface SessionUsage {
  activeSessions: number
  records: number
  pendingWaits: number
  queuedInputBytes: number
  retainedOutputBytes: number
}

export function containmentDrained(
  record: Pick<SessionRecord, 'containment' | 'terminationConfirmed' | 'directChildExited'>
): boolean {
  return (
    record.containment?.status === 'posix_best_effort_empty' ||
    record.containment?.status === 'windows_job_empty' ||
    record.containment?.status === 'not_applicable'
  )
}

export function terminalDirectChild(
  record: Pick<SessionRecord, 'containment' | 'terminationConfirmed' | 'directChildExited'>
): boolean {
  return (
    record.terminationConfirmed &&
    record.directChildExited === true &&
    (containmentDrained(record) || process.platform === 'darwin')
  )
}

export class SessionRegistry {
  readonly records = new Map<string, SessionRecord>()
  private readonly ownerSlots = new Map<string, Set<string>>()
  private readonly slotOwnerBySessionId = new Map<string, string>()
  private readonly recordsByOwner = new Map<string, Set<string>>()
  private readonly recordOwnerBySessionId = new Map<string, string>()
  private readonly outputBySessionId = new Map<string, number>()
  private readonly outputByOwner = new Map<string, number>()
  private outputTotal = 0
  private readonly waitsBySession = new Map<string, Set<number>>()
  private readonly waitsByOwner = new Map<string, Set<number>>()
  private readonly waits = new Set<number>()
  private nextWaitId = 0
  private readonly inputBytesBySession = new Map<string, number>()
  private readonly inputBytesByOwner = new Map<string, number>()
  private inputBytes = 0

  constructor(private readonly limits: SessionLimits = DEFAULT_SESSION_LIMITS) {}

  owns(
    id: string,
    parentSessionId: string,
    projectDirectory: string,
    capabilityHash: string
  ): boolean {
    const record = this.records.get(id)
    return Boolean(
      record &&
        record.parentSessionId === parentSessionId &&
        record.ownerProjectDirectory === projectDirectory &&
        record.ownerCapabilityHash === capabilityHash
    )
  }

  rebuildSlots(): void {
    this.ownerSlots.clear()
    this.slotOwnerBySessionId.clear()
    this.recordsByOwner.clear()
    this.recordOwnerBySessionId.clear()
    this.outputBySessionId.clear()
    this.outputByOwner.clear()
    this.outputTotal = 0
    for (const record of this.records.values()) {
      const ownerKey = this.ownerKey(record)
      this.addRecord(record.id, ownerKey)
      if (this.occupiesSlot(record)) this.addActive(record.id, ownerKey)
      this.setOutput(record.id, ownerKey, this.outputReservation(record))
    }
  }

  reserve(record: SessionRecord, maxSessionsPerOwner: number): SessionReservation {
    const ownerKey = this.ownerKey(record)
    const active = this.ownerSlots.get(ownerKey)?.size ?? 0
    const records = this.recordsByOwner.get(ownerKey)?.size ?? 0
    const output = this.outputReservation(record)
    if (
      active >= maxSessionsPerOwner ||
      this.slotOwnerBySessionId.size >= this.limits.maxActiveSessions
    )
      throw new DaemonError('Session limit exceeded.', 'limit')
    if (
      records >= this.limits.maxRecordsPerOwner ||
      this.recordOwnerBySessionId.size >= this.limits.maxRecords
    )
      throw new DaemonError('Session record limit exceeded.', 'limit')
    if (
      (this.outputByOwner.get(ownerKey) ?? 0) + output >
        this.limits.maxRetainedOutputBytesPerOwner ||
      this.outputTotal + output > this.limits.maxRetainedOutputBytes
    ) {
      throw new DaemonError('Retained output limit exceeded.', 'limit')
    }
    this.addActive(record.id, ownerKey)
    this.addRecord(record.id, ownerKey)
    this.setOutput(record.id, ownerKey, output)
    return { id: record.id, ownerKey, state: 'reserved' }
  }

  commit(reservation: SessionReservation): void {
    if (reservation.state !== 'reserved') throw new Error('Session reservation is no longer valid.')
    reservation.state = 'committed'
  }

  releaseReservation(reservation: SessionReservation): void {
    if (reservation.state === 'released') return
    reservation.state = 'released'
    this.release(reservation.id)
  }

  releaseIfSettled(record: SessionRecord): void {
    if (!this.occupiesSlot(record)) this.releaseActive(record.id)
    this.updateOutput(record)
  }

  release(id: string): void {
    this.releaseActive(id)
    const ownerKey = this.recordOwnerBySessionId.get(id)
    if (!ownerKey) return
    const records = this.recordsByOwner.get(ownerKey)
    records?.delete(id)
    if (!records?.size) this.recordsByOwner.delete(ownerKey)
    this.recordOwnerBySessionId.delete(id)
    this.setOutput(id, ownerKey, 0)
  }

  reserveWait(record: SessionRecord): WaitReservation {
    const ownerKey = this.ownerKey(record)
    const sessionWaits = this.waitsBySession.get(record.id)?.size ?? 0
    const ownerWaits = this.waitsByOwner.get(ownerKey)?.size ?? 0
    if (
      sessionWaits >= this.limits.maxPendingWaitsPerSession ||
      ownerWaits >= this.limits.maxPendingWaitsPerOwner ||
      this.waits.size >= this.limits.maxPendingWaits
    ) {
      throw new DaemonError('Pending wait limit exceeded.', 'limit')
    }
    const id = this.nextWaitId++
    const bySession = this.waitsBySession.get(record.id) ?? new Set<number>()
    bySession.add(id)
    this.waitsBySession.set(record.id, bySession)
    const byOwner = this.waitsByOwner.get(ownerKey) ?? new Set<number>()
    byOwner.add(id)
    this.waitsByOwner.set(ownerKey, byOwner)
    this.waits.add(id)
    return { id, sessionId: record.id, ownerKey, released: false }
  }

  releaseWait(reservation: WaitReservation): void {
    if (reservation.released) return
    reservation.released = true
    this.waits.delete(reservation.id)
    const bySession = this.waitsBySession.get(reservation.sessionId)
    bySession?.delete(reservation.id)
    if (!bySession?.size) this.waitsBySession.delete(reservation.sessionId)
    const byOwner = this.waitsByOwner.get(reservation.ownerKey)
    byOwner?.delete(reservation.id)
    if (!byOwner?.size) this.waitsByOwner.delete(reservation.ownerKey)
  }

  reserveInput(record: SessionRecord, bytes: number): InputReservation {
    const ownerKey = this.ownerKey(record)
    const sessionBytes = this.inputBytesBySession.get(record.id) ?? 0
    const ownerBytes = this.inputBytesByOwner.get(ownerKey) ?? 0
    if (
      sessionBytes + bytes > this.limits.maxQueuedInputBytesPerSession ||
      ownerBytes + bytes > this.limits.maxQueuedInputBytesPerOwner ||
      this.inputBytes + bytes > this.limits.maxQueuedInputBytes
    ) {
      throw new DaemonError('Queued input limit exceeded.', 'limit')
    }
    this.inputBytesBySession.set(record.id, sessionBytes + bytes)
    this.inputBytesByOwner.set(ownerKey, ownerBytes + bytes)
    this.inputBytes += bytes
    return { sessionId: record.id, ownerKey, bytes, released: false }
  }

  releaseInput(reservation: InputReservation): void {
    if (reservation.released) return
    reservation.released = true
    this.subtract(this.inputBytesBySession, reservation.sessionId, reservation.bytes)
    this.subtract(this.inputBytesByOwner, reservation.ownerKey, reservation.bytes)
    this.inputBytes -= reservation.bytes
  }

  usageFor(
    parentSessionId: string,
    projectDirectory: string,
    capabilityHash: string
  ): SessionUsage {
    return this.usage(
      this.ownerKey({
        parentSessionId,
        ownerProjectDirectory: projectDirectory,
        ownerCapabilityHash: capabilityHash,
      })
    )
  }

  totalUsage(): SessionUsage {
    return {
      activeSessions: this.slotOwnerBySessionId.size,
      records: this.recordOwnerBySessionId.size,
      pendingWaits: this.waits.size,
      queuedInputBytes: this.inputBytes,
      retainedOutputBytes: this.outputTotal,
    }
  }

  configuredLimits(): SessionLimits {
    return this.limits
  }

  private usage(ownerKey: string): SessionUsage {
    return {
      activeSessions: this.ownerSlots.get(ownerKey)?.size ?? 0,
      records: this.recordsByOwner.get(ownerKey)?.size ?? 0,
      pendingWaits: this.waitsByOwner.get(ownerKey)?.size ?? 0,
      queuedInputBytes: this.inputBytesByOwner.get(ownerKey) ?? 0,
      retainedOutputBytes: this.outputByOwner.get(ownerKey) ?? 0,
    }
  }

  private addActive(id: string, ownerKey: string): void {
    const slots = this.ownerSlots.get(ownerKey) ?? new Set<string>()
    slots.add(id)
    this.ownerSlots.set(ownerKey, slots)
    this.slotOwnerBySessionId.set(id, ownerKey)
  }

  private releaseActive(id: string): void {
    const ownerKey = this.slotOwnerBySessionId.get(id)
    if (!ownerKey) return
    const slots = this.ownerSlots.get(ownerKey)
    slots?.delete(id)
    if (!slots?.size) this.ownerSlots.delete(ownerKey)
    this.slotOwnerBySessionId.delete(id)
  }

  private addRecord(id: string, ownerKey: string): void {
    const records = this.recordsByOwner.get(ownerKey) ?? new Set<string>()
    records.add(id)
    this.recordsByOwner.set(ownerKey, records)
    this.recordOwnerBySessionId.set(id, ownerKey)
  }

  private updateOutput(record: SessionRecord): void {
    const ownerKey = this.recordOwnerBySessionId.get(record.id)
    if (ownerKey) this.setOutput(record.id, ownerKey, this.outputReservation(record))
  }

  private outputReservation(record: SessionRecord): number {
    return this.occupiesSlot(record)
      ? Math.max(record.outputLimitBytes ?? MAX_OUTPUT_BYTES, record.outputBytes)
      : record.outputBytes
  }

  private setOutput(id: string, ownerKey: string, bytes: number): void {
    const previous = this.outputBySessionId.get(id) ?? 0
    const delta = bytes - previous
    if (bytes === 0) this.outputBySessionId.delete(id)
    else this.outputBySessionId.set(id, bytes)
    this.outputTotal += delta
    const next = (this.outputByOwner.get(ownerKey) ?? 0) + delta
    if (next === 0) this.outputByOwner.delete(ownerKey)
    else this.outputByOwner.set(ownerKey, next)
  }

  private subtract(values: Map<string, number>, key: string, amount: number): void {
    const next = (values.get(key) ?? 0) - amount
    if (next <= 0) values.delete(key)
    else values.set(key, next)
  }

  private ownerKey(
    record: Pick<SessionRecord, 'parentSessionId' | 'ownerProjectDirectory' | 'ownerCapabilityHash'>
  ): string {
    return `${record.parentSessionId}\0${record.ownerProjectDirectory}\0${record.ownerCapabilityHash}`
  }

  private occupiesSlot(record: SessionRecord): boolean {
    return !(
      terminalDirectChild(record) ||
      (record.exitReason?.kind === 'spawn_error' &&
        record.exitReason.cleanup?.directChildStarted === false &&
        record.exitReason.cleanup.terminationConfirmed)
    )
  }
}
