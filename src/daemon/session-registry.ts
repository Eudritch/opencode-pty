import { DaemonError } from './errors.ts'
import type { SessionRecord } from './types.ts'

export interface SessionReservation {
  id: string
  ownerKey: string
  state: 'reserved' | 'committed' | 'released'
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
    for (const record of this.records.values()) {
      if (!this.occupiesSlot(record)) continue
      const ownerKey = this.ownerKey(record)
      const slots = this.ownerSlots.get(ownerKey) ?? new Set<string>()
      slots.add(record.id)
      this.ownerSlots.set(ownerKey, slots)
      this.slotOwnerBySessionId.set(record.id, ownerKey)
    }
  }

  reserve(record: SessionRecord, maxSessionsPerOwner: number): SessionReservation {
    const ownerKey = this.ownerKey(record)
    const slots = this.ownerSlots.get(ownerKey) ?? new Set<string>()
    if (slots.size >= maxSessionsPerOwner) throw new DaemonError('Session limit exceeded.', 'limit')
    slots.add(record.id)
    this.ownerSlots.set(ownerKey, slots)
    this.slotOwnerBySessionId.set(record.id, ownerKey)
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
    if (!this.occupiesSlot(record)) this.release(record.id)
  }

  release(id: string): void {
    const ownerKey = this.slotOwnerBySessionId.get(id)
    if (!ownerKey) return
    const slots = this.ownerSlots.get(ownerKey)
    slots?.delete(id)
    if (!slots?.size) this.ownerSlots.delete(ownerKey)
    this.slotOwnerBySessionId.delete(id)
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
