import type { SessionRegistry } from './session-registry.ts'
import type { WorkerClient } from './worker-client.ts'

export class SessionRouter {
  readonly workers = new Map<string, WorkerClient>()
  private readonly versions = new Map<string, number>()
  private readonly persists = new Map<string, Promise<void>>()
  private readonly mutations = new Map<string, Promise<void>>()

  constructor(private readonly registry: SessionRegistry) {}

  owns(
    id: string,
    parentSessionId: string,
    projectDirectory: string,
    capabilityHash: string
  ): boolean {
    return this.registry.owns(id, parentSessionId, projectDirectory, capabilityHash)
  }

  version(id: string): number {
    return this.versions.get(id) ?? 0
  }

  bumpVersion(id: string): number {
    const version = this.version(id) + 1
    this.versions.set(id, version)
    return version
  }

  persist<T>(id: string, task: () => Promise<T>): Promise<T> {
    const previous = this.persists.get(id) ?? Promise.resolve()
    const result = previous.then(task, task)
    const settled = result.then(
      () => undefined,
      () => undefined
    )
    this.persists.set(id, settled)
    void settled.then(() => {
      if (this.persists.get(id) === settled) this.persists.delete(id)
    })
    return result
  }

  mutate<T>(id: string, task: () => Promise<T>): Promise<T> {
    const previous = this.mutations.get(id) ?? Promise.resolve()
    const result = previous.then(task, task)
    const settled = result.then(
      () => undefined,
      () => undefined
    )
    this.mutations.set(id, settled)
    void settled.then(() => {
      if (this.mutations.get(id) === settled) this.mutations.delete(id)
    })
    return result
  }
}
