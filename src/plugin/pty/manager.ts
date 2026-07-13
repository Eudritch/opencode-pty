import { DaemonClient } from './daemon-client.ts'

// Kept as the tool adapter boundary while the implementation lives out of process.
export const manager = new DaemonClient()
