import { DaemonServer } from './server.ts'
import { DaemonStorage } from './storage.ts'
import { SessionSupervisor } from './supervisor.ts'
import type { DaemonLaunchOptions } from './types.ts'

function launchOptions(): DaemonLaunchOptions {
  const encoded = process.argv[2]
  if (!encoded) return {}
  try {
    const decoded = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8')
    ) as DaemonLaunchOptions
    if (
      (decoded.dataDirectory !== undefined && typeof decoded.dataDirectory !== 'string') ||
      (decoded.token !== undefined && typeof decoded.token !== 'string') ||
      (decoded.startLockToken !== undefined && typeof decoded.startLockToken !== 'string')
    ) {
      throw new Error('invalid options')
    }
    return decoded
  } catch {
    throw new Error('Invalid PTY daemon launch options.')
  }
}

const options = launchOptions()
const storage = new DaemonStorage(options.dataDirectory)
const server = new DaemonServer(
  storage,
  new SessionSupervisor(storage),
  options.token,
  undefined,
  options.startLockToken
)

await server.start()

process.on('SIGINT', () => void server.stop().finally(() => process.exit(0)))
process.on('SIGTERM', () => void server.stop().finally(() => process.exit(0)))
