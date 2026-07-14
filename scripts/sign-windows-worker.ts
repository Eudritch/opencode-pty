import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import {
  NATIVE_WORKER_TARGETS,
  nativeWorkerBinaryName,
  type NativeWorkerTarget,
} from '../src/shared/native-worker-targets.ts'

const target = process.argv[2] as NativeWorkerTarget | undefined
if (!target || NATIVE_WORKER_TARGETS[target]?.os !== 'win32')
  throw new Error('Usage: bun native:sign:windows <win32-x64|win32-arm64>')
const certificate = process.env.WINDOWS_SIGNING_CERTIFICATE_PATH
const password = process.env.WINDOWS_SIGNING_CERTIFICATE_PASSWORD
const timestamp = process.env.WINDOWS_SIGNING_TIMESTAMP_URL
if (!certificate || !password || !timestamp)
  throw new Error(
    'Windows signing requires WINDOWS_SIGNING_CERTIFICATE_PATH, WINDOWS_SIGNING_CERTIFICATE_PASSWORD, and WINDOWS_SIGNING_TIMESTAMP_URL.'
  )

const binary = join('target', 'release', nativeWorkerBinaryName('win32'))
await stat(binary)

function signTool(args: string[]) {
  const result = Bun.spawnSync({
    cmd: ['signtool.exe', ...args],
    stdout: 'inherit',
    stderr: 'inherit',
  })
  if (result.exitCode !== 0)
    throw new Error(`signtool.exe ${args[0]} failed with exit code ${result.exitCode}.`)
}

signTool([
  'sign',
  '/fd',
  'SHA256',
  '/f',
  certificate,
  '/p',
  password,
  '/tr',
  timestamp,
  '/td',
  'SHA256',
  binary,
])
signTool(['verify', '/pa', '/all', '/v', binary])
