import { mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  NATIVE_WORKER_TARGETS,
  nativeWorkerBinaryName,
  type NativeWorkerTarget,
} from '../src/shared/native-worker-targets.ts'

const target = process.argv[2] as NativeWorkerTarget | undefined
if (!target || NATIVE_WORKER_TARGETS[target]?.os !== 'darwin')
  throw new Error('Usage: bun native:sign:macos <darwin-arm64|darwin-x64>')
const identity = process.env.APPLE_SIGNING_IDENTITY
const profile = process.env.APPLE_NOTARY_KEYCHAIN_PROFILE
if (!identity || !profile)
  throw new Error(
    'macOS signing requires APPLE_SIGNING_IDENTITY and APPLE_NOTARY_KEYCHAIN_PROFILE.'
  )

const binary = join('target', 'release', nativeWorkerBinaryName('darwin'))
await stat(binary)

function run(command: string[], label: string): string {
  const result = Bun.spawnSync({ cmd: command, stdout: 'pipe', stderr: 'pipe' })
  if (result.exitCode === 0) return Buffer.from(result.stdout).toString('utf8')
  throw new Error(`${label} failed: ${Buffer.from(result.stderr).toString('utf8').trim()}`)
}

run(
  ['codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', identity, binary],
  'Sign worker'
)
run(['codesign', '--verify', '--strict', '--verbose=2', binary], 'Verify worker signature')
const temporary = await mkdtemp(join(tmpdir(), 'opencode-pty-notary-'))
try {
  const archive = join(temporary, 'opencode-pty-worker.zip')
  run(['ditto', '-c', '-k', '--keepParent', binary, archive], 'Create notarization archive')
  const result = JSON.parse(
    run(
      [
        'xcrun',
        'notarytool',
        'submit',
        archive,
        '--keychain-profile',
        profile,
        '--wait',
        '--output-format',
        'json',
      ],
      'Notarize worker'
    )
  ) as { status?: unknown }
  if (result.status !== 'Accepted')
    throw new Error(`Notarization was not accepted: ${JSON.stringify(result)}.`)
  run(
    ['codesign', '--verify', '--strict', '--verbose=2', binary],
    'Verify notarized worker signature'
  )
} finally {
  await rm(temporary, { recursive: true, force: true })
}
