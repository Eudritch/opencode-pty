import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { verifyNativeArtifacts } from './native-artifact-verifier.ts'

const directory = process.argv[2] ?? 'native-artifacts'
const releaseSha = process.argv[3]
if (!releaseSha) throw new Error('Usage: bun native:sign <directory> <checked-out-release-sha>')
const manifest = join(directory, 'native-artifacts.json')
const signature = `${manifest}.sig`
const publicKey = process.env.NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY_FILE
  ? process.env.NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY_FILE
  : process.env.NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY && 'env://NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY'
if (
  process.env.NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY_FILE &&
  process.env.NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY
)
  throw new Error('Set only one native artifact public-key source.')
if (!process.env.NATIVE_ARTIFACT_SIGNING_KEY || !publicKey)
  throw new Error(
    'Native artifact signing requires NATIVE_ARTIFACT_SIGNING_KEY and NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY or NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY_FILE.'
  )
await stat(manifest)
await verifyNativeArtifacts(directory, releaseSha)

function cosign(args: string[]) {
  const result = Bun.spawnSync({ cmd: ['cosign', ...args], stdout: 'inherit', stderr: 'inherit' })
  if (result.exitCode !== 0)
    throw new Error(`cosign ${args[0]} failed with exit code ${result.exitCode}.`)
}

cosign([
  'sign-blob',
  '--yes',
  '--key',
  'env://NATIVE_ARTIFACT_SIGNING_KEY',
  '--output-signature',
  signature,
  manifest,
])
cosign(['verify-blob', '--key', publicKey, '--signature', signature, manifest])
