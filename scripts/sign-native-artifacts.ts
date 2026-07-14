import { stat } from 'node:fs/promises'
import { join } from 'node:path'

const directory = process.argv[2] ?? 'native-artifacts'
const manifest = join(directory, 'native-artifacts.json')
const signature = `${manifest}.sig`
if (!process.env.NATIVE_ARTIFACT_SIGNING_KEY || !process.env.NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY)
  throw new Error(
    'Native artifact signing is not configured: set NATIVE_ARTIFACT_SIGNING_KEY and NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY.'
  )
await stat(manifest)

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
cosign([
  'verify-blob',
  '--key',
  'env://NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY',
  '--signature',
  signature,
  manifest,
])
