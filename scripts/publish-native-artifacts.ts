import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

type Manifest = {
  version: string
  artifacts: { file: string; sha256: string }[]
}

type PackageInfo = {
  name: string
  version: string
}

const directory = process.argv[2] ?? 'native-artifacts'
const manifestPath = join(directory, 'native-artifacts.json')
const signaturePath = `${manifestPath}.sig`
const releaseSha = process.argv[3]
if (!process.env.NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY)
  throw new Error(
    'Native artifact verification is not configured: set NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY.'
  )

function run(command: string[], label: string): string {
  const result = Bun.spawnSync({ cmd: command, stdout: 'pipe', stderr: 'pipe' })
  const stdout = Buffer.from(result.stdout).toString('utf8')
  if (result.exitCode === 0) return stdout
  throw new Error(`${label} failed: ${Buffer.from(result.stderr).toString('utf8').trim()}`)
}

function sha512Integrity(data: Uint8Array): string {
  return `sha512-${createHash('sha512').update(data).digest('base64')}`
}

function packageInfo(artifact: string): PackageInfo {
  const value = JSON.parse(
    run(['tar', '-xOf', artifact, 'package/package.json'], 'Read package metadata')
  )
  if (!value || typeof value.name !== 'string' || typeof value.version !== 'string')
    throw new Error(`Invalid package metadata in ${artifact}.`)
  return value
}

function registryPackage(info: PackageInfo): { version?: string; integrity?: string } | undefined {
  const result = Bun.spawnSync({
    cmd: ['npm', 'view', `${info.name}@${info.version}`, '--json'],
    stdout: 'pipe',
    stderr: 'pipe',
  })
  if (result.exitCode !== 0) {
    const stderr = Buffer.from(result.stderr).toString('utf8')
    if (/E404|404 Not Found/.test(stderr)) return undefined
    throw new Error(`Query ${info.name}@${info.version} failed: ${stderr.trim()}`)
  }
  const value = JSON.parse(Buffer.from(result.stdout).toString('utf8')) as {
    version?: unknown
    dist?: { integrity?: unknown }
  }
  return {
    version: typeof value.version === 'string' ? value.version : undefined,
    integrity: typeof value.dist?.integrity === 'string' ? value.dist.integrity : undefined,
  }
}

function verifyPublished(info: PackageInfo, integrity: string) {
  const published = registryPackage(info)
  if (!published) return false
  if (published.version !== info.version || published.integrity !== integrity)
    throw new Error(
      `${info.name}@${info.version} is already published with a different version or tarball integrity.`
    )
  return true
}

await stat(manifestPath)
await stat(signaturePath)
run(
  [
    'cosign',
    'verify-blob',
    '--key',
    'env://NATIVE_ARTIFACT_SIGNING_PUBLIC_KEY',
    '--signature',
    signaturePath,
    manifestPath,
  ],
  'Verify native artifact manifest signature'
)

const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as Manifest & {
  provenance?: { commit?: unknown }
}
if (!releaseSha || manifest.provenance?.commit !== releaseSha)
  throw new Error('Signed native artifact manifest is not tied to the checked-out release commit.')
const expected = new Map(manifest.artifacts.map(({ file, sha256 }) => [file, sha256]))
const files = (await readdir(directory)).filter((file) => file.endsWith('.tgz')).sort()
if (!files.length || files.length !== expected.size || files.some((file) => !expected.has(file)))
  throw new Error('Native artifact files do not match the signed manifest.')

for (const file of files) {
  const artifact = join(directory, file)
  const contents = await readFile(artifact)
  if (createHash('sha256').update(contents).digest('hex') !== expected.get(file))
    throw new Error(`${file} does not match the signed manifest checksum.`)
  const info = packageInfo(artifact)
  if (info.version !== manifest.version)
    throw new Error(`${file} version does not match the signed manifest.`)
  const integrity = sha512Integrity(contents)
  if (verifyPublished(info, integrity)) continue
  run(['npm', 'publish', artifact, '--access', 'public', '--provenance'], `Publish ${info.name}`)
  if (!verifyPublished(info, integrity))
    throw new Error(`Published ${info.name}@${info.version} is unavailable.`)
}

const temporary = await mkdtemp(join(tmpdir(), 'opencode-pty-publish-'))
try {
  const packed = JSON.parse(
    run(['npm', 'pack', '--json', '--pack-destination', temporary], 'Pack root package')
  ) as { filename?: unknown }[]
  const filename = packed[0]?.filename
  if (typeof filename !== 'string')
    throw new Error('npm pack did not return a root package filename.')
  const artifact = join(temporary, filename)
  const info = packageInfo(artifact)
  const integrity = sha512Integrity(await readFile(artifact))
  if (!verifyPublished(info, integrity)) {
    run(['npm', 'publish', artifact, '--access', 'public', '--provenance'], 'Publish root package')
    if (!verifyPublished(info, integrity))
      throw new Error(`Published ${info.name}@${info.version} is unavailable.`)
  }
} finally {
  await rm(temporary, { recursive: true, force: true })
}
