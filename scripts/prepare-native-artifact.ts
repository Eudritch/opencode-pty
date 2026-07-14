import { cp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const platforms = {
  'linux-x64-gnu': { os: 'linux', cpu: 'x64' },
  'win32-x64': { os: 'win32', cpu: 'x64' },
  'darwin-arm64': { os: 'darwin', cpu: 'arm64' },
} as const

const target = process.argv[2]
if (!target || !(target in platforms))
  throw new Error(`Usage: bun native:prepare <${Object.keys(platforms).join('|')}>`)

const platform = platforms[target as keyof typeof platforms]
const rootPackage = JSON.parse(await readFile('package.json', 'utf8')) as { version: string }
const output = join('native-artifacts', target)
const binary = join(
  'target',
  'release',
  `opencode-pty-worker${platform.os === 'win32' ? '.exe' : ''}`
)
await stat(binary)
await rm(output, { recursive: true, force: true })
await mkdir(join(output, 'bin'), { recursive: true })
await cp(binary, join(output, 'bin', `opencode-pty-worker${platform.os === 'win32' ? '.exe' : ''}`))
await writeFile(
  join(output, 'package.json'),
  `${JSON.stringify(
    {
      name: `@eudritch/opencode-pty-worker-${target}`,
      version: rootPackage.version,
      description: `Native worker for opencode-pty on ${target}`,
      license: 'MIT',
      os: [platform.os],
      cpu: [platform.cpu],
      files: ['bin'],
      publishConfig: { access: 'public' },
    },
    null,
    2
  )}\n`
)
