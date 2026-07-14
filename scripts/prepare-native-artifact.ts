import { cp, mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import {
  NATIVE_WORKER_TARGETS,
  nativeWorkerBinaryName,
  nativeWorkerPackageName,
  type NativeWorkerTarget,
} from '../src/shared/native-worker-targets.ts'

const target = process.argv[2] as NativeWorkerTarget | undefined
if (!target || !(target in NATIVE_WORKER_TARGETS))
  throw new Error(`Usage: bun native:prepare <${Object.keys(NATIVE_WORKER_TARGETS).join('|')}>`)

const platform = NATIVE_WORKER_TARGETS[target]
const rootPackage = JSON.parse(await readFile('package.json', 'utf8')) as { version: string }
const output = join('native-artifacts', target)
const binary = join('target', 'release', nativeWorkerBinaryName(platform.os))
await stat(binary)
await mkdir(join(output, 'bin'), { recursive: true })
await cp(binary, join(output, 'bin', nativeWorkerBinaryName(platform.os)))
await writeFile(
  join(output, 'package.json'),
  `${JSON.stringify(
    {
      name: nativeWorkerPackageName(target),
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
