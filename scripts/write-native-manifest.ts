import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import {
  NATIVE_WORKER_TARGETS,
  nativeWorkerBinaryName,
  nativeWorkerPackageName,
  type NativeWorkerTarget,
} from '../src/shared/native-worker-targets.ts'
import { nativeArtifactChecksums, verifyNativeArtifacts } from './native-artifact-verifier.ts'

const directory = process.argv[2] ?? 'native-artifacts'
const releaseSha = process.argv[3]
if (!releaseSha) throw new Error('Usage: bun native:manifest <directory> <checked-out-release-sha>')
const repository = process.env.GITHUB_REPOSITORY
const runId = process.env.GITHUB_RUN_ID
const attempt = process.env.GITHUB_RUN_ATTEMPT
const server = process.env.GITHUB_SERVER_URL
if (!repository || !runId || !attempt || !server)
  throw new Error('GitHub release provenance is required to write a native artifact manifest.')

const version = (JSON.parse(await readFile('package.json', 'utf8')) as { version: string }).version
const manifest = {
  schemaVersion: 1,
  version,
  provenance: {
    repository,
    releaseSha,
    workflow: { runId, attempt, url: `${server}/${repository}/actions/runs/${runId}` },
  },
  artifacts: (await nativeArtifactChecksums(directory, version)).map(({ target, file, sha256 }) => {
    const platform = NATIVE_WORKER_TARGETS[target as NativeWorkerTarget]
    return {
      target,
      file,
      package: nativeWorkerPackageName(target as NativeWorkerTarget),
      os: platform.os,
      cpu: platform.cpu,
      binary: `bin/${nativeWorkerBinaryName(platform.os)}`,
      sha256,
    }
  }),
}
await writeFile(join(directory, 'native-artifacts.json'), `${JSON.stringify(manifest, null, 2)}\n`)
await verifyNativeArtifacts(directory, releaseSha)
