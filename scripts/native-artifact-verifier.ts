import { createHash } from 'node:crypto'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import {
  NATIVE_WORKER_TARGETS,
  nativeWorkerArchiveName,
  nativeWorkerBinaryName,
  nativeWorkerPackageName,
  type NativeWorkerTarget,
} from '../src/shared/native-worker-targets.ts'

export type NativeArtifactManifest = {
  schemaVersion: 1
  version: string
  provenance: {
    repository: string
    releaseSha: string
    workflow: { runId: string; attempt: string; url: string }
  }
  artifacts: {
    target: NativeWorkerTarget
    file: string
    package: string
    os: string
    cpu: string
    binary: string
    sha256: string
  }[]
}

function tar(args: string[]): string {
  const result = Bun.spawnSync({ cmd: ['tar', ...args], stdout: 'pipe', stderr: 'pipe' })
  if (result.exitCode === 0) return Buffer.from(result.stdout).toString('utf8')
  throw new Error(`tar failed: ${Buffer.from(result.stderr).toString('utf8').trim()}`)
}

function sameList(actual: unknown, expected: string): boolean {
  return Array.isArray(actual) && actual.length === 1 && actual[0] === expected
}

export async function nativeArtifactChecksums(directory: string, version: string) {
  return Promise.all(
    (Object.keys(NATIVE_WORKER_TARGETS) as NativeWorkerTarget[]).map(async (target) => {
      const file = nativeWorkerArchiveName(target, version)
      return {
        target,
        file,
        sha256: createHash('sha256')
          .update(await readFile(join(directory, file)))
          .digest('hex'),
      }
    })
  )
}

export async function verifyNativeArtifacts(
  directory: string,
  releaseSha: string
): Promise<NativeArtifactManifest> {
  if (!releaseSha) throw new Error('A checked-out release SHA is required.')
  const root = JSON.parse(await readFile('package.json', 'utf8')) as { version?: unknown }
  if (typeof root.version !== 'string') throw new Error('Root package version is invalid.')
  const version = root.version
  const targets = Object.keys(NATIVE_WORKER_TARGETS) as NativeWorkerTarget[]
  const expectedFiles = new Set(targets.map((target) => nativeWorkerArchiveName(target, version)))
  const files = (await readdir(directory)).filter((file) => file.endsWith('.tgz')).sort()
  if (
    files.length !== expectedFiles.size ||
    files.some((file) => !expectedFiles.has(file)) ||
    [...expectedFiles].some((file) => !files.includes(file))
  )
    throw new Error(`Native archives must be exactly: ${[...expectedFiles].sort().join(', ')}.`)

  const checksums = new Map(
    (await nativeArtifactChecksums(directory, version)).map((item) => [item.file, item])
  )
  for (const target of targets) {
    const platform = NATIVE_WORKER_TARGETS[target]
    const file = nativeWorkerArchiveName(target, version)
    const archive = join(directory, file)
    const metadata = JSON.parse(tar(['-xOf', archive, 'package/package.json'])) as Record<
      string,
      unknown
    >
    if (
      metadata.name !== nativeWorkerPackageName(target) ||
      metadata.version !== root.version ||
      !sameList(metadata.os, platform.os) ||
      !sameList(metadata.cpu, platform.cpu)
    )
      throw new Error(`${file} package metadata does not match ${target}.`)
    const binary = `package/bin/${nativeWorkerBinaryName(platform.os)}`
    if (!tar(['-tf', archive]).split(/\r?\n/).includes(binary))
      throw new Error(`${file} does not contain ${binary}.`)
  }

  const manifest = JSON.parse(
    await readFile(join(directory, 'native-artifacts.json'), 'utf8')
  ) as NativeArtifactManifest
  if (
    manifest.schemaVersion !== 1 ||
    manifest.version !== version ||
    !manifest.provenance ||
    manifest.provenance.releaseSha !== releaseSha ||
    typeof manifest.provenance.repository !== 'string' ||
    !manifest.provenance.repository ||
    !manifest.provenance.workflow ||
    !Object.values(manifest.provenance.workflow).every(
      (value) => typeof value === 'string' && value
    )
  )
    throw new Error(
      'Native artifact manifest provenance is incomplete or does not match the release SHA.'
    )
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== targets.length)
    throw new Error('Native artifact manifest does not list every expected target.')

  const listed = new Set<NativeWorkerTarget>()
  for (const artifact of manifest.artifacts) {
    const platform = NATIVE_WORKER_TARGETS[artifact.target]
    const expected = checksums.get(artifact.file)
    if (
      !platform ||
      listed.has(artifact.target) ||
      artifact.file !== nativeWorkerArchiveName(artifact.target, version) ||
      artifact.package !== nativeWorkerPackageName(artifact.target) ||
      artifact.os !== platform.os ||
      artifact.cpu !== platform.cpu ||
      artifact.binary !== `bin/${nativeWorkerBinaryName(platform.os)}` ||
      artifact.sha256 !== expected?.sha256
    )
      throw new Error(`Native artifact manifest entry is invalid: ${artifact.file}.`)
    listed.add(artifact.target)
  }
  if (listed.size !== targets.length)
    throw new Error('Native artifact manifest has missing or extra targets.')
  return manifest
}
