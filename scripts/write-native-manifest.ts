import { createHash } from 'node:crypto'
import { readFile, readdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const directory = process.argv[2] ?? 'native-artifacts'
const commit = process.argv[3]
if (!commit) throw new Error('Usage: bun native:manifest <directory> <checked-out-release-sha>')
const files = (await readdir(directory)).filter((file) => file.endsWith('.tgz')).sort()
if (!files.length) throw new Error(`No native worker tarballs found in ${directory}.`)

const version = (JSON.parse(await readFile('package.json', 'utf8')) as { version: string }).version
const manifest = {
  schemaVersion: 1,
  version,
  provenance: {
    repository: process.env.GITHUB_REPOSITORY ?? 'local',
    commit,
    runId: process.env.GITHUB_RUN_ID ?? 'local',
  },
  artifacts: await Promise.all(
    files.map(async (file) => ({
      file,
      sha256: createHash('sha256')
        .update(await readFile(join(directory, file)))
        .digest('hex'),
    }))
  ),
}
await writeFile(join(directory, 'native-artifacts.json'), `${JSON.stringify(manifest, null, 2)}\n`)
