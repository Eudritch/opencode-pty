import { existsSync } from 'node:fs'
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

type Verification = {
  revision: string
  verifiedAt: string
  workerPath: string
}

type Checkpoint = Verification & {
  schemaVersion: 1
  entry: string
}

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const checkpoints = join(root, '.opencode-pty-checkpoints')
const activePath = join(root, '.opencode', 'opencode-pty-checkpoint.json')
const runtimePath = join(root, '.opencode', 'opencode-pty-checkpoint-runtime.json')
const binary = `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`

function usage(): never {
  throw new Error(
    'Usage: bun run checkpoint <stage|verify|activate|status> [git-ref]. Activate requires a verified checkpoint.'
  )
}

async function capture(command: string, args: string[], cwd = root): Promise<string> {
  const child = Bun.spawn([command, ...args], { cwd, stdout: 'pipe', stderr: 'pipe' })
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  if (code !== 0) throw new Error(`${command} ${args.join(' ')} failed: ${stderr.trim()}`)
  return stdout.trim()
}

async function run(command: string, args: string[], cwd: string): Promise<void> {
  console.log(`> ${command} ${args.join(' ')}`)
  const child = Bun.spawn([command, ...args], { cwd, stdout: 'inherit', stderr: 'inherit' })
  if ((await child.exited) !== 0) throw new Error(`${command} ${args.join(' ')} failed.`)
}

async function writeAtomic(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`)
  try {
    await rename(temporary, path)
  } catch (error) {
    await rm(temporary, { force: true })
    throw error
  }
}

async function stage(ref: string): Promise<{ revision: string; directory: string }> {
  const revision = await capture('git', ['rev-parse', '--verify', `${ref}^{commit}`])
  const directory = join(checkpoints, revision)
  if (!existsSync(directory)) {
    await mkdir(checkpoints, { recursive: true })
    await run('git', ['worktree', 'add', '--detach', directory, revision], root)
  }
  const actual = await capture('git', ['-C', directory, 'rev-parse', 'HEAD'])
  if (actual !== revision)
    throw new Error(`Checkpoint directory '${directory}' has the wrong revision.`)
  return { revision, directory }
}

async function readVerification(directory: string): Promise<Verification> {
  const path = join(directory, '.opencode-pty-checkpoint-verified.json')
  const parsed: unknown = JSON.parse(await readFile(path, 'utf8'))
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    typeof (parsed as Partial<Verification>).revision !== 'string' ||
    typeof (parsed as Partial<Verification>).verifiedAt !== 'string' ||
    typeof (parsed as Partial<Verification>).workerPath !== 'string'
  ) {
    throw new Error('Checkpoint verification record is invalid.')
  }
  return parsed as Verification
}

async function verify(ref: string): Promise<void> {
  const checkpoint = await stage(ref)
  const cargo = Bun.which('cargo') ?? 'cargo'
  await run(cargo, ['build', '--locked', '--workspace'], checkpoint.directory)
  await run(cargo, ['fmt', '--check'], checkpoint.directory)
  await run(cargo, ['test', '--locked', '--workspace'], checkpoint.directory)
  await run(
    cargo,
    ['clippy', '--locked', '--workspace', '--', '-D', 'warnings'],
    checkpoint.directory
  )
  await run(process.execPath, ['run', 'typecheck'], checkpoint.directory)
  await run(process.execPath, ['test'], checkpoint.directory)
  await run(process.execPath, ['package:smoke'], checkpoint.directory)
  const workerPath = join(checkpoint.directory, 'target', 'debug', binary)
  if (!existsSync(workerPath))
    throw new Error('Checkpoint debug worker is missing after verification.')
  await writeAtomic(join(checkpoint.directory, '.opencode-pty-checkpoint-verified.json'), {
    revision: checkpoint.revision,
    verifiedAt: new Date().toISOString(),
    workerPath: relative(root, workerPath),
  } satisfies Verification)
  console.log(`Verified ${checkpoint.revision}`)
}

async function activate(ref: string): Promise<void> {
  const checkpoint = await stage(ref)
  const verified = await readVerification(checkpoint.directory)
  if (verified.revision !== checkpoint.revision)
    throw new Error('Checkpoint verification revision mismatch.')
  const workerPath = resolve(root, verified.workerPath)
  if (!existsSync(workerPath))
    throw new Error('Checkpoint worker is missing. Run checkpoint verify.')
  await writeAtomic(activePath, {
    schemaVersion: 1,
    revision: checkpoint.revision,
    entry: relative(root, join(checkpoint.directory, 'index.ts')),
    workerPath: verified.workerPath,
    verifiedAt: verified.verifiedAt,
  } satisfies Checkpoint)
  console.log(`Activated ${checkpoint.revision}`)
}

async function status(): Promise<void> {
  if (!existsSync(activePath)) {
    console.log('No checkpoint is active.')
    return
  }
  const active = JSON.parse(await readFile(activePath, 'utf8')) as Checkpoint
  const runtime = existsSync(runtimePath)
    ? (JSON.parse(await readFile(runtimePath, 'utf8')) as Record<string, unknown>)
    : null
  console.log(JSON.stringify({ active, runtime }, null, 2))
}

const [command, ref = 'HEAD'] = process.argv.slice(2)
if (!command) usage()
if (command === 'stage') console.log(JSON.stringify(await stage(ref), null, 2))
else if (command === 'verify') await verify(ref)
else if (command === 'activate') await activate(ref)
else if (command === 'status') await status()
else usage()
