import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = process.cwd()
const packageDirectory = await mkdtemp(join(tmpdir(), 'opencode-pty-package-'))
const stateDirectory = await mkdtemp(join(tmpdir(), 'opencode-pty-state-'))
const workerPath = join(
  root,
  'target',
  'debug',
  `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
)
let daemon: ReturnType<typeof Bun.spawn> | undefined

async function removeTemporary(path: string) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await rm(path, { recursive: true, force: true })
      return
    } catch {
      await Bun.sleep(100)
    }
  }
  // ponytail: Windows can retain npm package handles after child exit; the OS temp directory cleans this up.
}

async function startDaemon(installed: string) {
  const child = Bun.spawn({
    cmd: ['bun', join(installed, 'dist', 'src', 'daemon', 'main.js')],
    env: {
      ...process.env,
      PTY_DAEMON_DIR: stateDirectory,
      PTY_NATIVE_WORKER_ENABLED: '1',
      PTY_NATIVE_WORKER_PATH: workerPath,
    },
    stdout: 'ignore',
    stderr: 'pipe',
  })
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      return {
        child,
        descriptor: JSON.parse(await readFile(join(stateDirectory, 'daemon.json'), 'utf8')),
      }
    } catch {
      if (child.exitCode !== null) {
        throw new Error(`Packaged daemon exited: ${await new Response(child.stderr).text()}`)
      }
      await Bun.sleep(25)
    }
  }
  child.kill()
  throw new Error('Packaged daemon did not start.')
}

async function rpc(
  descriptor: { endpoint: string; token: string },
  operation: string,
  payload: unknown,
  owner: Record<string, string>,
  signal?: AbortSignal
) {
  const response = await fetch(`${descriptor.endpoint}/rpc`, {
    method: 'POST',
    headers: { authorization: `Bearer ${descriptor.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ id: crypto.randomUUID(), version: 3, operation, owner, payload }),
    signal: signal ?? AbortSignal.timeout(10_000),
  })
  return response.json() as Promise<{ ok: boolean; result?: unknown; error?: unknown }>
}

try {
  await stat(workerPath)
  const packed = Bun.spawn({ cmd: ['npm', 'pack', '--pack-destination', packageDirectory] })
  if ((await packed.exited) !== 0) throw new Error('npm pack failed.')
  const archive = (await Array.fromAsync(new Bun.Glob('*.tgz').scan({ cwd: packageDirectory })))[0]
  if (!archive) throw new Error('npm pack produced no archive.')
  const installedRoot = join(packageDirectory, 'installed')
  const installed = join(installedRoot, 'node_modules', 'opencode-pty')
  const installedPackage = Bun.spawn({
    cmd: ['npm', 'install', '--prefix', installedRoot, join(packageDirectory, archive)],
  })
  if ((await installedPackage.exited) !== 0) throw new Error('npm install failed.')

  let started = await startDaemon(installed)
  daemon = started.child
  const secret = (await readFile(join(stateDirectory, 'ownership-secret'), 'utf8')).trim()
  const owner = {
    parentSessionId: 'packaged-native',
    projectDirectory: root,
    capability: new Bun.CryptoHasher('sha256')
      .update(`${secret}\0packaged-native\0${root}`)
      .digest('hex'),
  }
  const executeAbort = new AbortController()
  const executing = rpc(
    started.descriptor,
    'exec',
    {
      command: process.execPath,
      args: ['-e', "console.log('packed-native'); setInterval(() => {}, 1000)"],
      timeoutSeconds: 10,
    },
    owner,
    executeAbort.signal
  )
  let id: { id: string } | undefined
  for (let attempt = 0; attempt < 100 && !id; attempt += 1) {
    const listed = await rpc(started.descriptor, 'list', {}, owner)
    id = Array.isArray(listed.result)
      ? (listed.result.find((value) => (value as { mode?: string }).mode === 'exec') as
          | { id: string }
          | undefined)
      : undefined
    if (!id) await Bun.sleep(25)
  }
  if (!id) throw new Error('Packaged native exec was not recorded.')
  let workerPid: number | undefined
  for (let attempt = 0; attempt < 100 && !workerPid; attempt += 1) {
    try {
      const firstRecord = JSON.parse(
        await readFile(join(stateDirectory, 'sessions', id.id, 'session.json'), 'utf8')
      ) as { worker?: { pid?: number } }
      if (Number.isInteger(firstRecord.worker?.pid)) workerPid = firstRecord.worker?.pid
    } catch {}
    if (!workerPid) await Bun.sleep(25)
  }
  if (!Number.isInteger(workerPid)) throw new Error('Packaged native worker was not recorded.')
  const confirmedWorkerPid = workerPid as number

  daemon.kill('SIGKILL')
  await Promise.race([daemon.exited, Bun.sleep(5000)])
  executeAbort.abort()
  void executing.catch(() => undefined)
  await rm(join(stateDirectory, 'daemon.json'), { force: true })
  started = await startDaemon(installed)
  daemon = started.child
  const stopped = await rpc(started.descriptor, 'stop', { id: id.id }, owner)
  if (
    !stopped.ok ||
    (stopped.result as { terminationConfirmed?: boolean } | undefined)?.terminationConfirmed !==
      true
  )
    throw new Error('Reconnected packaged daemon did not stop native exec.')
  await Bun.sleep(100)
  try {
    process.kill(confirmedWorkerPid, 0)
    throw new Error('Native worker survived packaged daemon shutdown.')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error
  }
  await stat(join(stateDirectory, 'sessions', id.id, 'worker.json')).then(
    () => Promise.reject(new Error('Native worker descriptor survived shutdown.')),
    () => undefined
  )
} finally {
  daemon?.kill('SIGKILL')
  await Promise.race([daemon?.exited.catch(() => undefined), Bun.sleep(5000)])
  await removeTemporary(packageDirectory)
  await removeTemporary(stateDirectory)
}

process.exit(0)
