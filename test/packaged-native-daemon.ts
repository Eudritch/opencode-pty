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
let executing: Promise<{ ok: boolean; result?: unknown; error?: unknown }> | undefined
let executeAbort: AbortController | undefined
let childPid: number | undefined
let workerPid: number | undefined
let active:
  | {
      descriptor: { endpoint: string; token: string }
      owner: Record<string, string>
      id: string
    }
  | undefined

async function waitForExit(child: ReturnType<typeof Bun.spawn>, name: string) {
  const exited = await Promise.race([
    child.exited.then(() => true),
    Bun.sleep(5000).then(() => false),
  ])
  if (!exited) throw new Error(`${name} did not exit within 5 seconds.`)
}

async function waitForExecution() {
  if (!executing) return
  const settled = await Promise.race([
    executing.catch(() => undefined).then(() => true),
    Bun.sleep(5000).then(() => false),
  ])
  if (!settled) throw new Error('Packaged exec RPC did not settle within 5 seconds.')
}

async function assertStopped(pid: number, name: string) {
  const deadline = Date.now() + 5000
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0)
      if (process.platform === 'win32') {
        const processInfo = Bun.spawn({
          cmd: ['tasklist.exe', '/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'],
          stdout: 'pipe',
          stderr: 'ignore',
        })
        const output = await new Response(processInfo.stdout).text()
        if (!output.includes(`"${pid}"`)) return
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') return
      throw error
    }
    await Bun.sleep(25)
  }
  throw new Error(`${name} survived shutdown (PID ${pid}).`)
}

async function stopPid(pid: number | undefined, name: string) {
  if (!pid) return
  try {
    process.kill(pid, 'SIGKILL')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error
  }
  await assertStopped(pid, name)
}

async function removeTemporary(path: string) {
  let failure: unknown
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      await rm(path, { recursive: true, force: true })
      return
    } catch (error) {
      failure = error
      if (process.platform === 'win32') {
        const removed = Bun.spawn({
          cmd: ['cmd.exe', '/C', 'rmdir', '/S', '/Q', path],
          stdout: 'ignore',
          stderr: 'ignore',
        })
        if ((await removed.exited) === 0) return
      }
      await Bun.sleep(100)
    }
  }
  throw new Error(`Could not remove temporary directory: ${path}: ${failure}`)
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
  await waitForExit(child, 'Packaged daemon')
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
  const packed = Bun.spawn({
    cmd: ['npm', 'pack', '--pack-destination', packageDirectory],
    stdout: 'ignore',
    stderr: 'inherit',
  })
  if ((await packed.exited) !== 0) throw new Error('npm pack failed.')
  const archive = (await Array.fromAsync(new Bun.Glob('*.tgz').scan({ cwd: packageDirectory })))[0]
  if (!archive) throw new Error('npm pack produced no archive.')
  const installedRoot = join(packageDirectory, 'installed')
  const installed = join(installedRoot, 'node_modules', 'opencode-pty')
  const installedPackage = Bun.spawn({
    cmd: ['npm', 'install', '--prefix', installedRoot, join(packageDirectory, archive)],
    stdout: 'ignore',
    stderr: 'inherit',
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
  executeAbort = new AbortController()
  executing = rpc(
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
  active = { descriptor: started.descriptor, owner, id: id.id }
  for (let attempt = 0; attempt < 100 && !childPid; attempt += 1) {
    const snapshot = await rpc(started.descriptor, 'get', { id: id.id }, owner)
    const pid = (snapshot.result as { pid?: number } | undefined)?.pid
    if (Number.isInteger(pid) && (pid ?? 0) > 0) childPid = pid
    if (!childPid) await Bun.sleep(25)
  }
  if (!Number.isInteger(childPid)) throw new Error('Packaged native child PID was not recorded.')
  const confirmedChildPid = childPid as number
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
  await waitForExit(daemon, 'First packaged daemon')
  executeAbort.abort()
  await waitForExecution()
  await rm(join(stateDirectory, 'daemon.json'), { force: true })
  started = await startDaemon(installed)
  daemon = started.child
  active.descriptor = started.descriptor
  const stopped = await rpc(started.descriptor, 'stop', { id: id.id }, owner)
  if (
    !stopped.ok ||
    (stopped.result as { terminationConfirmed?: boolean } | undefined)?.terminationConfirmed !==
      true
  )
    throw new Error('Reconnected packaged daemon did not stop native exec.')
  const terminal = await rpc(started.descriptor, 'get', { id: id.id }, owner)
  if (
    !terminal.ok ||
    (terminal.result as { terminationConfirmed?: boolean } | undefined)?.terminationConfirmed !==
      true
  )
    throw new Error('Reconnected packaged daemon did not record native exec termination.')
  await assertStopped(confirmedChildPid, 'Native exec child')
  await assertStopped(confirmedWorkerPid, 'Native worker')
  await stat(join(stateDirectory, 'sessions', id.id, 'worker.json')).then(
    () => Promise.reject(new Error('Native worker descriptor survived shutdown.')),
    () => undefined
  )
} finally {
  executeAbort?.abort()
  await waitForExecution()
  if (daemon) {
    if (daemon.exitCode === null && active)
      await rpc(active.descriptor, 'stop', { id: active.id }, active.owner).catch(() => undefined)
    if (daemon.exitCode === null) daemon.kill('SIGKILL')
    await waitForExit(daemon, 'Packaged daemon cleanup')
  }
  await stopPid(childPid, 'Native exec child cleanup')
  await stopPid(workerPid, 'Native worker cleanup')
  await removeTemporary(packageDirectory)
  await removeTemporary(stateDirectory)
}
