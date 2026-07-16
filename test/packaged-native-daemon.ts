import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = process.cwd()
const packageDirectory = await mkdtemp(join(tmpdir(), 'opencode-pty-package-'))
const stateDirectory = await mkdtemp(join(tmpdir(), 'opencode-pty-state-'))
const platform =
  process.platform === 'linux' && (process.arch === 'x64' || process.arch === 'arm64')
    ? `linux-${process.arch}-gnu`
    : `${process.platform}-${process.arch}`
const supportedPlatforms = new Set([
  'linux-x64-gnu',
  'linux-arm64-gnu',
  'win32-x64',
  'win32-arm64',
  'darwin-arm64',
  'darwin-x64',
])
let daemon: ReturnType<typeof Bun.spawn> | undefined
let installed: string | undefined
let executing: Promise<{ ok: boolean; result?: unknown; error?: unknown }> | undefined
let executeAbort: AbortController | undefined
let cleanupVerified = false
let active:
  | {
      descriptor: { endpoint: string; token: string }
      owner: Record<string, string>
      id: string
    }
  | undefined
let worker:
  | {
      pid: number
      startIdentity: string
      processIdentity: string
      endpoint: string
      token: string
      executable: string
      observedIdentity?: string
    }
  | undefined

type Child = ReturnType<typeof Bun.spawn>

async function waitForExit(child: Child, name: string) {
  const exited = await Promise.race([
    child.exited.then(() => true),
    Bun.sleep(5000).then(() => false),
  ])
  if (!exited) throw new Error(`${name} did not exit within 5 seconds.`)
}

async function stopOwnedCommand(child: Child, name: string) {
  if (child.exitCode !== null) return
  if (process.platform === 'win32') {
    const killer = Bun.spawn({
      cmd: ['taskkill.exe', '/PID', String(child.pid), '/T', '/F'],
      stdout: 'pipe',
      stderr: 'pipe',
    })
    await Promise.race([killer.exited, Bun.sleep(5000).then(() => killer.kill())])
  } else child.kill('SIGKILL')
  await waitForExit(child, name)
}

async function runCommand(command: string[], name: string, timeoutMs = 120_000, cwd?: string) {
  const child = Bun.spawn({
    cmd: process.platform === 'win32' ? command : ['setsid', ...command],
    ...(cwd ? { cwd } : {}),
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const stdout = new Response(child.stdout).text()
  const stderr = new Response(child.stderr).text()
  const completed = await Promise.race([
    child.exited.then(() => true),
    Bun.sleep(timeoutMs).then(() => false),
  ])
  if (!completed) {
    await stopOwnedCommand(child, `${name} timeout cleanup`)
    throw new Error(
      `${name} timed out after ${timeoutMs}ms. stdout: ${await stdout}\nstderr: ${await stderr}`
    )
  }
  return { exitCode: child.exitCode, stdout: await stdout, stderr: await stderr }
}

async function requireCommand(command: string[], name: string, timeoutMs?: number, cwd?: string) {
  const result = await runCommand(command, name, timeoutMs, cwd)
  if (result.exitCode !== 0)
    throw new Error(
      `${name} exited ${result.exitCode}. stdout: ${result.stdout}\nstderr: ${result.stderr}`
    )
  return result
}

async function waitForExecution() {
  if (!executing) return
  const settled = await Promise.race([
    executing.catch(() => undefined).then(() => true),
    Bun.sleep(5000).then(() => false),
  ])
  if (!settled) throw new Error('Packaged exec RPC did not settle within 5 seconds.')
}

async function processIdentity(pid: number) {
  if (process.platform === 'win32') {
    const result = await runCommand(
      [
        'powershell.exe',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `$process = Get-Process -Id ${pid} -ErrorAction SilentlyContinue; if ($process) { [Console]::Write("windows:${pid}:$($process.StartTime.ToFileTimeUtc())") }`,
      ],
      `Read Windows process identity for ${pid}`,
      5000
    )
    return result.exitCode === 0 && result.stdout ? result.stdout.trim() : undefined
  }
  if (process.platform === 'darwin') {
    const result = await runCommand(
      ['ps', '-p', String(pid), '-o', 'lstart='],
      `Read macOS process identity for ${pid}`,
      5000
    )
    return result.exitCode === 0 && result.stdout
      ? `darwin:${pid}:${result.stdout.trim()}`
      : undefined
  }
  try {
    const data = await readFile(`/proc/${pid}/stat`, 'utf8')
    const fields = data
      .slice(data.lastIndexOf(')') + 1)
      .trim()
      .split(/\s+/)
    return fields[19] ? `posix:${pid}:${fields[19]}` : undefined
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
}

async function workerHealth(worker: { endpoint: string; token: string }, timeoutMs: number) {
  const response = await fetch(`${worker.endpoint}/rpc`, {
    method: 'POST',
    headers: { authorization: `Bearer ${worker.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ operation: 'health' }),
    signal: AbortSignal.timeout(timeoutMs),
  })
  const body = (await response.json()) as { ok?: boolean }
  if (!body.ok) throw new Error('Native worker rejected its authenticated health probe.')
}

async function shutdownWorker(worker: { endpoint: string; token: string }) {
  await fetch(`${worker.endpoint}/rpc`, {
    method: 'POST',
    headers: { authorization: `Bearer ${worker.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ operation: 'shutdown' }),
    signal: AbortSignal.timeout(5000),
  }).catch(() => undefined)
}

async function assertWorkerStopped(worker: {
  pid: number
  processIdentity: string
  endpoint: string
  token: string
  observedIdentity?: string
}) {
  const identity = worker.observedIdentity ?? worker.processIdentity
  const deadline = Date.now() + 5000
  while (Date.now() < deadline) {
    const current = await processIdentity(worker.pid)
    if (current !== identity) return // A reused PID is not our worker.
    try {
      await workerHealth(worker, 250)
    } catch {
      // Shutdown closes the listener before process exit; the identity probe remains authoritative.
    }
    await Bun.sleep(25)
  }
  throw new Error(`Native worker survived authenticated shutdown: ${identity}`)
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
        const removed = await runCommand(
          ['cmd.exe', '/C', 'rmdir', '/S', '/Q', path],
          `Remove temporary directory ${path}`,
          5000
        ).catch(() => undefined)
        if (removed?.exitCode === 0) return
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
      PTY_NATIVE_WORKER_PATH: '',
      PTY_NATIVE_WORKER_DEV: '',
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
    body: JSON.stringify({ id: crypto.randomUUID(), version: 5, operation, owner, payload }),
    signal: signal ?? AbortSignal.timeout(10_000),
  })
  return response.json() as Promise<{ ok: boolean; result?: unknown; error?: unknown }>
}

let testFailure: unknown
let cleanupFailure: unknown

try {
  if (!supportedPlatforms.has(platform)) throw new Error(`No native package for ${platform}.`)
  await requireCommand(['cargo', 'build', '--locked', '--release', '--workspace'], 'cargo build')
  const nativeDirectory = join(packageDirectory, 'native-artifacts', platform)
  await requireCommand(
    ['bun', 'native:prepare', platform, nativeDirectory],
    'prepare native package'
  )
  await requireCommand(
    ['npm', 'pack', '--pack-destination', packageDirectory],
    'npm pack worker',
    undefined,
    nativeDirectory
  )
  await requireCommand(['npm', 'pack', '--pack-destination', packageDirectory], 'npm pack')
  const archives = await Array.fromAsync(new Bun.Glob('*.tgz').scan({ cwd: packageDirectory }))
  const archive = archives.find((file) => file.startsWith('opencode-pty-'))
  const nativeArchive = archives.find((file) =>
    file.startsWith(`eudritch-opencode-pty-worker-${platform}-`)
  )
  if (!archive || !nativeArchive) throw new Error('npm pack produced incomplete package artifacts.')
  const installedRoot = join(packageDirectory, 'installed')
  installed = join(installedRoot, 'node_modules', 'opencode-pty')
  await requireCommand(
    [
      'npm',
      'install',
      '--prefix',
      installedRoot,
      join(packageDirectory, archive),
      join(packageDirectory, nativeArchive),
    ],
    'npm install packaged native worker'
  )
  await stat(
    join(
      installedRoot,
      'node_modules',
      '@eudritch',
      `opencode-pty-worker-${platform}`,
      'bin',
      `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
    )
  )

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
  if (process.platform === 'win32') {
    const pty = await rpc(
      started.descriptor,
      'spawn',
      {
        command: process.execPath,
        args: ['-e', "process.stdin.on('data', data => process.stdout.write('echo:' + data))"],
      },
      owner
    )
    if (!pty.ok) throw new Error(`Windows packaged ConPTY did not start: ${JSON.stringify(pty)}`)
    const id = (pty.result as { id: string }).id
    const marker = 'echo:conpty-check'
    const written = await rpc(
      started.descriptor,
      'sendWait',
      {
        id,
        data: 'conpty-check\r\n',
        condition: { kind: 'output', literal: marker },
        timeoutSeconds: 2,
      },
      owner
    )
    if (!written.ok || (written.result as { satisfied?: boolean } | undefined)?.satisfied !== true)
      throw new Error(`Windows packaged ConPTY did not echo input: ${JSON.stringify(written)}`)
    const resized = await rpc(started.descriptor, 'resize', { id, cols: 100, rows: 30 }, owner)
    if (!resized.ok)
      throw new Error(`Windows packaged ConPTY did not resize: ${JSON.stringify(resized)}`)
    const read = await rpc(started.descriptor, 'rawOutput', { id }, owner)
    const output = (read.result as { raw?: string } | undefined)?.raw ?? ''
    if (!read.ok || !output.includes(marker))
      throw new Error(`Windows packaged ConPTY did not echo input: ${JSON.stringify(output)}`)
    await rpc(started.descriptor, 'stop', { id }, owner)
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
  for (let attempt = 0; attempt < 100 && !worker; attempt += 1) {
    try {
      const descriptor = JSON.parse(
        await readFile(join(stateDirectory, 'sessions', id.id, 'worker.json'), 'utf8')
      ) as {
        pid?: number
        startIdentity?: string
        processIdentity?: string
        endpoint?: string
        token?: string
      }
      const firstRecord = JSON.parse(
        await readFile(join(stateDirectory, 'sessions', id.id, 'session.json'), 'utf8')
      ) as { worker?: { executable?: string } }
      const executable = firstRecord.worker?.executable
      const { pid } = descriptor
      if (
        typeof pid === 'number' &&
        Number.isInteger(pid) &&
        typeof descriptor.startIdentity === 'string' &&
        typeof descriptor.processIdentity === 'string' &&
        typeof descriptor.endpoint === 'string' &&
        typeof descriptor.token === 'string' &&
        typeof executable === 'string'
      )
        worker = {
          pid,
          startIdentity: descriptor.startIdentity,
          processIdentity: descriptor.processIdentity,
          endpoint: descriptor.endpoint,
          token: descriptor.token,
          executable,
        }
    } catch {}
    if (!worker) await Bun.sleep(25)
  }
  if (!worker) throw new Error('Packaged native worker identity was not recorded.')
  const packagedWorker = join(
    installedRoot,
    'node_modules',
    '@eudritch',
    `opencode-pty-worker-${platform}`,
    'bin',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )
  if (worker.executable !== packagedWorker)
    throw new Error(
      `Native worker was not resolved from the packed optional package: ${worker.executable}`
    )
  await workerHealth(worker, 5000)
  worker.observedIdentity = await processIdentity(worker.pid)
  if (!worker.observedIdentity)
    throw new Error(`Native worker identity could not be read: ${worker.pid}`)
  if (process.platform !== 'darwin' && worker.observedIdentity !== worker.processIdentity)
    throw new Error(
      `Native worker identity mismatch: ${worker.processIdentity} != ${worker.observedIdentity}`
    )

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
    throw new Error(
      `Reconnected packaged daemon did not stop native exec: ${JSON.stringify(stopped)}`
    )
  const terminal = await rpc(started.descriptor, 'get', { id: id.id }, owner)
  if (
    !terminal.ok ||
    (terminal.result as { terminationConfirmed?: boolean } | undefined)?.terminationConfirmed !==
      true
  )
    throw new Error('Reconnected packaged daemon did not record native exec termination.')
  const terminalResult = terminal.result as {
    containment?: { status?: string }
  }
  if (
    process.platform === 'linux' &&
    terminalResult.containment?.status !== 'posix_best_effort_empty'
  )
    throw new Error(
      `Linux packaged native exec was not containment-confirmed: ${terminalResult.containment?.status}`
    )
  if (process.platform === 'win32' && terminalResult.containment?.status !== 'windows_job_empty')
    throw new Error(
      `Windows packaged native exec was not Job-drain-confirmed: ${terminalResult.containment?.status}`
    )
  const output = await rpc(started.descriptor, 'execOutput', { id: id.id }, owner)
  if (
    process.platform === 'win32' &&
    (!output.ok || (output.result as { stdout?: string } | null)?.stdout !== 'packed-native\n')
  )
    throw new Error('Windows packaged native worker did not directly execute the requested argv.')
  await assertWorkerStopped(worker)
  await stat(join(stateDirectory, 'sessions', id.id, 'worker.json')).then(
    () => Promise.reject(new Error('Native worker descriptor survived shutdown.')),
    () => undefined
  )
  cleanupVerified = true
} catch (error) {
  testFailure = error
} finally {
  executeAbort?.abort()
  await waitForExecution().catch(() => undefined)
  if (active && installed) {
    if (!daemon || daemon.exitCode !== null) {
      const restarted = await startDaemon(installed).catch(() => undefined)
      if (restarted) {
        daemon = restarted.child
        active.descriptor = restarted.descriptor
      }
    }
    if (daemon?.exitCode === null)
      await rpc(active.descriptor, 'stop', { id: active.id }, active.owner).catch(() => undefined)
  }
  try {
    if (worker) {
      await shutdownWorker(worker)
      await assertWorkerStopped(worker)
    }
  } catch (error) {
    cleanupFailure = error
  } finally {
    if (daemon?.exitCode === null) daemon.kill('SIGKILL')
    if (daemon) await waitForExit(daemon, 'Packaged daemon cleanup').catch(() => undefined)
    await Promise.allSettled([removeTemporary(packageDirectory), removeTemporary(stateDirectory)])
  }
}

if (testFailure) throw testFailure
if (cleanupFailure) throw cleanupFailure
if (!cleanupVerified) throw new Error('Packaged native cleanup was not verified.')
process.exit(0)
