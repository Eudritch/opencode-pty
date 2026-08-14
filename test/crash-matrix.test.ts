import { expect, test } from 'bun:test'
import { existsSync, realpathSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DaemonStorage } from '../src/daemon/storage.ts'
import { DAEMON_PROTOCOL_VERSION } from '../src/daemon/types.ts'

const nativeWorkerPath =
  process.env.PTY_NATIVE_WORKER_PATH ??
  join(
    process.cwd(),
    'target',
    'debug',
    `opencode-pty-worker${process.platform === 'win32' ? '.exe' : ''}`
  )

type Descriptor = { endpoint: string; token: string }
type Daemon = { child: ReturnType<typeof Bun.spawn>; descriptor: Descriptor }

async function waitForExit(child: ReturnType<typeof Bun.spawn>): Promise<void> {
  const exited = await Promise.race([
    child.exited.then(() => true),
    Bun.sleep(5000).then(() => false),
  ])
  if (!exited) throw new Error('Daemon did not exit within 5 seconds.')
}

async function stopProcess(child: ReturnType<typeof Bun.spawn>): Promise<void> {
  if (child.exitCode !== null) return
  child.kill('SIGKILL')
  await waitForExit(child)
}

async function removeTemporary(root: string): Promise<void> {
  let failure: unknown
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      await rm(root, { recursive: true, force: true })
      return
    } catch (error) {
      failure = error
      await Bun.sleep(50)
    }
  }
  throw failure
}

async function startDaemon(root: string): Promise<Daemon> {
  const token = crypto.randomUUID().replaceAll('-', '')
  const options = Buffer.from(JSON.stringify({ dataDirectory: root, token })).toString('base64url')
  const child = Bun.spawn({
    cmd: [process.execPath, 'src/daemon/main.ts', options],
    cwd: process.cwd(),
    env: { ...process.env, PTY_NATIVE_WORKER_PATH: nativeWorkerPath },
    stdout: 'ignore',
    stderr: 'pipe',
    windowsHide: true,
  })
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    try {
      const descriptor = JSON.parse(await readFile(join(root, 'daemon.json'), 'utf8')) as {
        endpoint?: string
        token?: string
      }
      if (typeof descriptor.endpoint === 'string' && descriptor.token === token)
        return { child, descriptor: { endpoint: descriptor.endpoint, token } }
    } catch {}
    if (child.exitCode !== null)
      throw new Error(`Daemon exited: ${await new Response(child.stderr).text()}`)
    await Bun.sleep(25)
  }
  await stopProcess(child)
  throw new Error(`Daemon did not start: ${await new Response(child.stderr).text()}`)
}

async function rpc(
  descriptor: Descriptor,
  owner: Record<string, string>,
  operation: string,
  payload: unknown
): Promise<{ ok: boolean; result?: unknown; error?: { code?: string } }> {
  const response = await fetch(`${descriptor.endpoint}/rpc`, {
    method: 'POST',
    headers: { authorization: `Bearer ${descriptor.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      id: crypto.randomUUID(),
      version: DAEMON_PROTOCOL_VERSION,
      operation,
      owner,
      payload,
    }),
  })
  return response.json()
}

const crashTest = existsSync(nativeWorkerPath) ? test : test.skip

crashTest(
  'daemon crash after child creation reconnects without replaying start',
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'opencode-pty-crash-matrix-'))
    const marker = join(root, 'starts.log')
    let daemon: Daemon | undefined
    let id: string | undefined
    let owner: Record<string, string> | undefined
    try {
      daemon = await startDaemon(root)
      const storage = new DaemonStorage(root)
      const projectDirectory = realpathSync(root)
      owner = {
        parentSessionId: 'crash-matrix-parent',
        projectDirectory,
        capability: new Bun.CryptoHasher('sha256')
          .update(`${await storage.ownershipSecret()}\0crash-matrix-parent\0${projectDirectory}`)
          .digest('hex'),
      }
      const started = await rpc(daemon.descriptor, owner, 'execStart', {
        command: process.execPath,
        args: [
          '-e',
          `require('node:fs').appendFileSync(${JSON.stringify(marker)}, 'start\\n'); setInterval(() => {}, 1000)`,
        ],
        timeoutSeconds: 30,
        lifecycle: 'persistent',
      })
      expect(started.ok).toBeTrue()
      id = (started.result as { id?: string }).id
      expect(id).toStartWith('exec_')
      for (let attempt = 0; attempt < 100 && !existsSync(marker); attempt += 1) await Bun.sleep(25)
      expect(existsSync(marker)).toBeTrue()

      await stopProcess(daemon.child)
      daemon = await startDaemon(root)
      let recovered: { status?: string } | undefined
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const current = await rpc(daemon.descriptor, owner, 'get', { id })
        recovered = current.result as { status?: string } | undefined
        if (current.ok && recovered?.status === 'running') break
        await Bun.sleep(25)
      }
      expect(recovered?.status).toBe('running')
      expect((await readFile(marker, 'utf8')).trim().split('\n')).toEqual(['start'])
    } finally {
      if (daemon && owner && id)
        await rpc(daemon.descriptor, owner, 'stop', { id }).catch(() => undefined)
      if (daemon) await stopProcess(daemon.child).catch(() => undefined)
      await removeTemporary(root)
    }
  },
  45_000
)
