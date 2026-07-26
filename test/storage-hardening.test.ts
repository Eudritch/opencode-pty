import { afterEach, expect, test } from 'bun:test'
import { existsSync } from 'node:fs'
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DaemonStorage, daemonDataDirectory } from '../src/daemon/storage.ts'
import { DAEMON_PROTOCOL_VERSION } from '../src/daemon/types.ts'

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

function restoreEnv(name: string, previous: string | undefined): void {
  if (previous === undefined) delete process.env[name]
  else process.env[name] = previous
}

test('daemonDataDirectory rejects stringified non-values and relative paths', () => {
  const previous = process.env.PTY_DAEMON_DIR
  try {
    process.env.PTY_DAEMON_DIR = 'undefined'
    expect(() => daemonDataDirectory()).toThrow(
      'PTY_DAEMON_DIR must be an absolute path (got "undefined").'
    )
    process.env.PTY_DAEMON_DIR = 'relative/daemon-dir'
    expect(() => daemonDataDirectory()).toThrow('must be an absolute path')
    process.env.PTY_DAEMON_DIR = tmpdir()
    expect(daemonDataDirectory()).toBe(tmpdir())
  } finally {
    restoreEnv('PTY_DAEMON_DIR', previous)
  }
})

test('daemonDataDirectory falls back through APPDATA, XDG_STATE_HOME, then HOME', () => {
  const previous = {
    PTY_DAEMON_DIR: process.env.PTY_DAEMON_DIR,
    APPDATA: process.env.APPDATA,
    XDG_STATE_HOME: process.env.XDG_STATE_HOME,
    HOME: process.env.HOME,
  }
  try {
    delete process.env.PTY_DAEMON_DIR
    process.env.APPDATA = join(tmpdir(), 'appdata')
    process.env.XDG_STATE_HOME = join(tmpdir(), 'xdg-state')
    process.env.HOME = join(tmpdir(), 'home')
    expect(daemonDataDirectory()).toBe(join(tmpdir(), 'appdata', 'opencode-pty'))
    delete process.env.APPDATA
    expect(daemonDataDirectory()).toBe(join(tmpdir(), 'xdg-state', 'opencode-pty'))
    delete process.env.XDG_STATE_HOME
    expect(daemonDataDirectory()).toBe(join(tmpdir(), 'home', 'opencode-pty'))
    delete process.env.HOME
    expect(() => daemonDataDirectory()).toThrow('per-user daemon data directory')
  } finally {
    for (const [name, value] of Object.entries(previous)) restoreEnv(name, value)
  }
})

test('descriptorOwnerAlive is false for an unknowable owner with an unreachable endpoint', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-owner-unknown-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  await storage.writeDescriptor({
    pid: process.pid,
    processIdentity: 'unknowable-identity',
    endpoint: 'http://127.0.0.1:1',
    protocolVersion: DAEMON_PROTOCOL_VERSION,
    token: 'test-token',
  })
  // An expired deadline makes the process-identity probe return null while the
  // pid still exists (owner status 'unknown') and gives the authenticated
  // health probe a zero budget against an unreachable endpoint: the daemon
  // must be reported dead, never alive.
  expect(await storage.descriptorOwnerAlive(Date.now())).toBeFalse()
})

test('releaseStartLock removes an owned lock even when the identity probe cannot run', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-release-lock-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  const lockPath = join(root, 'daemon-start.lock')
  await writeFile(
    lockPath,
    JSON.stringify({ token: 'owned', handoffToken: null, pid: process.pid, processIdentity: null })
  )
  // The expired deadline forces any process-identity probe to fail (the fresh
  // root guarantees a cold identity cache); pid + token match must release.
  await storage.releaseStartLock('owned', Date.now())
  expect(existsSync(lockPath)).toBeFalse()

  // A lock recorded for a different pid is never released, probe or not.
  await writeFile(
    lockPath,
    JSON.stringify({
      token: 'foreign',
      handoffToken: null,
      pid: process.pid + 1,
      processIdentity: null,
    })
  )
  await storage.releaseStartLock('foreign', Date.now())
  expect(existsSync(lockPath)).toBeTrue()
})

test('acquireStartLockRecovery throws instead of looping past its deadline', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-recovery-deadline-'))
  roots.push(root)
  const storage = new DaemonStorage(root)
  await storage.requiredCurrentProcessStartIdentity()
  const internals = storage as unknown as {
    acquireStartLockRecovery: (deadline?: number) => Promise<boolean>
    writeExclusiveLock: () => Promise<boolean>
    startLockOwnerAlive: () => Promise<boolean>
  }
  // Simulate perpetual contention: exclusive creation always loses and the
  // contended lock is always gone by quarantine time (rename ENOENT retry).
  internals.writeExclusiveLock = async () => false
  internals.startLockOwnerAlive = async () => false
  const started = Date.now()
  await expect(internals.acquireStartLockRecovery(Date.now() + 250)).rejects.toThrow(
    'Timed out acquiring the daemon start-lock recovery lock.'
  )
  expect(Date.now() - started).toBeLessThan(4000)
})

test('daemon main refuses a relative dataDirectory with a clear stderr message', async () => {
  const root = await mkdtemp(join(tmpdir(), 'opencode-pty-main-validate-'))
  roots.push(root)
  const payload = Buffer.from(
    JSON.stringify({
      dataDirectory: 'undefined',
      token: 'test-token',
      startLockHandoffToken: 'handoff-token',
    })
  ).toString('base64url')
  const child = Bun.spawn({
    cmd: [
      process.execPath,
      fileURLToPath(new URL('../src/daemon/main.ts', import.meta.url)),
      payload,
    ],
    cwd: root,
    stdin: 'ignore',
    stdout: 'ignore',
    stderr: 'pipe',
    windowsHide: true,
  })
  const stderr = await new Response(child.stderr).text()
  expect(await child.exited).not.toBe(0)
  expect(stderr).toContain('dataDirectory must be a non-empty absolute path')
  expect(stderr).toContain('"undefined"')
  // The daemon must not have materialized locks or session state in its cwd.
  expect(await readdir(root)).toEqual([])
}, 15_000)
