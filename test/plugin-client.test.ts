import { afterEach, expect, test } from 'bun:test'
import { realpathSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  DaemonClient,
  ownerContext,
  safeStartupStderrTail,
} from '../src/plugin/pty/daemon-client.ts'
import { manager } from '../src/plugin/pty/manager.ts'
import { createShellExec } from '../src/plugin/pty/tools/exec.ts'
import { ptyResize } from '../src/plugin/pty/tools/resize.ts'
import { createPtySpawn } from '../src/plugin/pty/tools/spawn.ts'
import { ptySendWait, ptyWait } from '../src/plugin/pty/tools/wait.ts'
import { parseEscapeSequences, ptyWrite, writePreview } from '../src/plugin/pty/tools/write.ts'

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

async function tempRoot(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix))
  roots.push(root)
  return root
}

function toolContext(directory: string) {
  return {
    sessionID: 'plugin-client-test',
    directory,
    agent: 'test',
    abort: new AbortController().signal,
    ask: async () => {},
    metadata: () => {},
  } as never
}

function patchManager(overrides: Record<string, unknown>): () => void {
  const target = manager as unknown as Record<string, unknown>
  for (const [key, value] of Object.entries(overrides)) target[key] = value
  return () => {
    for (const key of Object.keys(overrides)) Reflect.deleteProperty(target, key)
  }
}

test('startup stderr tail redacts every occurrence of each secret', () => {
  expect(
    safeStartupStderrTail('boot failed: token=TOKEN payload=PAYLOAD then TOKEN', 'TOKEN', 'PAYLOAD')
  ).toBe('boot failed: token=[REDACTED] payload=[REDACTED] then [REDACTED]')
})

test('startup stderr tail trims surrounding whitespace', () => {
  expect(safeStartupStderrTail('  \n daemon exploded \t ')).toBe('daemon exploded')
})

test('startup stderr tail keeps only the last 4096 characters', () => {
  const tail = `${'x'.repeat(5000)}END`
  const result = safeStartupStderrTail(tail)
  expect(result?.length).toBe(4096)
  expect(result).toBe(tail.slice(-4096))
})

test('startup stderr tail redacts secrets before applying the length cap', () => {
  const result = safeStartupStderrTail(`${'x'.repeat(5000)}SECRET`, 'SECRET')
  expect(result?.endsWith('[REDACTED]')).toBeTrue()
  expect(result?.length).toBe(4096)
})

test('startup stderr tail returns null for missing or blank input', () => {
  expect(safeStartupStderrTail(null)).toBeNull()
  expect(safeStartupStderrTail(undefined)).toBeNull()
  expect(safeStartupStderrTail('')).toBeNull()
  expect(safeStartupStderrTail('   \n\t  ')).toBeNull()
})

test('startup stderr tail tolerates null, undefined, and empty secrets', () => {
  expect(safeStartupStderrTail(' boom TOKEN ', null, undefined, '', 'TOKEN')).toBe(
    'boom [REDACTED]'
  )
})

test('owner context realpaths the project directory', async () => {
  const root = await tempRoot('opencode-pty-plugin-owner-')
  expect(ownerContext('session', root)).toEqual({
    parentSessionId: 'session',
    projectDirectory: realpathSync(root),
    capability: '',
  })
})

test('owner context rejects missing or empty inputs with a descriptive error', async () => {
  const root = await tempRoot('opencode-pty-plugin-owner-invalid-')
  const message = 'PTY owner context requires a session id and project directory.'
  expect(() => ownerContext(undefined as never, root)).toThrow(message)
  expect(() => ownerContext('', root)).toThrow(message)
  expect(() => ownerContext('session', undefined as never)).toThrow(message)
  expect(() => ownerContext('session', '')).toThrow(message)
})

test('write preview substitutes control characters in decoded input', () => {
  expect(writePreview('\x03')).toBe('^C')
  expect(writePreview('a\r\nb')).toBe('a\\r\\nb')
  expect(parseEscapeSequences('\\x03')).toBe('\x03')
})

test('pty_write reports decoded byte counts and a decoded ^C preview', async () => {
  const root = await tempRoot('opencode-pty-plugin-write-')
  const written: string[] = []
  const restore = patchManager({
    get: async () => ({ status: 'running' }),
    write: async (_id: string, data: string) => {
      written.push(data)
      return {
        acceptedBytes: Buffer.byteLength(data, 'utf8'),
        acceptedCharacters: [...data].length,
      }
    },
  })
  try {
    const output = await ptyWrite.execute({ id: 'pty_test', data: '\\x03' }, toolContext(root))
    expect(written).toEqual(['\x03'])
    expect(output).toBe('Accepted 1 UTF-8 bytes (1 characters) for pty_test: "^C"')
  } finally {
    restore()
  }
})

test('pty_write truncates the decoded preview after substitutions', async () => {
  const root = await tempRoot('opencode-pty-plugin-write-long-')
  const restore = patchManager({
    get: async () => ({ status: 'running' }),
    write: async (_id: string, data: string) => ({
      acceptedBytes: Buffer.byteLength(data, 'utf8'),
      acceptedCharacters: [...data].length,
    }),
  })
  try {
    const output = await ptyWrite.execute(
      { id: 'pty_test', data: `echo ${'a'.repeat(60)}\\n` },
      toolContext(root)
    )
    // Decoded input is 66 characters ("echo " + 60 * "a" + newline); the preview
    // substitutes the newline, then truncates the decoded text at 50 characters.
    expect(output).toBe(
      `Accepted 66 UTF-8 bytes (66 characters) for pty_test: "echo ${'a'.repeat(45)}..."`
    )
  } finally {
    restore()
  }
})

test('resize schema rejects out-of-range dimensions', () => {
  expect(() => ptyResize.args.cols.parse(0)).toThrow()
  expect(() => ptyResize.args.cols.parse(1001)).toThrow()
  expect(() => ptyResize.args.rows.parse(0)).toThrow()
  expect(() => ptyResize.args.rows.parse(1001)).toThrow()
  expect(ptyResize.args.cols.parse(1)).toBe(1)
  expect(ptyResize.args.rows.parse(1000)).toBe(1000)
})

test('wait schemas reject timeouts outside the daemon runtime cap', () => {
  for (const schema of [ptyWait.args.timeoutSeconds, ptySendWait.args.timeoutSeconds]) {
    expect(() => schema.parse(0)).toThrow()
    expect(() => schema.parse(3601)).toThrow()
    expect(schema.parse(1)).toBe(1)
    expect(schema.parse(3600)).toBe(3600)
  }
})

test('exec schema rejects timeouts outside the daemon runtime cap', () => {
  const shellExec = createShellExec(async () => '')
  expect(() => shellExec.args.timeoutSeconds.parse(0)).toThrow()
  expect(() => shellExec.args.timeoutSeconds.parse(3601)).toThrow()
  expect(shellExec.args.timeoutSeconds.parse(3600)).toBe(3600)
})

test('spawn schema enforces a positive timeout without capping long sessions', () => {
  const spawn = createPtySpawn(async () => '')
  expect(() => spawn.args.timeoutSeconds.parse(0)).toThrow()
  expect(spawn.args.timeoutSeconds.parse(undefined)).toBeUndefined()
  expect(spawn.args.timeoutSeconds.parse(86_400)).toBe(86_400)
})

test('daemon client reads PTY_DAEMON_DIR at first use rather than at construction', async () => {
  const root = await tempRoot('opencode-pty-plugin-lazy-storage-')
  const client = new DaemonClient()
  const previous = process.env.PTY_DAEMON_DIR
  process.env.PTY_DAEMON_DIR = root
  try {
    const storage = (client as unknown as { storage: { rootDirectory: string } }).storage
    expect(storage.rootDirectory).toBe(resolve(root))
  } finally {
    if (previous === undefined) delete process.env.PTY_DAEMON_DIR
    else process.env.PTY_DAEMON_DIR = previous
  }
})
