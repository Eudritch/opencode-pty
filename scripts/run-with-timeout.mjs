import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'

const MAX_OUTPUT_BYTES = 1024 * 1024
const MAX_TIMEOUT_MS = 60 * 60 * 1000
const CLEANUP_WAIT_MS = 750
const DRAIN_WAIT_MS = 300
const WAIT_TIMEOUT = Symbol('wait timeout')

function waitFor(promise, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => finish(WAIT_TIMEOUT), timeoutMs)
    promise.then(finish, finish)
    function finish(value) {
      clearTimeout(timer)
      resolve(value)
    }
  })
}

function utf8SafeEnd(buffer) {
  let start = buffer.length
  while (start > 0 && (buffer[start - 1] & 0xc0) === 0x80) start -= 1
  if (start === buffer.length) {
    const byte = buffer[start - 1]
    return byte >= 0xc2 && byte <= 0xf4 ? start - 1 : start
  }
  if (start === 0) return buffer.length
  const lead = buffer[start - 1]
  const expected =
    lead >= 0xc2 && lead <= 0xdf
      ? 2
      : lead >= 0xe0 && lead <= 0xef
        ? 3
        : lead >= 0xf0 && lead <= 0xf4
          ? 4
          : 0
  return expected && buffer.length - start < expected - 1 ? start - 1 : buffer.length
}

function capture(stream) {
  const chunks = []
  let bytes = 0
  let truncated = false
  stream?.on('data', (chunk) => {
    const buffer = Buffer.from(chunk)
    const part = buffer.subarray(0, Math.max(0, MAX_OUTPUT_BYTES - bytes))
    if (part.length < buffer.length) truncated = true
    if (part.length) {
      chunks.push(part)
      bytes += part.length
    }
  })
  const output = () => {
    const captured = Buffer.concat(chunks, bytes)
    return `${captured.subarray(0, utf8SafeEnd(captured)).toString('utf8')}${truncated ? '\n[output truncated]' : ''}`
  }
  output.truncated = () => truncated
  return output
}

function baseResult(command) {
  return {
    command,
    exitCode: null,
    signal: null,
    status: 'not_started',
    timedOut: false,
    cancelled: false,
    elapsedMs: 0,
    stdout: '',
    stderr: '',
    outputMayBePartial: false,
    directChildCleanupAttempted: false,
    directChildCleanupConfirmed: false,
  }
}

const RESULT_KEYS = Object.keys(baseResult([])).sort()

function statusFor({ cancelled, timedOut, directChildObserved, childSpawned, cleanupUnconfirmed }) {
  if (cancelled) return 'cancelled'
  if (timedOut) return 'timed_out'
  if (directChildObserved) return 'exited'
  if (!childSpawned) return 'not_started'
  return cleanupUnconfirmed ? 'cleanup_unconfirmed' : 'not_started'
}

async function stopDirectChild(child, exited, directChildExited) {
  if (directChildExited()) {
    return {
      directChildCleanupAttempted: false,
      directChildCleanupConfirmed: true,
    }
  }

  let killed = false
  try {
    // This uses the ChildProcess handle for this direct child, not a numeric PID.
    killed = child.kill('SIGTERM')
  } catch {}
  if (!killed) {
    return {
      directChildCleanupAttempted: true,
      directChildCleanupConfirmed: false,
    }
  }

  await waitFor(exited, CLEANUP_WAIT_MS)
  return {
    directChildCleanupAttempted: true,
    directChildCleanupConfirmed: directChildExited(),
  }
}

async function drain(child, closed) {
  const drained = (await waitFor(closed, DRAIN_WAIT_MS)) !== WAIT_TIMEOUT
  if (!drained) {
    child.stdout?.destroy()
    child.stderr?.destroy()
    child.unref()
  }
  return drained
}

export async function runWithTimeout({ command, args = [], timeoutMs, signal } = {}) {
  if (
    typeof command !== 'string' ||
    !command ||
    !Array.isArray(args) ||
    !args.every((arg) => typeof arg === 'string')
  ) {
    throw new Error('command must be a non-empty string and args must be string array')
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`timeoutMs must be a positive integer no greater than ${MAX_TIMEOUT_MS}`)
  }
  if (
    signal !== undefined &&
    (signal === null ||
      typeof signal !== 'object' ||
      typeof signal.addEventListener !== 'function' ||
      typeof signal.removeEventListener !== 'function' ||
      typeof signal.aborted !== 'boolean')
  ) {
    throw new Error('signal must be an AbortSignal')
  }

  const commandLine = [command, ...args]
  if (process.platform !== 'win32') {
    return { ...baseResult(commandLine), stderr: 'run-with-timeout is supported only on Windows' }
  }

  const started = performance.now()
  if (signal?.aborted) {
    return {
      ...baseResult(commandLine),
      status: 'cancelled',
      cancelled: true,
      elapsedMs: Math.round(performance.now() - started),
    }
  }

  const child = spawn(command, args, {
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  })
  const stdout = capture(child.stdout)
  const stderr = capture(child.stderr)
  let childSpawned = false
  let directChildObserved = false
  let directResult
  const exited = new Promise((resolve) => {
    child.once('spawn', () => {
      childSpawned = true
    })
    child.once('exit', (exitCode, exitSignal) => {
      directChildObserved = true
      directResult = { exitCode, signal: exitSignal }
      resolve(directResult)
    })
    child.once('error', (error) => {
      directResult = { exitCode: null, error: error.message }
      resolve(directResult)
    })
  })
  const closed = new Promise((resolve) => child.once('close', resolve))
  let abort
  const cancelled = new Promise((resolve) => {
    abort = () => resolve({ cancelled: true })
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
  })
  const winner = await waitFor(Promise.race([exited, cancelled]), timeoutMs)
  try {
    signal?.removeEventListener('abort', abort)
  } catch {}
  const timedOut = winner === WAIT_TIMEOUT
  const wasCancelled = winner?.cancelled === true
  const needsCleanup = timedOut || wasCancelled
  const cleanup = needsCleanup
    ? await stopDirectChild(child, exited, () => directChildObserved)
    : { directChildCleanupAttempted: false, directChildCleanupConfirmed: directChildObserved }
  const streamsClosed = await drain(child, closed)
  const finalResult = directResult ?? winner ?? { exitCode: null }
  const capturedStderr = stderr()

  return {
    command: commandLine,
    exitCode: finalResult.exitCode ?? null,
    signal: finalResult.signal ?? null,
    status: statusFor({
      cancelled: wasCancelled,
      timedOut,
      directChildObserved,
      childSpawned,
      cleanupUnconfirmed:
        cleanup.directChildCleanupAttempted && !cleanup.directChildCleanupConfirmed,
    }),
    timedOut,
    cancelled: wasCancelled,
    elapsedMs: Math.round(performance.now() - started),
    stdout: stdout(),
    stderr: finalResult.error
      ? `${capturedStderr}${capturedStderr ? '\n' : ''}${finalResult.error}`
      : capturedStderr,
    outputMayBePartial: stdout.truncated() || stderr.truncated() || !streamsClosed,
    ...cleanup,
  }
}

function assertResultSchema(result, label) {
  assert.deepEqual(Object.keys(result).sort(), RESULT_KEYS, `${label} result schema changed`)
  assert.equal(
    typeof result.exitCode === 'number' || result.exitCode === null,
    true,
    `${label} exitCode is invalid`
  )
  assert.equal(
    typeof result.signal === 'string' || result.signal === null,
    true,
    `${label} signal is invalid`
  )
  assert.equal(typeof result.status, 'string', `${label} status is invalid`)
  assert.equal(typeof result.timedOut, 'boolean', `${label} timedOut is invalid`)
  assert.equal(typeof result.cancelled, 'boolean', `${label} cancelled is invalid`)
  assert.equal(typeof result.elapsedMs, 'number', `${label} elapsedMs is invalid`)
  assert.equal(typeof result.stdout, 'string', `${label} stdout is invalid`)
  assert.equal(typeof result.stderr, 'string', `${label} stderr is invalid`)
  assert.equal(
    typeof result.outputMayBePartial,
    'boolean',
    `${label} outputMayBePartial is invalid`
  )
  assert.equal(
    typeof result.directChildCleanupAttempted,
    'boolean',
    `${label} directChildCleanupAttempted is invalid`
  )
  assert.equal(
    typeof result.directChildCleanupConfirmed,
    'boolean',
    `${label} directChildCleanupConfirmed is invalid`
  )
}

async function selfTest(signal) {
  const finite = await runWithTimeout({
    command: process.execPath,
    args: ['-e', "console.log('ok')"],
    timeoutMs: 2_500,
    signal,
  })
  assertResultSchema(finite, 'finite')
  if (process.platform !== 'win32') {
    assert.equal(finite.status, 'not_started', 'unsupported platform started a child')
    assert.match(
      finite.stderr,
      /supported only on Windows/,
      'unsupported platform was not reported'
    )
    process.stdout.write(`${JSON.stringify({ ok: true, unsupported: finite })}\n`)
    return
  }

  const timedOut = await runWithTimeout({
    command: process.execPath,
    args: ['-e', 'setInterval(() => {}, 1_000)'],
    timeoutMs: 500,
    signal,
  })
  const cancellation = new AbortController()
  const cancelledPromise = runWithTimeout({
    command: process.execPath,
    args: ['-e', 'setInterval(() => {}, 1_000)'],
    timeoutMs: 2_500,
    signal: cancellation.signal,
  })
  const cancelTimer = setTimeout(() => cancellation.abort(), 50)
  const cancelled = await cancelledPromise
  clearTimeout(cancelTimer)
  assert.equal(finite.exitCode, 0, 'finite child failed')
  assert.equal(finite.stdout.trim(), 'ok', 'finite child output failed')
  assert.equal(finite.status, 'exited', 'finite child status failed')
  assertResultSchema(timedOut, 'timed out')
  assert.equal(timedOut.timedOut, true, 'hanging child did not time out')
  assert.equal(timedOut.status, 'timed_out', 'timed out status was overwritten')
  assert.equal(
    timedOut.directChildCleanupConfirmed,
    true,
    'timed out direct child cleanup was not confirmed'
  )
  assertResultSchema(cancelled, 'cancelled')
  assert.equal(cancelled.cancelled, true, 'aborted child was not cancelled')
  assert.equal(cancelled.status, 'cancelled', 'cancelled status was overwritten')
  assert.equal(cancelled.timedOut, false, 'aborted child timed out')
  assert.equal(
    cancelled.directChildCleanupAttempted,
    true,
    'aborted direct child cleanup was not attempted'
  )
  assert.equal(
    cancelled.directChildCleanupConfirmed,
    true,
    'aborted direct child cleanup was not confirmed'
  )
  const preAbort = new AbortController()
  preAbort.abort()
  const preAborted = await runWithTimeout({
    command: process.execPath,
    timeoutMs: 2_500,
    signal: preAbort.signal,
  })
  assertResultSchema(preAborted, 'pre-aborted')
  assert.equal(preAborted.status, 'cancelled', 'pre-aborted status failed')
  assert.equal(preAborted.cancelled, true, 'pre-aborted child was not cancelled')
  process.stdout.write(`${JSON.stringify({ ok: true, finite, timedOut, cancelled })}\n`)
}

const controller = new AbortController()
const cancel = () => controller.abort()
process.once('SIGINT', cancel)
process.once('SIGTERM', cancel)
try {
  if (process.argv[2] === '--self-test') {
    await selfTest(controller.signal)
  } else {
    const input = JSON.parse(process.argv[2] ?? readFileSync(0, 'utf8'))
    process.stdout.write(
      `${JSON.stringify(await runWithTimeout({ ...input, signal: controller.signal }))}\n`
    )
  }
} catch (error) {
  process.stdout.write(
    `${JSON.stringify({ error: error instanceof Error ? error.message : String(error) })}\n`
  )
  process.exitCode = 1
} finally {
  process.removeListener('SIGINT', cancel)
  process.removeListener('SIGTERM', cancel)
}
