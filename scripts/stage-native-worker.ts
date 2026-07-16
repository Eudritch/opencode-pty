import { copyFile, rename, rm } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'

const RETRY_CODES = new Set(['EBUSY', 'EPERM', 'EACCES'])
const RETRY_MS = 10_000

type Operations = {
  copyFile?: (source: string, destination: string) => Promise<void>
  rename?: (source: string, destination: string) => Promise<void>
  remove?: (path: string) => Promise<void>
  sleep?: (milliseconds: number) => Promise<void>
  now?: () => number
}

function retryable(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && RETRY_CODES.has((error as NodeJS.ErrnoException).code ?? '')
}

export async function stageNativeWorker(
  source: string,
  destination: string,
  windows = process.platform === 'win32',
  operations: Operations = {}
) {
  const copy = operations.copyFile ?? copyFile
  if (!windows) return copy(source, destination)

  const replace = operations.rename ?? rename
  const remove = operations.remove ?? ((path: string) => rm(path, { force: true }))
  const sleep = operations.sleep ?? ((milliseconds: number) => Bun.sleep(milliseconds))
  const now = operations.now ?? Date.now
  const temporary = join(
    dirname(destination),
    `.${basename(destination)}.${crypto.randomUUID()}.tmp`
  )
  try {
    await copy(source, temporary)
    const deadline = now() + RETRY_MS
    let delay = 25
    for (;;) {
      try {
        await replace(temporary, destination)
        return
      } catch (error) {
        const remaining = deadline - now()
        if (!retryable(error) || remaining <= 0)
          throw new Error(
            `Could not replace staged native worker ${destination}: ${
              retryable(error) ? 'it remained locked for 10 seconds' : String(error)
            }. No process was forcibly terminated.`,
            { cause: error }
          )
        await sleep(Math.min(delay, remaining))
        delay = Math.min(delay * 2, 1_000)
      }
    }
  } finally {
    await remove(temporary)
  }
}
