import { existsSync, watch } from 'node:fs'
import { readFile, rename, writeFile } from 'node:fs/promises'
import { basename, relative, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

type PluginResult = Record<string, unknown> & {
  tool?: Record<string, ToolDefinition>
}

type ToolDefinition = Record<string, unknown> & {
  execute?: (...args: unknown[]) => unknown
}

type Checkpoint = {
  schemaVersion: 1
  revision: string
  entry: string
  workerPath: string
  verifiedAt: string
}

const root = resolve(import.meta.dir, '../..')
const checkpointRoot = resolve(root, '.opencode-pty-checkpoints')
const runtimeRoot = resolve(root, '.opencode-pty-runtime')
const checkpointPath = resolve(root, '.opencode/opencode-pty-checkpoint.json')
const runtimePath = resolve(root, '.opencode/opencode-pty-checkpoint-runtime.json')
const watchers = new Set<ReturnType<typeof watch>>()

function insideCheckpointRoot(path: string): boolean {
  const pathRelative = relative(checkpointRoot, path)
  return pathRelative !== '' && !pathRelative.startsWith('..') && !pathRelative.includes(':')
}

async function readCheckpoint(): Promise<Checkpoint> {
  const parsed: unknown = JSON.parse(await readFile(checkpointPath, 'utf8'))
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    (parsed as Partial<Checkpoint>).schemaVersion !== 1 ||
    typeof (parsed as Partial<Checkpoint>).revision !== 'string' ||
    typeof (parsed as Partial<Checkpoint>).entry !== 'string' ||
    typeof (parsed as Partial<Checkpoint>).workerPath !== 'string' ||
    typeof (parsed as Partial<Checkpoint>).verifiedAt !== 'string'
  ) {
    throw new Error('Checkpoint manifest is invalid.')
  }
  const checkpoint = parsed as Checkpoint
  const entry = resolve(root, checkpoint.entry)
  const workerPath = resolve(root, checkpoint.workerPath)
  if (!insideCheckpointRoot(entry) || !insideCheckpointRoot(workerPath) || !existsSync(entry))
    throw new Error('Checkpoint manifest points outside a staged checkpoint.')
  if (!existsSync(workerPath))
    throw new Error('Checkpoint worker is missing. Run checkpoint verify.')
  return checkpoint
}

async function writeRuntime(state: Record<string, string>): Promise<void> {
  const temporary = `${runtimePath}.${process.pid}.${Date.now()}.tmp`
  await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`)
  await rename(temporary, runtimePath)
}

function contract(result: PluginResult): string {
  const tools = Object.entries(result.tool ?? {})
    .map(
      ([name, definition]) =>
        `${name}:${Object.keys((definition.args as object) ?? {})
          .sort()
          .join(',')}`
    )
    .sort()
  const hooks = Object.keys(result)
    .filter((key) => key !== 'tool')
    .sort()
  return JSON.stringify({ hooks, tools })
}

export const OpencodePtyCheckpoint = async (context: unknown, options: unknown = {}) => {
  let active: PluginResult
  let activeContract = ''
  let activeRevision = ''
  let queued = Promise.resolve()

  const load = async () => {
    const checkpoint = await readCheckpoint()
    const entry = resolve(root, checkpoint.entry)
    const workerPath = resolve(root, checkpoint.workerPath)
    process.env.PTY_DAEMON_DIR = runtimeRoot
    const module = await import(`${pathToFileURL(entry).href}?checkpoint=${checkpoint.revision}`)
    const factory = module.PTYPlugin ?? module.server ?? module.default
    if (typeof factory !== 'function')
      throw new Error('Checkpoint does not export an OpenCode plugin.')
    const next = (await factory(context, options)) as PluginResult
    const nextContract = contract(next)
    if (activeContract && nextContract !== activeContract)
      throw new Error(
        'Checkpoint changes the static plugin contract; restart OpenCode to apply it.'
      )
    process.env.PTY_NATIVE_WORKER_PATH = workerPath
    active = next
    activeContract = nextContract
    activeRevision = checkpoint.revision
    await writeRuntime({ revision: checkpoint.revision, loadedAt: new Date().toISOString() }).catch(
      () => undefined
    )
  }

  await load()

  const initial = active
  const proxiedTools = Object.fromEntries(
    Object.entries(initial.tool ?? {}).map(([name, definition]) => [
      name,
      {
        ...definition,
        execute: async (...args: unknown[]) => {
          const current = active.tool?.[name]
          if (!current?.execute)
            throw new Error(`Checkpoint does not provide the registered '${name}' tool.`)
          return current.execute(...args)
        },
      },
    ])
  )
  const result: PluginResult = { tool: proxiedTools }
  for (const [name, definition] of Object.entries(initial)) {
    if (name === 'tool') continue
    result[name] =
      typeof definition === 'function'
        ? async (...args: unknown[]) => {
            const current = active[name]
            if (typeof current !== 'function') return
            return current(...args)
          }
        : definition
  }

  // Watch the directory because Windows can replace the manifest during an atomic activation.
  const watcher = watch(resolve(root, '.opencode'), { persistent: false }, (_event, changed) => {
    if (!changed || basename(changed.toString()) !== basename(checkpointPath)) return
    queued = queued
      .catch(() => undefined)
      .then(() => Bun.sleep(50))
      .then(load)
      .catch(async (error) => {
        await writeRuntime({
          revision: activeRevision || 'none',
          failedAt: new Date().toISOString(),
          error: error instanceof Error ? error.message : String(error),
        }).catch(() => undefined)
      })
  })
  watchers.add(watcher)
  return result
}

export const server = OpencodePtyCheckpoint
