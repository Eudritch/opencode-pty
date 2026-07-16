import type { PluginClient } from '../types.ts'
import { match } from './wildcard.ts'
import { realpath } from 'node:fs/promises'
import { isAbsolute, relative, sep } from 'node:path'

type PermissionAction = 'allow' | 'ask' | 'deny'
type PermissionRule = PermissionAction | Record<string, PermissionAction>
type PermissionConfig = PermissionAction | Record<string, PermissionRule>

interface Config {
  permission?: PermissionConfig
  agent?: Record<string, { permission?: PermissionConfig }>
}

export type SpawnAuthorizer = (
  command: string,
  args: string[],
  workdir?: string,
  agent?: string
) => Promise<string>

export type BashAuthorizer = (
  command: string,
  workdir?: string,
  agent?: string
) => Promise<{ action: PermissionAction; workdir: string }>

// ponytail: SDK 1.3.13 has no permission evaluator/request API, so this local adapter fails closed.
export function createSpawnAuthorizer(client: PluginClient, directory: string): SpawnAuthorizer {
  return async (command, args, workdir, agent) => {
    const permissions = await permissionConfig(client)
    const action = evaluate(permissions, agent, 'bash', [command, ...args].join(' '))
    if (action !== 'allow') {
      return deny(
        client,
        `PTY spawn denied: Command "${[command, ...args].join(' ')}" has no explicit allow rule.`
      )
    }
    return authorizeWorkdir(client, permissions, directory, workdir, agent)
  }
}

// Shell input stays opaque: policy matching sees the unmodified original string.
export function createBashAuthorizer(client: PluginClient, directory: string): BashAuthorizer {
  return async (command, workdir, agent) => {
    const permissions = await permissionConfig(client)
    const action = evaluate(permissions, agent, 'bash', command)
    if (!action || action === 'deny')
      return deny(client, 'Bash command denied: no explicit allow rule.')
    return {
      action,
      workdir: await authorizeWorkdir(client, permissions, directory, workdir, agent),
    }
  }
}

async function permissionConfig(client: PluginClient): Promise<Config> {
  try {
    const response = await client.config.get()
    if (response.error || !response.data) throw new Error('unavailable')
    return parseConfig(response.data)
  } catch {
    throw new Error('PTY spawn denied: permission configuration is unavailable.')
  }
}

async function deny(client: PluginClient, message: string): Promise<never> {
  try {
    await client.tui.showToast({ body: { message, variant: 'error' } })
  } catch {
    // A failed notification must not weaken the policy decision.
  }
  throw new Error(message)
}

async function authorizeWorkdir(
  client: PluginClient,
  permissions: Config,
  directory: string,
  workdir: string | undefined,
  agent: string | undefined
): Promise<string> {
  let resolvedPaths: [string, string]
  try {
    resolvedPaths = await Promise.all([realpath(workdir ?? directory), realpath(directory)])
  } catch {
    return deny(client, 'PTY spawn denied: unable to verify the working directory.')
  }
  const [resolvedWorkdir, resolvedProject] = resolvedPaths
  const pathToWorkdir = relative(resolvedProject, resolvedWorkdir)
  const outside =
    pathToWorkdir === '..' || pathToWorkdir.startsWith(`..${sep}`) || isAbsolute(pathToWorkdir)
  if (!outside) return resolvedWorkdir
  if (evaluate(permissions, agent, 'external_directory', resolvedWorkdir) === 'allow')
    return resolvedWorkdir
  return deny(
    client,
    `PTY spawn denied: Working directory "${workdir}" is outside project directory "${directory}" without explicit external_directory allow.`
  )
}

function parseConfig(value: unknown): Config {
  if (!record(value)) throw new Error('invalid')
  const permission = value.permission === undefined ? undefined : parsePermission(value.permission)
  if (value.agent === undefined) return { permission }
  if (!record(value.agent)) throw new Error('invalid')
  const agent: Config['agent'] = {}
  for (const [name, definition] of Object.entries(value.agent)) {
    if (!record(definition)) throw new Error('invalid')
    agent[name] = {
      permission:
        definition.permission === undefined ? undefined : parsePermission(definition.permission),
    }
  }
  return { permission, agent }
}

function parsePermission(value: unknown): PermissionConfig {
  if (action(value)) return value
  if (!record(value)) throw new Error('invalid')
  const result: Record<string, PermissionRule> = {}
  for (const [permission, rule] of Object.entries(value)) {
    if (action(rule)) result[permission] = rule
    else if (record(rule) && Object.values(rule).every(action))
      result[permission] = rule as Record<string, PermissionAction>
    else throw new Error('invalid')
  }
  return result
}

function evaluate(config: Config, agent: string | undefined, permission: string, input: string) {
  let result: PermissionAction | undefined
  for (const rules of [config.permission, agent ? config.agent?.[agent]?.permission : undefined]) {
    if (!rules) continue
    for (const rule of rulesFor(rules)) {
      if (match(permission, rule.permission) && match(input, rule.pattern)) result = rule.action
    }
  }
  return result
}

function* rulesFor(permission: PermissionConfig): Generator<{
  permission: string
  pattern: string
  action: PermissionAction
}> {
  if (action(permission)) {
    yield { permission: '*', pattern: '*', action: permission }
    return
  }
  for (const [key, rule] of Object.entries(permission)) {
    if (action(rule)) yield { permission: key, pattern: '*', action: rule }
    else
      for (const [pattern, action] of Object.entries(rule))
        yield { permission: key, pattern, action }
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function action(value: unknown): value is PermissionAction {
  return value === 'allow' || value === 'ask' || value === 'deny'
}
