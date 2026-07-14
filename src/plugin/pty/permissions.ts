import type { PluginClient } from '../types.ts'
import { allStructured } from './wildcard.ts'
import { realpath } from 'node:fs/promises'
import { relative } from 'node:path'

type PermissionAction = 'allow' | 'ask' | 'deny'
type BashPermissions = PermissionAction | Record<string, PermissionAction>

interface PermissionConfig {
  bash?: BashPermissions
  external_directory?: PermissionAction
}

let _client: PluginClient | null = null
let _directory: string | null = null

export function initPermissions(client: PluginClient, directory: string): void {
  _client = client
  _directory = directory
}

async function getPermissionConfig(): Promise<PermissionConfig> {
  if (!_client) {
    throw new Error('PTY spawn denied: permission configuration is unavailable.')
  }
  try {
    const response = await _client.config.get()
    if (response.error || !response.data) {
      throw new Error('PTY spawn denied: permission configuration is unavailable.')
    }
    return (response.data as { permission?: PermissionConfig }).permission ?? {}
  } catch {
    throw new Error('PTY spawn denied: permission configuration is unavailable.')
  }
}

async function showToast(
  message: string,
  variant: 'info' | 'success' | 'error' = 'info'
): Promise<void> {
  if (!_client) return
  try {
    await _client.tui.showToast({ body: { message, variant } })
  } catch {
    // Ignore toast errors
  }
}

async function denyWithToast(msg: string, details?: string): Promise<never> {
  await showToast(msg, 'error')
  throw new Error(details ? `${msg} ${details}` : msg)
}

async function handleAskPermission(commandLine: string): Promise<never> {
  await denyWithToast(
    `PTY: Command "${commandLine}" requires permission (treated as denied)`,
    `PTY spawn denied: Command "${commandLine}" requires user permission which is not supported by this plugin. Configure explicit "allow" or "deny" in your opencode.json permission.bash settings.`
  )
  throw new Error('Unreachable') // For TS, should never hit.
}

export async function checkCommandPermission(command: string, args: string[]): Promise<void> {
  const config = await getPermissionConfig()
  const bashPerms = config.bash

  if (!bashPerms) {
    return
  }

  if (typeof bashPerms === 'string') {
    if (bashPerms === 'deny') {
      await denyWithToast('PTY spawn denied: All bash commands are disabled by user configuration.')
    }
    if (bashPerms === 'ask') {
      await handleAskPermission(command)
    }
    return
  }

  const action = allStructured({ head: command, tail: args }, bashPerms)

  if (action === 'deny') {
    await denyWithToast(
      `PTY spawn denied: Command "${command} ${args.join(' ')}" is explicitly denied by user configuration.`
    )
  }

  if (action === 'ask') {
    await handleAskPermission(`${command} ${args.join(' ')}`)
  }
}

export async function checkWorkdirPermission(workdir?: string): Promise<string> {
  if (!_directory) {
    throw new Error('PTY spawn denied: project directory is unavailable.')
  }
  const requestedWorkdir = workdir ?? _directory
  let resolvedPaths: [string, string]
  try {
    resolvedPaths = await Promise.all([realpath(requestedWorkdir), realpath(_directory)])
  } catch {
    return denyWithToast('PTY spawn denied: unable to verify the working directory.')
  }
  const [resolvedWorkdir, resolvedProject] = resolvedPaths
  const pathToWorkdir = relative(resolvedProject, resolvedWorkdir)
  if (pathToWorkdir === '' || (!pathToWorkdir.startsWith('..') && !pathToWorkdir.includes(':'))) {
    return resolvedWorkdir
  }

  const config = await getPermissionConfig()
  const extDirPerm = config.external_directory

  if (extDirPerm === 'deny') {
    await denyWithToast(
      `PTY spawn denied: Working directory "${workdir}" is outside project directory "${_directory}". External directory access is denied by user configuration.`
    )
  }

  if (extDirPerm === 'ask') {
    await denyWithToast(
      `PTY spawn denied: Working directory "${workdir}" is outside project directory "${_directory}" and requires permission.`
    )
  }
  return resolvedWorkdir
}

// ponytail: one adapter keeps every daemon process launch behind the same policy boundary.
export async function authorizeSpawn(
  command: string,
  args: string[],
  workdir?: string
): Promise<string> {
  await checkCommandPermission(command, args)
  return checkWorkdirPermission(workdir)
}
