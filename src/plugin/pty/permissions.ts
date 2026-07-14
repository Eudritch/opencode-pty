import type { PluginClient } from '../types.ts'
import { allStructured } from './wildcard.ts'
import { realpath } from 'node:fs/promises'
import { isAbsolute, relative, sep } from 'node:path'

type PermissionAction = 'allow' | 'ask' | 'deny'
type BashPermissions = PermissionAction | Record<string, PermissionAction>

interface PermissionConfig {
  bash?: BashPermissions
  external_directory?: PermissionAction
}

export type SpawnAuthorizer = (command: string, args: string[], workdir?: string) => Promise<string>

// ponytail: SDK 1.3.13 has no permission evaluator/request API, so this local adapter fails closed.
export function createSpawnAuthorizer(client: PluginClient, directory: string): SpawnAuthorizer {
  const config = async (): Promise<PermissionConfig> => {
    try {
      const response = await client.config.get()
      if (response.error || !response.data) throw new Error('unavailable')
      return (response.data as { permission?: PermissionConfig }).permission ?? {}
    } catch {
      throw new Error('PTY spawn denied: permission configuration is unavailable.')
    }
  }
  const deny = async (message: string): Promise<never> => {
    try {
      await client.tui.showToast({ body: { message, variant: 'error' } })
    } catch {
      // A failed notification must not weaken the policy decision.
    }
    throw new Error(message)
  }
  return async (command, args, workdir) => {
    const bash = (await config()).bash
    const action =
      typeof bash === 'object' && bash ? allStructured({ head: command, tail: args }, bash) : bash
    if (action !== 'allow') {
      return deny(
        `PTY spawn denied: Command "${[command, ...args].join(' ')}" has no explicit allow rule.`
      )
    }
    let resolvedPaths: [string, string]
    try {
      resolvedPaths = await Promise.all([realpath(workdir ?? directory), realpath(directory)])
    } catch {
      return deny('PTY spawn denied: unable to verify the working directory.')
    }
    const [resolvedWorkdir, resolvedProject] = resolvedPaths
    const pathToWorkdir = relative(resolvedProject, resolvedWorkdir)
    const outside =
      pathToWorkdir === '..' || pathToWorkdir.startsWith(`..${sep}`) || isAbsolute(pathToWorkdir)
    if (!outside) return resolvedWorkdir
    if ((await config()).external_directory === 'allow') return resolvedWorkdir
    return deny(
      `PTY spawn denied: Working directory "${workdir}" is outside project directory "${directory}" without explicit external_directory allow.`
    )
  }
}
