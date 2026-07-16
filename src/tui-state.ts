import type { ApprovalGrant, ApprovalRequest } from './daemon/types.ts'
import type { PTYSessionInfo } from './plugin/pty/types.ts'
import { ownerContext, type OwnerContext } from './plugin/pty/daemon-client.ts'

export interface TuiSession {
  id: string
  directory: string
}

export function ownerForRoute(
  route: { name: string; params?: Record<string, unknown> },
  session: TuiSession | undefined
): OwnerContext | undefined {
  const sessionID = route.name === 'session' ? route.params?.sessionID : undefined
  if (typeof sessionID !== 'string' || !session || session.id !== sessionID || !session.directory)
    return undefined
  return ownerContext(sessionID, session.directory)
}

export function commandPreview(command: string, args: string[]): string {
  return `${command} ${args.join(' ')}`
    .replace(/([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY)\s*=\s*)[^\s]+/g, '$1[REDACTED]')
    .replace(/(--?(?:token|secret|password|key)\s+)[^\s]+/gi, '$1[REDACTED]')
    .slice(0, 96)
}

export function sessionCard(session: PTYSessionInfo): string {
  const activity = session.mode === 'exec' ? 'foreground' : 'background'
  return [
    `opencode-pty | ${activity} | ${session.lifecycle}`,
    `${session.title} | ${session.status}`,
    commandPreview(session.command, session.args),
  ].join('\n')
}

export function approvalSummary(request: ApprovalRequest): string {
  return `${request.status} | ${request.capability} | ${commandPreview(request.command, [])}`
}

export function grantSummary(grant: ApprovalGrant): string {
  return `${grant.capability} | ${grant.workdir}`
}
