import type { ApprovalGrant, ApprovalRequest } from './daemon/types.ts'
import type { PTYSessionInfo } from './plugin/pty/types.ts'
import { ownerContext, type OwnerContext } from './plugin/pty/daemon-client.ts'

export interface TuiSession {
  id: string
  directory: string
}

export interface TuiScope {
  sessionID: string
  directory: string
}

export function scopeForRoute(
  route: { name: string; params?: Record<string, unknown> },
  directory: string
): TuiScope | undefined {
  const sessionID = route.name === 'session' ? route.params?.sessionID : undefined
  if (typeof sessionID !== 'string' || !directory) return undefined
  return { sessionID, directory }
}

export function scopeMatchesRoute(
  route: { name: string; params?: Record<string, unknown> },
  directory: string,
  scope: TuiScope
): boolean {
  const current = scopeForRoute(route, directory)
  return Boolean(
    current && current.sessionID === scope.sessionID && current.directory === scope.directory
  )
}

export function ownerForRoute(
  route: { name: string; params?: Record<string, unknown> },
  session: TuiSession | undefined,
  activeDirectory?: string
): OwnerContext | undefined {
  const sessionID = route.name === 'session' ? route.params?.sessionID : undefined
  if (typeof sessionID !== 'string' || !session || session.id !== sessionID || !session.directory)
    return undefined
  const owner = ownerContext(sessionID, session.directory)
  if (
    activeDirectory &&
    ownerContext(sessionID, activeDirectory).projectDirectory !== owner.projectDirectory
  ) {
    return undefined
  }
  return owner
}

export function ownerMatchesRoute(
  route: { name: string; params?: Record<string, unknown> },
  activeDirectory: string,
  owner: OwnerContext
): boolean {
  const sessionID = route.name === 'session' ? route.params?.sessionID : undefined
  if (typeof sessionID !== 'string' || sessionID !== owner.parentSessionId || !activeDirectory)
    return false
  return ownerContext(sessionID, activeDirectory).projectDirectory === owner.projectDirectory
}

export function canClaimApproval(request: ApprovalRequest): boolean {
  return (
    request.status === 'pending' &&
    request.uiEligible === true &&
    Date.parse(request.uiExpiresAt ?? '') > Date.now()
  )
}

export function isApprovalClaim(value: unknown): value is {
  request: ApprovalRequest
  claimToken: string
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const claim = value as Record<string, unknown>
  return (
    typeof claim.claimToken === 'string' &&
    Boolean(claim.claimToken) &&
    Boolean(claim.request) &&
    typeof claim.request === 'object' &&
    (claim.request as ApprovalRequest).status === 'claimed' &&
    typeof (claim.request as ApprovalRequest).id === 'string'
  )
}

function secretValue(): string {
  return '[REDACTED]'
}

export function commandPreview(command: string, args: string[]): string {
  return redactPreview(`${command} ${args.join(' ')}`)
}

export function redactPreview(value: string): string {
  const sensitiveName =
    '(?:[a-z0-9_-]*(?:token|secret|password|pass|api[-_]?key|key|session(?:[-_]?id)?))'
  const secret = '(?:\'[^\']*\'|"[^"]*"|[^\\s]+)'
  return value
    .replace(/\b((?:set-)?cookie\s*:\s*)[^\r\n]*/gi, (_, prefix) => `${prefix}${secretValue()}`)
    .replace(
      new RegExp(
        `\\b((?:authorization|proxy-authorization|${sensitiveName})\\s*:\\s*(?:(?:bearer|basic)\\s*)?)(?:'[^']*'|"[^"]*"|[^\\s'"]+)`,
        'gi'
      ),
      (_, prefix) => `${prefix}${secretValue()}`
    )
    .replace(
      /([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+(?::[^\s/@]*)?@/gi,
      (_, prefix) => `${prefix}${secretValue()}@`
    )
    .replace(
      new RegExp(`([?&]${sensitiveName}=)${secret}`, 'gi'),
      (_, prefix) => `${prefix}${secretValue()}`
    )
    .replace(
      new RegExp(`(--${sensitiveName}=)${secret}`, 'gi'),
      (_, prefix) => `${prefix}${secretValue()}`
    )
    .replace(
      new RegExp(`(--${sensitiveName}\\s+)${secret}`, 'gi'),
      (_, prefix) => `${prefix}${secretValue()}`
    )
    .replace(
      new RegExp(`((?:export\\s+|set\\s+)?${sensitiveName}\\s*=\\s*)${secret}`, 'gi'),
      (_, prefix) => `${prefix}${secretValue()}`
    )
    .replace(
      new RegExp(`(\\$env:${sensitiveName}\\s*=\\s*)${secret}`, 'gi'),
      (_, prefix) => `${prefix}${secretValue()}`
    )
    .replace(
      new RegExp(`(setenv\\s+${sensitiveName}\\s+)${secret}`, 'gi'),
      (_, prefix) => `${prefix}${secretValue()}`
    )
    .slice(0, 96)
}

export function sessionCard(session: PTYSessionInfo): string {
  const activity = session.mode === 'exec' ? 'foreground' : 'background'
  return [
    `opencode-pty | ${activity} | ${session.lifecycle}`,
    `${redactPreview(session.title)} | ${session.status}`,
    commandPreview(session.command, session.args),
  ].join('\n')
}

export function approvalSummary(request: ApprovalRequest): string {
  return `${request.status} | ${commandPreview(request.command, [])}`
}

export function approvalDetails(request: ApprovalRequest): string {
  return [
    `Command: ${commandPreview(request.command, [])}`,
    `Reason: ${request.reason ? redactPreview(request.reason) : 'Not provided'}`,
    `Workdir: ${redactPreview(request.workdir)}`,
  ].join('\n')
}

export function grantSummary(grant: ApprovalGrant): string {
  return redactPreview(grant.workdir)
}
