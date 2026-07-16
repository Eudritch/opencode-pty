import type { TuiPlugin, TuiPluginApi } from '@opencode-ai/plugin/tui'
import { createEffect, createSignal, onCleanup } from 'solid-js'
import type { ApprovalGrant, ApprovalRequest } from './daemon/types.ts'
import { manager } from './plugin/pty/manager.ts'
import type { PTYSessionInfo } from './plugin/pty/types.ts'
import {
  approvalDetails,
  approvalSummary,
  grantSummary,
  isApprovalClaim,
  ownerMatchesRoute,
  ownerForRoute,
  sessionCard,
  scopeForRoute,
  scopeMatchesRoute,
  canClaimApproval,
  type TuiScope,
} from './tui-state.ts'

const POLL_MS = 5_000

interface PanelState {
  sessions: PTYSessionInfo[]
  requests: ApprovalRequest[]
  grants: ApprovalGrant[]
  error?: string
}

function isCurrentOwner(api: TuiPluginApi, owner: ReturnType<typeof ownerForRoute>): boolean {
  return Boolean(owner && ownerMatchesRoute(api.route.current, api.state.path.directory, owner))
}

function currentScope(api: TuiPluginApi, expectedSessionID?: string): TuiScope | undefined {
  const scope = scopeForRoute(api.route.current, api.state.path.directory)
  return scope && (!expectedSessionID || scope.sessionID === expectedSessionID) ? scope : undefined
}

function scopeIsCurrent(api: TuiPluginApi, scope: TuiScope): boolean {
  return scopeMatchesRoute(api.route.current, api.state.path.directory, scope)
}

async function currentOwner(api: TuiPluginApi, scope = currentScope(api)) {
  if (!scope) return undefined
  const route = api.route.current
  const result = await api.client.session.get({ sessionID: scope.sessionID })
  const owner = ownerForRoute(route, result.data, scope.directory)
  return scopeIsCurrent(api, scope) && isCurrentOwner(api, owner) ? owner : undefined
}

async function reviewApprovals(api: TuiPluginApi): Promise<void> {
  const scope = currentScope(api)
  const owner = await currentOwner(api, scope)
  if (!owner) {
    api.ui.toast({ variant: 'warning', message: 'Open a session before reviewing PTY approvals.' })
    return
  }
  try {
    const [requests, grants] = await Promise.all([
      manager.listApprovalRequests(owner),
      manager.listApprovalGrants(owner),
    ])
    if (!scope || !dialogIsCurrent(api, scope, owner)) return
    const { DialogSelect } = api.ui
    api.ui.dialog.replace(() => (
      <DialogSelect
        title="Advanced PTY approvals"
        placeholder="Advanced PTY approvals only; native Bash is not controlled here"
        options={[
          ...requests.map((request) => approvalOption(api, owner, scope, request)),
          ...grants.map((grant) => ({
            title: `Revoke: ${grantSummary(grant)}`,
            value: grant.id,
            description: `Expires ${grant.expiresAt}`,
            onSelect: () => api.ui.dialog.replace(() => revokeDialog(api, owner, scope, grant)),
          })),
        ]}
      />
    ))
  } catch (error) {
    api.ui.dialog.clear()
    api.ui.toast({ variant: 'error', message: errorMessage(error) })
  }
}

function revokeDialog(
  api: TuiPluginApi,
  owner: NonNullable<ReturnType<typeof ownerForRoute>>,
  scope: TuiScope,
  grant: ApprovalGrant
) {
  const { DialogConfirm } = api.ui
  return (
    <DialogConfirm
      title="Revoke PTY approval"
      message={grantSummary(grant)}
      onConfirm={() => {
        void revokeGrant(api, owner, scope, grant.id)
      }}
    />
  )
}

async function revokeGrant(
  api: TuiPluginApi,
  owner: NonNullable<ReturnType<typeof ownerForRoute>>,
  scope: TuiScope,
  id: string
): Promise<void> {
  try {
    const actionOwner = await currentOwner(api, scope)
    if (!actionOwner || !scopeIsCurrent(api, scope) || !sameOwner(actionOwner, owner))
      throw new Error('Open the owning session before revoking its grant.')
    await manager.revokeApprovalGrant(id, actionOwner)
    if (!dialogIsCurrent(api, scope, actionOwner)) return
    await reviewApprovals(api)
  } catch (error) {
    api.ui.dialog.clear()
    api.ui.toast({ variant: 'error', message: errorMessage(error) })
  }
}

function approvalOption(
  api: TuiPluginApi,
  owner: NonNullable<ReturnType<typeof ownerForRoute>>,
  scope: TuiScope,
  request: ApprovalRequest
) {
  const claimable = canClaimApproval(request)
  return {
    title: claimable ? `Claim: ${approvalSummary(request)}` : approvalSummary(request),
    value: request.id,
    description: `${approvalDetails(request)}\n\n${claimable ? 'Available briefly before native fallback.' : 'Native OpenCode approval remains authoritative.'}`,
    disabled: !claimable,
    onSelect: claimable ? () => void claimApproval(api, owner, scope, request.id) : undefined,
  }
}

async function claimApproval(
  api: TuiPluginApi,
  owner: NonNullable<ReturnType<typeof ownerForRoute>>,
  scope: TuiScope,
  id: string
): Promise<void> {
  try {
    const actionOwner = await currentOwner(api, scope)
    if (!actionOwner || !sameOwner(actionOwner, owner)) return api.ui.dialog.clear()
    const result = await manager.claimApproval(id, actionOwner)
    if (!dialogIsCurrent(api, scope, actionOwner)) return
    if (!isApprovalClaim(result) || result.request.id !== id) {
      api.ui.dialog.clear()
      return api.ui.toast({ variant: 'warning', message: 'Approval is no longer available.' })
    }
    const { DialogSelect } = api.ui
    let deciding = false
    api.ui.dialog.replace(() => (
      <DialogSelect
        title="Decide PTY approval"
        placeholder="Choose a safe approval decision"
        options={(['approve_once', 'approve_session', 'reject'] as const).map((decision) => ({
          title:
            decision === 'approve_once'
              ? 'Approve once'
              : decision === 'approve_session'
                ? 'Approve session'
                : 'Reject',
          value: decision,
          onSelect: () => {
            if (deciding) return
            deciding = true
            void decideApproval(api, owner, scope, id, result.claimToken, decision).finally(() => {
              deciding = false
            })
          },
        }))}
      />
    ))
  } catch (error) {
    api.ui.dialog.clear()
    api.ui.toast({ variant: 'error', message: errorMessage(error) })
  }
}

async function decideApproval(
  api: TuiPluginApi,
  owner: NonNullable<ReturnType<typeof ownerForRoute>>,
  scope: TuiScope,
  id: string,
  claimToken: string,
  decision: 'approve_once' | 'approve_session' | 'reject'
): Promise<void> {
  try {
    const actionOwner = await currentOwner(api, scope)
    if (!actionOwner || !sameOwner(actionOwner, owner)) return api.ui.dialog.clear()
    await manager.decideApproval(id, decision, claimToken, actionOwner)
    if (!dialogIsCurrent(api, scope, actionOwner)) return
    await reviewApprovals(api)
  } catch (error) {
    api.ui.dialog.clear()
    api.ui.toast({ variant: 'error', message: errorMessage(error) })
  }
}

function PtyPanel(props: { api: TuiPluginApi; sessionID: string }) {
  const [state, setState] = createSignal<PanelState>({ sessions: [], requests: [], grants: [] })
  let displayedOwner: ReturnType<typeof ownerForRoute>
  let timer: ReturnType<typeof setInterval> | undefined
  let stopped = false
  const clear = () => {
    displayedOwner = undefined
    setState({ sessions: [], requests: [], grants: [] })
  }
  const refresh = async (scope = currentScope(props.api, props.sessionID)) => {
    if (stopped) return
    try {
      if (!scope || props.sessionID !== scope.sessionID || !scopeIsCurrent(props.api, scope)) {
        clear()
        return
      }
      if (displayedOwner && !isCurrentOwner(props.api, displayedOwner)) clear()
      const owner = await currentOwner(props.api, scope)
      if (!owner) {
        clear()
        return
      }
      if (displayedOwner && !sameOwner(displayedOwner, owner)) clear()
      const [sessions, requests, grants] = await Promise.all([
        manager.list(owner),
        manager.listApprovalRequests(owner),
        manager.listApprovalGrants(owner),
      ])
      if (
        stopped ||
        props.sessionID !== scope.sessionID ||
        !scopeIsCurrent(props.api, scope) ||
        !isCurrentOwner(props.api, owner)
      ) {
        return
      }
      displayedOwner = owner
      setState({ sessions, requests, grants })
    } catch (error) {
      if (
        !stopped &&
        scope &&
        props.sessionID === scope.sessionID &&
        scopeIsCurrent(props.api, scope) &&
        displayedOwner &&
        isCurrentOwner(props.api, displayedOwner)
      ) {
        setState({ sessions: [], requests: [], grants: [], error: errorMessage(error) })
      }
    }
  }
  createEffect(() => {
    const scope = currentScope(props.api, props.sessionID)
    props.api.state.path.directory
    if (timer) clearInterval(timer)
    timer = undefined
    if (!scope || (displayedOwner && !isCurrentOwner(props.api, displayedOwner))) clear()
    if (!scope) return
    void refresh(scope)
    timer = setInterval(() => void refresh(scope), POLL_MS)
  })
  onCleanup(() => {
    stopped = true
    if (timer) clearInterval(timer)
  })
  return (
    <box flexDirection="column" gap={1} border borderColor={props.api.theme.current.borderSubtle}>
      <text fg={props.api.theme.current.accent}>PTY companion</text>
      <text fg={props.api.theme.current.textMuted}>
        {() => `${state().sessions.length} sessions | ${state().requests.length} approvals`}
      </text>
      <text fg={props.api.theme.current.error}>{() => state().error ?? ''}</text>
      {() => state().sessions.map((session) => <text>{sessionCard(session)}</text>)}
      {() =>
        state().requests.map((request) => (
          <text fg={props.api.theme.current.warning}>{approvalDetails(request)}</text>
        ))
      }
      {() => state().grants.map((grant) => <text>{`grant | ${grantSummary(grant)}`}</text>)}
    </box>
  )
}

function errorMessage(error: unknown): string {
  void error
  return 'PTY companion request failed.'
}

function sameOwner(
  left: NonNullable<ReturnType<typeof ownerForRoute>>,
  right: NonNullable<ReturnType<typeof ownerForRoute>>
): boolean {
  return (
    left.parentSessionId === right.parentSessionId &&
    left.projectDirectory === right.projectDirectory
  )
}

function dialogIsCurrent(
  api: TuiPluginApi,
  scope: TuiScope,
  owner: NonNullable<ReturnType<typeof ownerForRoute>>
): boolean {
  const current = scopeIsCurrent(api, scope) && isCurrentOwner(api, owner)
  if (!current) api.ui.dialog.clear()
  return current
}

export const tui: TuiPlugin = async (api) => {
  api.command.register(() => [
    {
      title: 'Advanced PTY approvals',
      value: 'opencode-pty.approvals',
      description: 'Claim advanced PTY approvals and revoke their session grants',
      category: 'PTY',
      onSelect: () => void reviewApprovals(api),
    },
  ])
  api.slots.register({
    slots: {
      sidebar_content: (_context, props) => <PtyPanel api={api} sessionID={props.session_id} />,
    },
  })
}
