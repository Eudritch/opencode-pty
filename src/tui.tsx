import type { TuiPlugin, TuiPluginApi } from '@opencode-ai/plugin/tui'
import { createSignal, onCleanup } from 'solid-js'
import type { ApprovalGrant, ApprovalRequest } from './daemon/types.ts'
import { manager } from './plugin/pty/manager.ts'
import type { PTYSessionInfo } from './plugin/pty/types.ts'
import {
  approvalSummary,
  grantSummary,
  ownerForRoute,
  sessionCard,
  type TuiSession,
} from './tui-state.ts'

const POLL_MS = 5_000

type TuiStateWithSession = TuiPluginApi['state'] & {
  session: TuiPluginApi['state']['session'] & { get: (sessionID: string) => TuiSession | undefined }
}

interface PanelState {
  sessions: PTYSessionInfo[]
  requests: ApprovalRequest[]
  grants: ApprovalGrant[]
  error?: string
}

function currentOwner(api: TuiPluginApi) {
  const state = api.state as TuiStateWithSession
  const route = api.route.current
  const sessionID = route.name === 'session' ? route.params?.sessionID : undefined
  if (typeof sessionID !== 'string') return undefined
  return ownerForRoute(route, state.session.get(sessionID))
}

async function reviewApprovals(api: TuiPluginApi): Promise<void> {
  const owner = currentOwner(api)
  if (!owner) {
    api.ui.toast({ variant: 'warning', message: 'Open a session before reviewing PTY approvals.' })
    return
  }
  try {
    const [requests, grants] = await Promise.all([
      manager.listApprovalRequests(owner),
      manager.listApprovalGrants(owner),
    ])
    const { DialogConfirm, DialogSelect } = api.ui
    api.ui.dialog.replace(() => (
      <DialogSelect
        title="PTY approvals"
        placeholder="Review pending requests or revoke a session grant"
        options={[
          ...requests.map((request) => ({
            title: approvalSummary(request),
            value: request.id,
            description: request.reason ?? 'Native approval prompt remains authoritative.',
            disabled: true,
          })),
          ...grants.map((grant) => ({
            title: `Revoke: ${grantSummary(grant)}`,
            value: grant.id,
            description: `Expires ${grant.expiresAt}`,
            onSelect: () =>
              api.ui.dialog.replace(() => (
                <DialogConfirm
                  title="Revoke PTY approval"
                  message={grantSummary(grant)}
                  onConfirm={() => {
                    void (async () => {
                      const actionOwner = currentOwner(api)
                      if (!actionOwner)
                        throw new Error('Open the owning session before revoking its grant.')
                      await manager.revokeApprovalGrant(grant.id, actionOwner)
                      await reviewApprovals(api)
                    })().catch((error) =>
                      api.ui.toast({ variant: 'error', message: errorMessage(error) })
                    )
                  }}
                />
              )),
          })),
        ]}
      />
    ))
  } catch (error) {
    api.ui.toast({ variant: 'error', message: errorMessage(error) })
  }
}

function PtyPanel(props: { api: TuiPluginApi; sessionID: string }) {
  const [state, setState] = createSignal<PanelState>({ sessions: [], requests: [], grants: [] })
  let stopped = false
  const refresh = async () => {
    const owner = currentOwner(props.api)
    if (stopped || !owner || owner.parentSessionId !== props.sessionID) return
    try {
      const [sessions, requests, grants] = await Promise.all([
        manager.list(owner),
        manager.listApprovalRequests(owner),
        manager.listApprovalGrants(owner),
      ])
      if (!stopped) setState({ sessions, requests, grants })
    } catch (error) {
      if (!stopped) setState({ sessions: [], requests: [], grants: [], error: errorMessage(error) })
    }
  }
  void refresh()
  const timer = setInterval(() => void refresh(), POLL_MS)
  onCleanup(() => {
    stopped = true
    clearInterval(timer)
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
          <text fg={props.api.theme.current.warning}>{approvalSummary(request)}</text>
        ))
      }
      {() => state().grants.map((grant) => <text>{`grant | ${grantSummary(grant)}`}</text>)}
    </box>
  )
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'PTY companion request failed.'
}

export const tui: TuiPlugin = async (api) => {
  api.command.register(() => [
    {
      title: 'PTY approvals',
      value: 'opencode-pty.approvals',
      description: 'Review pending PTY approvals and revoke session grants',
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
