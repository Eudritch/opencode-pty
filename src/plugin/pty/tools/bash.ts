import { tool, type ToolContext } from '@opencode-ai/plugin'
import { existsSync } from 'node:fs'
import {
  MAX_EXEC_RUNTIME_SECONDS,
  MAX_EXEC_WAIT_SECONDS,
  type ApprovalPreparation,
  type ApprovalRequest,
  type ExecResult,
} from '../../../daemon/types.ts'
import { ownerContext, type OwnerContext } from '../daemon-client.ts'
import { manager } from '../manager.ts'
import type { BashAuthorizer } from '../permissions.ts'
import { escapeXml } from '../xml.ts'

const DEFAULT_TIMEOUT_MS = 120_000
const APPROVAL_EXPIRY_SECONDS = MAX_EXEC_RUNTIME_SECONDS

interface BashDaemon {
  prepareApproval(
    request: {
      command: string
      reason?: string
      capability: string
      workdir: string
      expirySeconds: number
    },
    owner: OwnerContext
  ): Promise<ApprovalPreparation>
  approveNativeApproval(id: string, owner: OwnerContext): Promise<ApprovalRequest>
  consumeApproval(
    id: string,
    details: Pick<ApprovalRequest, 'command' | 'reason' | 'capability' | 'workdir'>,
    owner: OwnerContext
  ): Promise<ApprovalRequest>
  cancelApproval(id: string, owner: OwnerContext): Promise<ApprovalRequest>
  execStart(
    options: {
      command: string
      args: string[]
      workdir: string
      title: string
      description?: string
      parentSessionId: string
      parentAgent: string
      timeoutSeconds: number
    },
    owner: OwnerContext
  ): Promise<ExecResult['session']>
  execWait(
    id: string,
    timeoutSeconds: number,
    owner: OwnerContext,
    signal?: AbortSignal
  ): Promise<ExecResult>
  stop(id: string, owner: OwnerContext): Promise<{ terminationConfirmed: boolean }>
}

export function bashArgv(
  command: string,
  platform = process.platform,
  environment = process.env,
  exists = existsSync
): [string, string[]] {
  const shell = platform === 'win32' ? (environment.ComSpec ?? environment.COMSPEC) : '/bin/sh'
  if (!shell || !exists(shell))
    throw new Error(`Bash compatibility shell is unavailable: ${shell ?? 'none'}.`)
  return platform === 'win32' ? [shell, ['/d', '/s', '/c', command]] : [shell, ['-lc', command]]
}

export function bashTimeout(timeout = DEFAULT_TIMEOUT_MS): number {
  if (!Number.isSafeInteger(timeout) || timeout < 1000)
    throw new Error('Bash timeout must be a whole number of milliseconds of at least 1000.')
  const seconds = Math.floor(timeout / 1000)
  if (seconds > MAX_EXEC_RUNTIME_SECONDS)
    throw new Error(`Bash timeout exceeds the ${MAX_EXEC_RUNTIME_SECONDS} second limit.`)
  return seconds
}

export function bashApprovalCapability(agent: string): string {
  return `bash:${new Bun.CryptoHasher('sha256').update(agent.normalize('NFC')).digest('hex')}`
}

export function createBash(authorize: BashAuthorizer, daemon: BashDaemon = manager) {
  return tool({
    description:
      'Run one finite shell command in the foreground. This intentionally overrides OpenCode Bash rendering; use pty_spawn for durable background work.',
    args: {
      command: tool.schema.string().describe('Raw shell command'),
      workdir: tool.schema.string().optional().describe('Working directory'),
      timeout: tool.schema.number().optional().describe('Timeout in milliseconds (default 120000)'),
      description: tool.schema.string().optional().describe('Brief purpose for the command'),
    },
    async execute(args, ctx) {
      if (!args.command) throw new Error('Bash command is required.')
      ctx.metadata({
        title: 'Bash',
        metadata: {
          output: '[opencode-pty · foreground · awaiting approval]',
        },
      })
      const policy = await authorize(args.command, args.workdir, ctx.agent)
      const owner = ownerContext(ctx.sessionID, ctx.directory)
      const capability = bashApprovalCapability(ctx.agent)
      const approval =
        policy.action === 'ask'
          ? await daemon.prepareApproval(
              {
                command: args.command,
                capability,
                workdir: policy.workdir,
                expirySeconds: APPROVAL_EXPIRY_SECONDS,
              },
              owner
            )
          : undefined
      try {
        if (approval && approval.status !== 'approved_session') {
          await abortableAsk(ctx, args.command)
          await daemon.approveNativeApproval(approval.id, owner)
          const consumed = await daemon.consumeApproval(
            approval.id,
            {
              command: args.command,
              capability,
              workdir: policy.workdir,
            },
            owner
          )
          if (consumed.status !== 'consumed')
            throw new Error('Bash command approval was not granted.')
        }
      } catch (error) {
        if (approval && approval.status !== 'approved_session')
          await daemon.cancelApproval(approval.id, owner).catch(() => undefined)
        throw error
      }
      if (ctx.abort.aborted) throw new Error('Bash execution cancelled before start.')
      const [command, shellArgs] = bashArgv(args.command)
      const timeoutSeconds = bashTimeout(args.timeout)
      ctx.metadata({
        title: 'Bash',
        metadata: {
          output: '[opencode-pty · foreground · running]',
        },
      })
      try {
        const session = await daemon.execStart(
          {
            command,
            args: shellArgs,
            workdir: policy.workdir,
            title: 'Bash',
            parentSessionId: ctx.sessionID,
            parentAgent: ctx.agent,
            timeoutSeconds,
          },
          owner
        )
        const result = await abortableExec(
          ctx,
          daemon,
          session.id,
          owner,
          Math.min(timeoutSeconds + 5, MAX_EXEC_WAIT_SECONDS)
        )
        if (!terminalExecResult(result))
          throw new Error('Bash execution completed without terminal evidence.')
        ctx.metadata({
          title: 'Bash',
          metadata: {
            output: '[opencode-pty · foreground · completed]',
          },
        })
        return [
          `<bash origin="opencode-pty" mode="foreground" status="${escapeXml(result.session.status)}" exit_code="${escapeXml(result.exitCode ?? 'unknown')}" timed_out="${result.timedOut}" termination_confirmed="${result.terminationConfirmed}" terminal="true">`,
          `<stdout>${escapeXml(result.stdout)}</stdout>`,
          `<stderr>${escapeXml(result.stderr)}</stderr>`,
          '</bash>',
        ].join('\n')
      } catch (error) {
        ctx.metadata({
          title: 'Bash',
          metadata: {
            output: '[opencode-pty · foreground · request failed]',
          },
        })
        throw error
      }
    },
  })
}

async function abortableAsk(ctx: ToolContext, command: string): Promise<void> {
  if (ctx.abort.aborted) throw new Error('Bash approval cancelled before prompting.')
  if (typeof ctx.ask !== 'function') throw new Error('Bash approval is unavailable in this host.')
  let abort!: () => void
  const cancelled = new Promise<never>((_, reject) => {
    abort = () => reject(new Error('Bash approval cancelled before prompting.'))
    ctx.abort.addEventListener('abort', abort, { once: true })
  })
  try {
    await Promise.race([
      ctx.ask({
        permission: 'bash',
        patterns: [command],
        always: [],
        metadata: { output: '[opencode-pty · foreground · awaiting approval]' },
      }),
      cancelled,
    ])
  } finally {
    ctx.abort.removeEventListener('abort', abort)
  }
  if (ctx.abort.aborted) throw new Error('Bash approval cancelled before execution.')
}

async function abortableExec(
  ctx: ToolContext,
  daemon: BashDaemon,
  id: string,
  owner: OwnerContext,
  timeoutSeconds: number
): Promise<ExecResult> {
  try {
    return await daemon.execWait(id, timeoutSeconds, owner, ctx.abort)
  } catch (error) {
    if (!ctx.abort.aborted) throw error
    await daemon.stop(id, owner).catch(() => undefined)
    const terminal = await daemon
      .execWait(id, 5, owner)
      .then((result) => (terminalExecResult(result) ? result : undefined))
      .catch(() => undefined)
    throw new Error(
      `Bash execution aborted; termination_confirmed=${terminal?.terminationConfirmed ?? false}.`
    )
  }
}

function terminalExecResult(result: ExecResult): boolean {
  return (
    result.terminationConfirmed &&
    (result.session.status === 'exited' ||
      result.session.status === 'timed_out' ||
      result.session.status === 'output_limited')
  )
}
