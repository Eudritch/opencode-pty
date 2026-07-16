import { tool, type ToolContext } from '@opencode-ai/plugin'
import { existsSync } from 'node:fs'
import type { ApprovalRequest, ExecResult } from '../../../daemon/types.ts'
import { ownerContext, type OwnerContext } from '../daemon-client.ts'
import { manager } from '../manager.ts'
import type { BashAuthorizer } from '../permissions.ts'
import { escapeXml } from '../xml.ts'

const DEFAULT_TIMEOUT_MS = 120_000
const APPROVAL_EXPIRY_SECONDS = 300

interface BashDaemon {
  createApproval(
    request: {
      command: string
      reason?: string
      capability: string
      workdir: string
      expirySeconds: number
    },
    owner: OwnerContext
  ): Promise<ApprovalRequest>
  approveNativeApproval(id: string, owner: OwnerContext): Promise<ApprovalRequest>
  consumeApproval(
    id: string,
    details: Pick<ApprovalRequest, 'command' | 'reason' | 'capability' | 'workdir'>,
    owner: OwnerContext
  ): Promise<ApprovalRequest>
  cancelApproval(id: string, owner: OwnerContext): Promise<ApprovalRequest>
  exec(
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
    owner: OwnerContext,
    signal: AbortSignal
  ): Promise<ExecResult>
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
  if (seconds > 3600) throw new Error('Bash timeout exceeds the 3600 second limit.')
  return seconds
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
      const title = args.description ?? 'Bash'
      ctx.metadata({
        title,
        metadata: {
          output: '[opencode-pty · foreground · awaiting approval]',
          description: args.description,
        },
      })
      const policy = await authorize(args.command, args.workdir, ctx.agent)
      const owner = ownerContext(ctx.sessionID, ctx.directory)
      const approval =
        policy.action === 'ask'
          ? await daemon.createApproval(
              {
                command: args.command,
                reason: args.description,
                capability: 'bash',
                workdir: policy.workdir,
                expirySeconds: APPROVAL_EXPIRY_SECONDS,
              },
              owner
            )
          : undefined
      try {
        if (approval) {
          await abortableAsk(ctx, args.command, policy.workdir)
          await daemon.approveNativeApproval(approval.id, owner)
          const consumed = await daemon.consumeApproval(
            approval.id,
            {
              command: args.command,
              reason: args.description,
              capability: 'bash',
              workdir: policy.workdir,
            },
            owner
          )
          if (consumed.status !== 'consumed')
            throw new Error('Bash command approval was not granted.')
        }
      } catch (error) {
        if (approval) await daemon.cancelApproval(approval.id, owner).catch(() => undefined)
        throw error
      }
      const [command, shellArgs] = bashArgv(args.command)
      const timeoutSeconds = bashTimeout(args.timeout)
      ctx.metadata({
        title,
        metadata: {
          output: '[opencode-pty · foreground · running]',
          description: args.description,
        },
      })
      try {
        const result = await daemon.exec(
          {
            command,
            args: shellArgs,
            workdir: policy.workdir,
            title,
            description: args.description,
            parentSessionId: ctx.sessionID,
            parentAgent: ctx.agent,
            timeoutSeconds,
          },
          owner,
          ctx.abort
        )
        ctx.metadata({
          title,
          metadata: {
            output: `[opencode-pty · foreground · ${result.session.status}] ${preview(result.stdout || result.stderr)}`,
            description: args.description,
          },
        })
        return [
          `<bash origin="opencode-pty" mode="foreground" status="${escapeXml(result.session.status)}" exit_code="${escapeXml(result.exitCode ?? 'unknown')}" timed_out="${result.timedOut}" termination_confirmed="${result.terminationConfirmed}">`,
          `<stdout>${escapeXml(result.stdout)}</stdout>`,
          `<stderr>${escapeXml(result.stderr)}</stderr>`,
          '</bash>',
        ].join('\n')
      } catch (error) {
        ctx.metadata({
          title,
          metadata: {
            output: '[opencode-pty · foreground · request failed]',
            description: args.description,
          },
        })
        throw error
      }
    },
  })
}

async function abortableAsk(ctx: ToolContext, command: string, workdir: string): Promise<void> {
  if (ctx.abort.aborted) throw new Error('Bash approval cancelled before prompting.')
  await Promise.race([
    ctx.ask({
      permission: 'bash',
      patterns: [command],
      always: [],
      metadata: { command, workdir },
    }),
    new Promise<never>((_, reject) => {
      ctx.abort.addEventListener(
        'abort',
        () => reject(new Error('Bash approval cancelled before prompting.')),
        { once: true }
      )
    }),
  ])
  if (ctx.abort.aborted) throw new Error('Bash approval cancelled before execution.')
}

function preview(output: string): string {
  return output.replaceAll(/\s+/g, ' ').slice(0, 240)
}
