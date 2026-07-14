import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { ownerContext } from '../daemon-client.ts'
import { escapeXml } from '../xml.ts'
import { parseEscapeSequences } from './write.ts'

const waitArgs = {
  id: tool.schema.string().describe('PTY session ID'),
  timeoutSeconds: tool.schema.number().describe('Deadline in seconds, maximum 3600'),
  literal: tool.schema.string().optional().describe('Wait for this literal output'),
  regex: tool.schema
    .string()
    .optional()
    .describe('Wait for a limited-safe regular expression in retained output'),
  exit: tool.schema.boolean().optional().describe('Wait for process exit instead of output'),
}

function condition(args: { literal?: string; regex?: string; exit?: boolean }) {
  if (args.exit) {
    if (args.literal || args.regex)
      throw new Error('exit cannot be combined with literal or regex.')
    return { kind: 'exit' as const }
  }
  if (Boolean(args.literal) === Boolean(args.regex)) {
    throw new Error('Provide exactly one of literal, regex, or exit=true.')
  }
  return { kind: 'output' as const, literal: args.literal, regex: args.regex }
}

function format(result: Awaited<ReturnType<typeof manager.wait>>): string {
  const containment = result.containment
  return `<pty_wait satisfied="${result.satisfied}" reason="${escapeXml(result.reason)}" matched="${escapeXml(result.matched ?? '')}" exit_code="${escapeXml(result.exitCode ?? 'unknown')}" output_truncated="${result.outputTruncated}" termination_confirmed="${Boolean(result.termination?.rootExited && containment?.status === 'posix_best_effort_empty')}" containment="${escapeXml(containment?.status ?? 'unavailable')}" group_pids="${containment?.observedGroupPids.join(',') ?? ''}" session_pids="${containment?.observedSessionPids.join(',') ?? ''}" escaped_pids="${containment?.observedEscapedDescendantPids.join(',') ?? ''}"/>`
}

export const ptyWait = tool({
  description: 'Wait daemon-side for PTY output or exit. This does not poll from the plugin.',
  args: waitArgs,
  async execute(args, ctx) {
    return format(
      await manager.wait(
        args.id,
        condition(args),
        args.timeoutSeconds,
        ownerContext(ctx.sessionID, ctx.directory)
      )
    )
  },
})

export const ptySendWait = tool({
  description: 'Send input to a running PTY, then wait daemon-side for output or exit.',
  args: {
    ...waitArgs,
    data: tool.schema.string().describe('Input to send to the PTY; terminal escapes are decoded'),
  },
  async execute(args, ctx) {
    return format(
      await manager.sendWait(
        args.id,
        parseEscapeSequences(args.data),
        condition(args),
        args.timeoutSeconds,
        ownerContext(ctx.sessionID, ctx.directory)
      )
    )
  },
})
