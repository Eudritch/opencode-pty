import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { ownerContext } from '../daemon-client.ts'
import DESCRIPTION from './kill.txt'
import { escapeXml } from '../xml.ts'

export const ptyKill = tool({
  description: DESCRIPTION,
  args: {
    id: tool.schema.string().describe('The PTY session ID (e.g., pty_a1b2c3d4)'),
    cleanup: tool.schema
      .boolean()
      .optional()
      .describe('If true, removes the session and frees the buffer (default: false)'),
  },
  async execute(args, ctx) {
    const owner = ownerContext(ctx.sessionID, ctx.directory)
    const session = await manager.get(args.id, owner)
    if (!session) {
      throw new Error(`PTY session '${args.id}' not found. Use pty_list to see active sessions.`)
    }

    const cleanup = args.cleanup ?? false
    const stop = await manager.stop(args.id, owner)
    const cleaned =
      cleanup && stop.terminationConfirmed ? await manager.cleanup(args.id, owner) : false
    const action = stop.terminationConfirmed
      ? 'Termination confirmed'
      : stop.requested
        ? 'Termination requested'
        : 'No stop request possible (session is lost or termination is unconfirmed)'
    const cleanupNote = cleaned
      ? ' (exited session removed)'
      : cleanup
        ? ' (record retained until termination is confirmed)'
        : ' (session retained for log access)'

    return [
      `<pty_stop>`,
      `${action}: ${escapeXml(args.id)}${cleanupNote}`,
      `Termination confirmed: ${stop.terminationConfirmed ? 'yes' : 'no'}`,
      stop.containment
        ? `Containment: ${escapeXml(stop.containment.status)}; group=${stop.containment.observedGroupPids.join(',') || 'none'}; session=${stop.containment.observedSessionPids.join(',') || 'none'}; escaped=${stop.containment.observedEscapedDescendantPids.join(',') || 'none'}`
        : '',
      `Title: ${escapeXml(session.title)}`,
      `Command: ${escapeXml(session.command)} ${escapeXml(session.args.join(' '))}`,
      `Line count before stop request: ${session.lineCount}`,
      `</pty_stop>`,
    ].join('\n')
  },
})
