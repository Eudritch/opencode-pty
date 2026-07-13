import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import DESCRIPTION from './kill.txt'

export const ptyKill = tool({
  description: DESCRIPTION,
  args: {
    id: tool.schema.string().describe('The PTY session ID (e.g., pty_a1b2c3d4)'),
    cleanup: tool.schema
      .boolean()
      .optional()
      .describe('If true, removes the session and frees the buffer (default: false)'),
  },
  async execute(args) {
    const session = await manager.get(args.id)
    if (!session) {
      throw new Error(`PTY session '${args.id}' not found. Use pty_list to see active sessions.`)
    }

    const cleanup = args.cleanup ?? false
    const stop = await manager.stop(args.id)
    const cleaned = cleanup && stop.terminationConfirmed ? await manager.cleanup(args.id) : false
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
      `${action}: ${args.id}${cleanupNote}`,
      `Termination confirmed: ${stop.terminationConfirmed ? 'yes' : 'no'}`,
      `Title: ${session.title}`,
      `Command: ${session.command} ${session.args.join(' ')}`,
      `Final line count: ${session.lineCount}`,
      `</pty_stop>`,
    ].join('\n')
  },
})
