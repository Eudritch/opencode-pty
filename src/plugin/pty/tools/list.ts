import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { ownerContext } from '../daemon-client.ts'
import { formatSessionInfo } from '../formatters.ts'
import DESCRIPTION from './list.txt'

export const ptyList = tool({
  description: DESCRIPTION,
  args: {},
  async execute(_, ctx) {
    const sessions = await manager.list(ownerContext(ctx.sessionID, ctx.directory))

    if (sessions.length === 0) {
      return '<pty_list>\nNo PTY session records.\n</pty_list>'
    }

    const lines = ['<pty_list>']
    for (const session of sessions) {
      lines.push(...formatSessionInfo(session))
    }
    lines.push(`Total retained records: ${sessions.length}`)
    lines.push('</pty_list>')

    return lines.join('\n')
  },
})
