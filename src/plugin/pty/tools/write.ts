import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { ownerContext } from '../daemon-client.ts'
import { escapeXml } from '../xml.ts'
import DESCRIPTION from './write.txt'

const ETX = String.fromCharCode(3)

export function parseEscapeSequences(input: string): string {
  return input.replace(/\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|[nrt\\])/g, (match, seq: string) => {
    if (seq.startsWith('x')) {
      return String.fromCharCode(parseInt(seq.slice(1), 16))
    }
    if (seq.startsWith('u')) {
      return String.fromCharCode(parseInt(seq.slice(1), 16))
    }
    switch (seq) {
      case 'n':
        return '\n'
      case 'r':
        return '\r'
      case 't':
        return '\t'
      case '\\':
        return '\\'
      default:
        return match
    }
  })
}

export const ptyWrite = tool({
  description: DESCRIPTION,
  args: {
    id: tool.schema.string().describe('The PTY session ID (e.g., pty_a1b2c3d4)'),
    data: tool.schema.string().describe('The input data to send to the PTY'),
  },
  async execute(args, ctx) {
    const owner = ownerContext(ctx.sessionID, ctx.directory)
    const session = await manager.get(args.id, owner)
    if (!session) {
      throw new Error(`PTY session '${args.id}' not found. Use pty_list to see active sessions.`)
    }

    if (session.status !== 'running') {
      throw new Error(`Cannot write to PTY '${args.id}' - session status is '${session.status}'.`)
    }

    const parsedData = parseEscapeSequences(args.data)

    const result = await manager.write(args.id, parsedData, owner)

    const preview = args.data.length > 50 ? `${args.data.slice(0, 50)}...` : args.data
    const displayPreview = preview
      .replace(new RegExp(ETX, 'g'), '^C')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
    return `Accepted ${result.acceptedBytes} UTF-8 bytes (${result.acceptedCharacters} characters) for ${escapeXml(args.id)}: "${escapeXml(displayPreview)}"`
  },
})
