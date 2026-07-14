import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { ownerContext } from '../daemon-client.ts'

export const ptyResize = tool({
  description:
    'Resize a running native PTY terminal. Output remains a redacted UTF-8 stream, not a screen snapshot.',
  args: {
    id: tool.schema.string().describe('The PTY session ID'),
    cols: tool.schema.number().describe('Terminal columns, from 1 to 1000'),
    rows: tool.schema.number().describe('Terminal rows, from 1 to 1000'),
  },
  async execute(args, ctx) {
    const result = await manager.resize(
      args.id,
      args.cols,
      args.rows,
      ownerContext(ctx.sessionID, ctx.directory)
    )
    return `Resized ${args.id} to ${result.cols}x${result.rows}.`
  },
})
