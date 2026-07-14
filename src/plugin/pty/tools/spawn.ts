import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { authorizeSpawn } from '../permissions.ts'
import DESCRIPTION from './spawn.txt'
import { escapeXml } from '../xml.ts'

export const ptySpawn = tool({
  description: DESCRIPTION,
  args: {
    command: tool.schema.string().describe('The command/executable to run'),
    args: tool.schema.array(tool.schema.string()).describe('Arguments to pass to the command'),
    workdir: tool.schema.string().optional().describe('Working directory for the PTY session'),
    env: tool.schema
      .record(tool.schema.string(), tool.schema.string())
      .optional()
      .describe('Additional environment variables'),
    title: tool.schema.string().optional().describe('Human-readable title for the session'),
    description: tool.schema
      .string()
      .describe('Clear, concise description of what this PTY session is for in 5-10 words'),
    notifyOnExit: tool.schema
      .boolean()
      .optional()
      .describe('Unsupported by the durable daemon; omit this option'),
    timeoutSeconds: tool.schema
      .number()
      .optional()
      .describe(
        'Optional per-session timeout in seconds. The PTY is killed automatically when this duration elapses.'
      ),
    name: tool.schema
      .string()
      .optional()
      .describe('Optional stable name, scoped to this OpenCode session and workdir'),
    idempotencyKey: tool.schema
      .string()
      .optional()
      .describe('Reuse the matching active named PTY; a changed command or spec is rejected'),
  },
  async execute(args, ctx) {
    if (args.notifyOnExit) {
      throw new Error(
        'notifyOnExit is not supported by the durable daemon. Use pty_list or pty_read.'
      )
    }
    const workdir = await authorizeSpawn(args.command, args.args ?? [], args.workdir)

    const sessionId = ctx.sessionID
    const info = await manager.spawn({
      command: args.command,
      args: args.args,
      workdir,
      env: args.env,
      title: args.title,
      description: args.description,
      parentSessionId: sessionId,
      parentAgent: ctx.agent,
      timeoutSeconds: args.timeoutSeconds,
      name: args.name,
      idempotencyKey: args.idempotencyKey,
    })

    const output = [
      `<pty_spawned>`,
      `ID: ${escapeXml(info.id)}`,
      `Title: ${escapeXml(info.title)}`,
      `Command: ${escapeXml(info.command)} ${escapeXml(info.args.join(' '))}`,
      `Workdir: ${escapeXml(info.workdir)}`,
      `PID: ${info.pid}`,
      `Status: ${info.status}`,
      `TimeoutSeconds: ${info.timeoutSeconds ?? 'none'}`,
      `Mode: ${info.mode}`,
      `</pty_spawned>`,
    ].join('\n')

    return output
  },
})
