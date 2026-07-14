import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { authorizeSpawn } from '../permissions.ts'

export const shellExec = tool({
  description:
    'Run one finite argv command without a terminal. Use this for commands expected to finish; it returns separate stdout and stderr, exit evidence, timeout status, and bounded output.',
  args: {
    command: tool.schema.string().describe('Executable only, not shell syntax'),
    args: tool.schema.array(tool.schema.string()).describe('Structured argv arguments'),
    workdir: tool.schema.string().optional().describe('Working directory'),
    env: tool.schema.record(tool.schema.string(), tool.schema.string()).optional(),
    timeoutSeconds: tool.schema.number().describe('Required finite deadline in seconds'),
    maxOutputBytes: tool.schema
      .number()
      .optional()
      .describe('Maximum captured bytes per stdout/stderr stream'),
  },
  async execute(args, ctx) {
    const workdir = await authorizeSpawn(args.command, args.args ?? [], args.workdir)
    const result = await manager.exec({
      ...args,
      workdir,
      parentSessionId: ctx.sessionID,
      parentAgent: ctx.agent,
    })
    return [
      `<shell_exec id="${result.session.id}" status="${result.session.status}" exit_code="${result.exitCode ?? 'unknown'}" timed_out="${result.timedOut}" output_limited="${result.outputLimited}">`,
      '<stdout>',
      result.stdout,
      '</stdout>',
      '<stderr>',
      result.stderr,
      '</stderr>',
      '</shell_exec>',
    ].join('\n')
  },
})
