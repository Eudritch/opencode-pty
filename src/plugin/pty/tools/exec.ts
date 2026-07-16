import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { ownerContext } from '../daemon-client.ts'
import type { SpawnAuthorizer } from '../permissions.ts'
import { escapeXml } from '../xml.ts'

export function createShellExec(authorizeSpawn: SpawnAuthorizer) {
  return tool({
    description:
      'Run one finite argv command without a terminal. Use this for commands expected to finish; it returns separate stdout and stderr, exit evidence, timeout status, and bounded output.',
    args: {
      command: tool.schema.string().describe('Executable only, not shell syntax'),
      args: tool.schema.array(tool.schema.string()).describe('Structured argv arguments'),
      workdir: tool.schema.string().optional().describe('Working directory'),
      env: tool.schema.record(tool.schema.string(), tool.schema.string()).optional(),
      inheritEnv: tool.schema.boolean().optional(),
      timeoutSeconds: tool.schema.number().describe('Required finite deadline in seconds'),
      maxOutputBytes: tool.schema
        .number()
        .optional()
        .describe('Maximum captured bytes per stdout/stderr stream'),
    },
    async execute(args, ctx) {
      const workdir = await authorizeSpawn(
        args.command,
        args.args ?? [],
        args.workdir,
        ctx.agent,
        ctx.ask
      )
      const result = await manager.exec(
        {
          ...args,
          workdir,
          parentSessionId: ctx.sessionID,
          parentAgent: ctx.agent,
          inheritEnv: args.inheritEnv,
        },
        ownerContext(ctx.sessionID, ctx.directory)
      )
      return [
        `<shell_exec id="${escapeXml(result.session.id)}" status="${escapeXml(result.session.status)}" exit_code="${escapeXml(result.exitCode ?? 'unknown')}" timed_out="${result.timedOut}" output_limited="${result.outputLimited}" termination_confirmed="${result.terminationConfirmed}">`,
        '<stdout>',
        escapeXml(result.stdout),
        '</stdout>',
        '<stderr>',
        escapeXml(result.stderr),
        '</stderr>',
        result.containment
          ? `<containment status="${escapeXml(result.containment.status)}" direct_child_exited="${result.termination?.directChildExited ?? false}" root_identity_verified="${result.containment.rootIdentityVerified}" group_pids="${result.containment.observedGroupPids.join(',')}" session_pids="${result.containment.observedSessionPids.join(',')}" escaped_pids="${result.containment.observedEscapedDescendantPids.join(',')}"/>`
          : '',
        '</shell_exec>',
      ].join('\n')
    },
  })
}
