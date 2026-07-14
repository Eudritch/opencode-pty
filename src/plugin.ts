import type { PluginContext, PluginResult } from './plugin/types.ts'
import { manager } from './plugin/pty/manager.ts'
import { ownerContext } from './plugin/pty/daemon-client.ts'
import { initPermissions } from './plugin/pty/permissions.ts'
import { ptySpawn } from './plugin/pty/tools/spawn.ts'
import { ptyWrite } from './plugin/pty/tools/write.ts'
import { ptyRead } from './plugin/pty/tools/read.ts'
import { ptyList } from './plugin/pty/tools/list.ts'
import { ptyKill } from './plugin/pty/tools/kill.ts'
import { shellExec } from './plugin/pty/tools/exec.ts'
import { ptySendWait, ptyWait } from './plugin/pty/tools/wait.ts'

export const PTYPlugin = async ({ client, directory }: PluginContext): Promise<PluginResult> => {
  initPermissions(client, directory)

  return {
    tool: {
      pty_spawn: ptySpawn,
      pty_write: ptyWrite,
      pty_read: ptyRead,
      pty_list: ptyList,
      pty_kill: ptyKill,
      shell_exec: shellExec,
      pty_wait: ptyWait,
      pty_send_wait: ptySendWait,
    },
    event: async ({ event }) => {
      if (event.type === 'session.deleted') {
        await manager.cleanupBySession(ownerContext(event.properties.info.id, directory))
      }
    },
  }
}
