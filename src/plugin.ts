import type { PluginContext, PluginOptions, PluginResult } from './plugin/types.ts'
import { manager } from './plugin/pty/manager.ts'
import { ownerContext } from './plugin/pty/daemon-client.ts'
import { createBashAuthorizer, createSpawnAuthorizer } from './plugin/pty/permissions.ts'
import { createPtySpawn } from './plugin/pty/tools/spawn.ts'
import { ptyWrite } from './plugin/pty/tools/write.ts'
import { ptyRead } from './plugin/pty/tools/read.ts'
import { ptyList } from './plugin/pty/tools/list.ts'
import { ptyKill } from './plugin/pty/tools/kill.ts'
import { createShellExec } from './plugin/pty/tools/exec.ts'
import { ptySendWait, ptyWait } from './plugin/pty/tools/wait.ts'
import { ptyResize } from './plugin/pty/tools/resize.ts'
import { createBash } from './plugin/pty/tools/bash.ts'

export const PTYPlugin = async (
  { client, directory }: PluginContext,
  options: PluginOptions = {}
): Promise<PluginResult> => {
  const authorizeSpawn = createSpawnAuthorizer(client, directory)

  return {
    tool: {
      pty_spawn: createPtySpawn(authorizeSpawn),
      pty_write: ptyWrite,
      pty_read: ptyRead,
      pty_list: ptyList,
      pty_kill: ptyKill,
      shell_exec: createShellExec(authorizeSpawn),
      pty_wait: ptyWait,
      pty_send_wait: ptySendWait,
      pty_resize: ptyResize,
      ...(options.bash === false
        ? {}
        : { bash: createBash(createBashAuthorizer(client, directory)) }),
    },
    event: async ({ event }) => {
      if (event.type === 'session.deleted') {
        await manager.cleanupBySession(
          ownerContext(event.properties.info.id, event.properties.info.directory)
        )
      }
    },
  }
}

// OpenCode accepts this legacy module entry name as well as PTYPlugin.
export const server = PTYPlugin
