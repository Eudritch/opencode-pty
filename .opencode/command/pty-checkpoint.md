---
description: Stage, verify, activate, or inspect the hot-swappable opencode-pty checkpoint.
---

Run `stage`, `activate`, and `status` with finite `shell_exec` calls to `bun run checkpoint $ARGUMENTS` from the repository root. Run `verify` with durable `pty_spawn` using `command: "bun"` and args `['run', 'checkpoint', 'verify', '<git-ref>']`; inspect it with `pty_read` or wait for exit with `pty_wait`. Do not hold a foreground shell while verification runs.

Commands:

- `stage <git-ref>` creates an immutable local worktree for a commit.
- `verify <git-ref>` runs the full local checkpoint gate and records its matching debug worker.
- `activate <git-ref>` atomically switches only to an already verified checkpoint.
- `status` reports the requested active checkpoint.

`activate` hot-swaps internal plugin behavior in a running OpenCode session. It must not be used for changes to tool names, tool arguments, plugin options, TUI registration, or worker protocol; those require the normal OpenCode restart boundary.
