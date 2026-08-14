---
description: Stage, verify, activate, or inspect the hot-swappable opencode-pty checkpoint.
---

Use `shell_exec` with `bun run checkpoint $ARGUMENTS` from the repository root.

Commands:

- `stage <git-ref>` creates an immutable local worktree for a commit.
- `verify <git-ref>` runs the full local checkpoint gate and records its matching debug worker.
- `activate <git-ref>` atomically switches only to an already verified checkpoint.
- `status` reports the requested active checkpoint.

`activate` hot-swaps internal plugin behavior in a running OpenCode session. It must not be used for changes to tool names, tool arguments, plugin options, TUI registration, or worker protocol; those require the normal OpenCode restart boundary.
