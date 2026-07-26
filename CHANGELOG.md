# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Restored the POSIX native worker build.
- Windows exec reliability: spurious exit code 259 (`STILL_ACTIVE`) handling, `PATHEXT`-aware executable resolution, and UTF-8 output handling.
- Hardened daemon start-lock ownership, daemon liveness detection, and environment handling.
- Restored the Bash-to-TUI approval producer: experimental Bash `ask` decisions are published as daemon approval requests that the TUI companion can claim within a short lease, falling back to the host's native ask when unclaimed.
- Test determinism fixes across the daemon suite.

## [0.5.0] - 2026-07-14

### Added

- Durable background daemon that owns PTY and exec sessions across OpenCode restarts, with authenticated loopback RPC and per-owner capability checks.
- Native per-session Rust workers shipped as platform-specific optional npm packages (Linux glibc, macOS, Windows ConPTY).
- TUI companion plugin with a session sidebar and a durable approval protocol with session-scoped, agent-bound grants.
- Experimental opaque Bash compatibility override, opt-in via `{ "bash": true }`.
- Windows Job Object containment: children start suspended, join a non-breakaway kill-on-close Job, and post-termination Job accounting is verified.

### Changed

- Session metadata, output journals, and approvals persist under the daemon state directory, protected with a restrictive DACL on Windows.
