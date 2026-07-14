export const NATIVE_WORKER_TARGETS = {
  'linux-x64-gnu': { os: 'linux', cpu: 'x64' },
  'linux-arm64-gnu': { os: 'linux', cpu: 'arm64' },
  'win32-x64': { os: 'win32', cpu: 'x64' },
  'win32-arm64': { os: 'win32', cpu: 'arm64' },
  'darwin-arm64': { os: 'darwin', cpu: 'arm64' },
  'darwin-x64': { os: 'darwin', cpu: 'x64' },
} as const

export type NativeWorkerTarget = keyof typeof NATIVE_WORKER_TARGETS

export function nativeWorkerTarget(
  platform: string,
  architecture: string
): NativeWorkerTarget | undefined {
  return (
    Object.entries(NATIVE_WORKER_TARGETS) as [NativeWorkerTarget, { os: string; cpu: string }][]
  ).find(([, value]) => value.os === platform && value.cpu === architecture)?.[0]
}

export function nativeWorkerBinaryName(platform: string): string {
  return `opencode-pty-worker${platform === 'win32' ? '.exe' : ''}`
}

export function nativeWorkerPackageName(target: NativeWorkerTarget): string {
  return `@eudritch/opencode-pty-worker-${target}`
}

export function nativeWorkerArchiveName(target: NativeWorkerTarget, version: string): string {
  return `eudritch-opencode-pty-worker-${target}-${version}.tgz`
}
