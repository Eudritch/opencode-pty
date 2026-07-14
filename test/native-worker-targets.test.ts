import { expect, test } from 'bun:test'
import { NATIVE_WORKER_TARGETS, nativeWorkerTarget } from '../src/shared/native-worker-targets.ts'

test('native worker target table covers exactly the released native platforms', () => {
  expect(Object.keys(NATIVE_WORKER_TARGETS)).toEqual([
    'linux-x64-gnu',
    'linux-arm64-gnu',
    'win32-x64',
    'win32-arm64',
    'darwin-arm64',
    'darwin-x64',
  ])
  expect(nativeWorkerTarget('linux', 'arm64')).toBe('linux-arm64-gnu')
  expect(nativeWorkerTarget('win32', 'arm64')).toBe('win32-arm64')
  expect(nativeWorkerTarget('darwin', 'x64')).toBe('darwin-x64')
  expect(nativeWorkerTarget('linux', 'ppc64')).toBeUndefined()
})
