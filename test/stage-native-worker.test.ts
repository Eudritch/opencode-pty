import { expect, test } from 'bun:test'
import { stageNativeWorker } from '../scripts/stage-native-worker.ts'

test('retries a locked Windows worker replacement', async () => {
  let attempts = 0
  const removed: string[] = []
  await stageNativeWorker(
    'worker.exe',
    'native-artifacts/win32-x64/bin/opencode-pty-worker.exe',
    true,
    {
      copyFile: async () => undefined,
      rename: async () => {
        attempts += 1
        if (attempts === 1) throw Object.assign(new Error('locked'), { code: 'EBUSY' })
      },
      remove: async (path) => void removed.push(path),
      sleep: async () => undefined,
    }
  )
  expect(attempts).toBe(2)
  expect(removed).toHaveLength(1)
  expect(removed[0]).toMatch(/bin[\\/][.]opencode-pty-worker[.]exe[.].+[.]tmp$/)
})

test('reports a persistent Windows lock without terminating a process', async () => {
  let clock = 0
  await expect(
    stageNativeWorker(
      'worker.exe',
      'native-artifacts/win32-x64/bin/opencode-pty-worker.exe',
      true,
      {
        copyFile: async () => undefined,
        rename: async () => {
          throw Object.assign(new Error('locked'), { code: 'EBUSY' })
        },
        remove: async () => undefined,
        sleep: async (milliseconds) => {
          clock += milliseconds
        },
        now: () => clock,
      }
    )
  ).rejects.toThrow(/remained locked for 10 seconds[.] No process was forcibly terminated/)
})
