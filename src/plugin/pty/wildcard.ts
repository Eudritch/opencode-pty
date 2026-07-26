export function match(str: string, pattern: string, platform = process.platform): boolean {
  str = normalize(str, platform)
  pattern = normalize(pattern, platform)
  // OpenCode's command wildcard permits an omitted argv tail.
  if (pattern.endsWith(' *') && str === pattern.slice(0, -2)) return true
  const regex = new RegExp(
    '^' +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.') +
      '$',
    's'
  )
  return regex.test(str)
}

function normalize(value: string, platform: string): string {
  const normalized = value.replace(/\\/g, '/')
  return platform === 'win32' ? normalized.toLowerCase() : normalized
}
