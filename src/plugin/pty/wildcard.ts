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

export function all(input: string, patterns: Record<string, string>): string | undefined {
  const sorted = Object.entries(patterns).sort(
    (a, b) => a[0].length - b[0].length || a[0].localeCompare(b[0])
  )
  let result: string | undefined
  for (const [pattern, value] of sorted) {
    if (match(input, pattern)) {
      result = value
    }
  }
  return result
}

export function allStructured(
  input: { head: string; tail: string[] },
  patterns: Record<string, string>
): string | undefined {
  let result: string | undefined
  for (const [pattern, value] of Object.entries(patterns)) {
    const parts = pattern.split(/\s+/)
    const firstPart = parts[0]
    if (!firstPart || !match(input.head, firstPart)) continue
    if (matchSequence(input.tail, parts.slice(1))) {
      result = value
    }
  }
  return result
}

function matchSequence(items: string[], patterns: string[]): boolean {
  if (patterns.length === 0) return items.length === 0
  const [pattern, ...rest] = patterns
  if (pattern === '*') {
    for (let index = 0; index <= items.length; index += 1) {
      if (matchSequence(items.slice(index), rest)) return true
    }
    return false
  }
  const [item, ...remaining] = items
  return Boolean(item && pattern && match(item, pattern) && matchSequence(remaining, rest))
}
