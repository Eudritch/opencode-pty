export function escapeXml(value: unknown): string {
  let sanitized = ''
  for (const character of String(value)) {
    const code = character.codePointAt(0) ?? 0
    sanitized +=
      code === 0x9 ||
      code === 0xa ||
      code === 0xd ||
      (code >= 0x20 && code <= 0xd7ff) ||
      (code >= 0xe000 && code <= 0xfffd) ||
      (code >= 0x10000 && code <= 0x10ffff)
        ? character
        : '\uFFFD'
  }
  return sanitized
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}
