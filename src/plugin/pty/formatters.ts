import type { PTYSessionInfo } from './types.ts'
import { escapeXml } from './xml.ts'

export function formatSessionInfo(session: PTYSessionInfo): string[] {
  const timedOutInfo = session.timedOut ? ' | timed out' : ''
  const exitInfo = session.exitCode !== undefined ? ` | exit: ${session.exitCode}` : ''
  const exitSignal = session.exitSignal ? ` | signal: ${session.exitSignal}` : ''
  const timeoutInfo =
    session.timeoutSeconds !== undefined ? ` | timeout: ${session.timeoutSeconds}s` : ''
  const outputInfo = session.outputTruncated ? ' (older output truncated)' : ''
  return [
    `[${escapeXml(session.id)}] ${escapeXml(session.title)}`,
    `  Command: ${escapeXml(session.command)} ${escapeXml(session.args.join(' '))}`,
    `  Status: ${session.status}${timedOutInfo}${exitInfo}${exitSignal}`,
    `  PID: ${session.pid}${timeoutInfo}`,
    `  Lines: ${session.lineCount}${outputInfo}`,
    `  Workdir: ${escapeXml(session.workdir)}`,
    `  Created: ${session.createdAt}`,
    '',
  ]
}

export function formatLine(
  line: string,
  lineNum: number,
  maxLength: number = 2000,
  sequence?: number
): string {
  const lineNumStr = lineNum.toString().padStart(5, '0')
  const truncatedLine = line.length > maxLength ? `${line.slice(0, maxLength)}...` : line
  return `${lineNumStr}${sequence === undefined ? '' : `@${sequence}`}| ${escapeXml(truncatedLine)}`
}
