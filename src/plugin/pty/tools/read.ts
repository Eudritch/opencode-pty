import { tool } from '@opencode-ai/plugin'
import { manager } from '../manager.ts'
import { DEFAULT_READ_LIMIT, MAX_LINE_LENGTH } from '../../../shared/constants.ts'
import { formatLine } from '../formatters.ts'
import type { PTYSessionInfo } from '../types.ts'
import { escapeXml } from '../xml.ts'
import DESCRIPTION from './read.txt'

function buildTimeoutReminder(session: PTYSessionInfo): string {
  return [
    `<system_reminder>`,
    `This session was auto-killed after reaching \`timeoutSeconds=${session.timeoutSeconds ?? 'unknown'}\`.`,
    `Use \`pty_read\` to inspect the final output or \`pty_list\` to review other sessions.`,
    `</system_reminder>`,
  ].join('\n')
}

interface ReadArgs {
  id: string
  offset?: number
  limit?: number
  pattern?: string
  ignoreCase?: boolean
  sequence?: number
}

/**
 * Formats PTY output with XML tags and pagination
 */
function formatPtyOutput(
  id: string,
  status: string,
  pattern: string | undefined,
  session: PTYSessionInfo,
  formattedLines: string[],
  hasMore: boolean,
  paginationMessage: string,
  endMessage: string
): string {
  const output = [
    `<pty_output id="${escapeXml(id)}" status="${escapeXml(status)}" output_sequence="${session.outputSequence ?? 0}" retained_from="${session.firstRetainedSequence ?? 0}" truncated="${session.outputTruncated ?? false}"${pattern ? ` pattern="${escapeXml(pattern)}"` : ''}>`,
    ...formattedLines,
    '',
    hasMore ? paginationMessage : endMessage,
    `</pty_output>`,
  ]
  return output.join('\n')
}

function appendTimeoutReminder(output: string, session: PTYSessionInfo): string {
  if (!session.timedOut) {
    return output
  }

  return `${output}\n\n${buildTimeoutReminder(session)}`
}

function appendSessionReminders(output: string, session: PTYSessionInfo): string {
  return appendTimeoutReminder(output, session)
}

/**
 * Handles pattern-based reading and formatting
 */
async function handlePatternRead(
  id: string,
  pattern: string,
  ignoreCase: boolean | undefined,
  session: PTYSessionInfo,
  offset: number,
  limit: number,
  sequence?: number
): Promise<string> {
  const result = await manager.search(id, pattern, ignoreCase, offset, limit, sequence)
  if (!result) {
    throw new Error(`PTY session '${id}' not found. Use pty_list to see active sessions.`)
  }

  if (result.matches.length === 0) {
    return appendSessionReminders(
      [
        `<pty_output id="${escapeXml(id)}" status="${escapeXml(session.status)}" output_sequence="${result.nextSequence}" retained_from="${result.firstRetainedSequence}" truncated="${result.truncated}" pattern="${escapeXml(pattern)}">`,
        `No lines matched the pattern '${escapeXml(pattern)}'.`,
        `Total lines in buffer: ${result.totalLines}`,
        `</pty_output>`,
      ].join('\n'),
      session
    )
  }

  const formattedLines = result.matches.map((match) =>
    formatLine(match.text, match.lineNumber, MAX_LINE_LENGTH, match.sequence)
  )

  const paginationMessage = `(${result.matches.length} of ${result.totalMatches} matches shown. Use offset=${offset + result.matches.length} to see more.)`
  const endMessage = `(${result.totalMatches} match${result.totalMatches === 1 ? '' : 'es'} from ${result.totalLines} total lines)`

  return appendSessionReminders(
    formatPtyOutput(
      id,
      session.status,
      pattern,
      {
        ...session,
        outputSequence: result.nextSequence,
        firstRetainedSequence: result.firstRetainedSequence,
        outputTruncated: result.truncated,
      },
      formattedLines,
      result.hasMore,
      paginationMessage,
      endMessage
    ),
    session
  )
}

/**
 * Handles plain reading and formatting
 */
async function handlePlainRead(
  args: ReadArgs,
  session: PTYSessionInfo,
  offset: number,
  limit: number,
  sequence?: number
): Promise<string> {
  const result = await manager.read(args.id, offset, limit, sequence)
  if (!result) {
    throw new Error(`PTY session '${args.id}' not found. Use pty_list to see active sessions.`)
  }

  if (result.lines.length === 0) {
    return appendSessionReminders(
      [
        `<pty_output id="${escapeXml(args.id)}" status="${escapeXml(session.status)}" output_sequence="${result.nextSequence}" retained_from="${result.firstRetainedSequence}" truncated="${result.truncated}">`,
        `(No output available - buffer is empty)`,
        `Total lines: ${result.totalLines}`,
        `</pty_output>`,
      ].join('\n'),
      session
    )
  }

  const formattedLines = result.lines.map((line, index) =>
    formatLine(line, result.offset + index + 1, MAX_LINE_LENGTH, result.sequences[index])
  )

  const paginationMessage = `(Buffer has more lines. Use offset=${result.offset + result.lines.length} to read beyond line ${result.offset + result.lines.length})`
  const endMessage = `(End of buffer - total ${result.totalLines} lines)`

  return appendSessionReminders(
    formatPtyOutput(
      args.id,
      session.status,
      undefined,
      {
        ...session,
        outputSequence: result.nextSequence,
        firstRetainedSequence: result.firstRetainedSequence,
        outputTruncated: result.truncated,
      },
      formattedLines,
      result.hasMore,
      paginationMessage,
      endMessage
    ),
    session
  )
}

export const ptyRead = tool({
  description: DESCRIPTION,
  args: {
    id: tool.schema.string().describe('The PTY session ID (e.g., pty_a1b2c3d4)'),
    offset: tool.schema
      .number()
      .optional()
      .describe(
        'Line number to start reading from (0-based, defaults to 0). When using pattern, this applies to filtered matches.'
      ),
    limit: tool.schema
      .number()
      .optional()
      .describe(
        'Number of lines to read (defaults to 500). When using pattern, this applies to filtered matches.'
      ),
    pattern: tool.schema
      .string()
      .optional()
      .describe(
        'Literal text to filter lines. When set, only matching lines are returned, then offset/limit apply to the matches.'
      ),
    ignoreCase: tool.schema
      .boolean()
      .optional()
      .describe('Case-insensitive pattern matching (default: false)'),
    sequence: tool.schema
      .number()
      .optional()
      .describe('Only return lines at or after this durable UTF-8 byte sequence position.'),
  },
  async execute(args) {
    const session = await manager.get(args.id)
    if (!session) {
      throw new Error(`PTY session '${args.id}' not found. Use pty_list to see active sessions.`)
    }

    const offset = args.offset ?? 0
    const limit = args.limit ?? DEFAULT_READ_LIMIT

    if (args.pattern) {
      return await handlePatternRead(
        args.id,
        args.pattern,
        args.ignoreCase,
        session,
        offset,
        limit,
        args.sequence
      )
    } else {
      return await handlePlainRead(args, session, offset, limit, args.sequence)
    }
  },
})
