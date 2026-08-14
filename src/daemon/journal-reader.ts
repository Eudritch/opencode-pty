import type { ReadResult, SearchResult } from '../plugin/pty/types.ts'
import type { DaemonStorage } from './storage.ts'
import type { SessionRecord } from './types.ts'

export function lineCount(output: string): number {
  if (!output) return 0
  const lines = output.split('\n')
  return lines.at(-1) === '' ? lines.length - 1 : lines.length
}

function outputLines(
  output: string,
  firstSequence: number
): Array<{ lineNumber: number; sequence: number; text: string }> {
  if (!output) return []
  const parts = output.split('\n')
  const count = output.endsWith('\n') ? parts.length - 1 : parts.length
  let sequence = firstSequence
  return parts.slice(0, count).map((text, index) => {
    const line = { lineNumber: index + 1, sequence, text }
    sequence += Buffer.byteLength(text) + (index < parts.length - 1 ? 1 : 0)
    return line
  })
}

function searchLines(
  output: string,
  pattern: string,
  ignoreCase: boolean,
  firstSequence: number
): Array<{ lineNumber: number; sequence: number; text: string }> {
  const needle = ignoreCase ? pattern.toLowerCase() : pattern
  return outputLines(output, firstSequence).filter(({ text }) => {
    const haystack = ignoreCase ? text.toLowerCase() : text
    return Boolean(text) && haystack.includes(needle)
  })
}

export class JournalReader {
  constructor(
    private readonly storage: DaemonStorage,
    private readonly flush: () => Promise<void>
  ) {}

  async output(id: string): Promise<string> {
    await this.flush()
    return this.storage.readOutput(id)
  }

  async read(
    record: SessionRecord,
    offset = 0,
    limit?: number,
    sequence?: number
  ): Promise<ReadResult> {
    const output = await this.output(record.id)
    const lines = outputLines(output, record.firstRetainedSequence).filter(
      (line) => sequence === undefined || line.sequence >= sequence
    )
    const start = Math.max(0, offset)
    const page = limit === undefined ? lines.slice(start) : lines.slice(start, start + limit)
    return {
      lines: page.map((line) => line.text),
      sequences: page.map((line) => line.sequence),
      totalLines: lines.length,
      offset: start,
      hasMore: start + page.length < lines.length,
      firstRetainedSequence: record.firstRetainedSequence,
      nextSequence: record.nextSequence,
      truncated: record.outputTruncated,
      containment: record.containment,
      termination: record.termination,
    }
  }

  async search(
    record: SessionRecord,
    pattern: string,
    ignoreCase = false,
    offset = 0,
    limit?: number,
    sequence?: number
  ): Promise<SearchResult> {
    const output = await this.output(record.id)
    const matches = searchLines(output, pattern, ignoreCase, record.firstRetainedSequence).filter(
      (match) => sequence === undefined || match.sequence >= sequence
    )
    const start = Math.max(0, offset)
    const page = limit === undefined ? matches.slice(start) : matches.slice(start, start + limit)
    return {
      matches: page,
      totalMatches: matches.length,
      totalLines: lineCount(output),
      offset: start,
      hasMore: start + page.length < matches.length,
      firstRetainedSequence: record.firstRetainedSequence,
      nextSequence: record.nextSequence,
      truncated: record.outputTruncated,
      containment: record.containment,
      termination: record.termination,
    }
  }

  async raw(record: SessionRecord): Promise<{
    raw: string
    byteLength: number
    containment?: SessionRecord['containment']
    termination?: SessionRecord['termination']
  }> {
    const raw = await this.output(record.id)
    return {
      raw,
      byteLength: Buffer.byteLength(raw),
      containment: record.containment,
      termination: record.termination,
    }
  }
}
