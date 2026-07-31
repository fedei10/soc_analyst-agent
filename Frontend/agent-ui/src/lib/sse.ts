/** Pure SSE framing helpers, kept separate from fetch so they are testable. */

export interface SSEEvent {
  event: string
  data: string
}

/**
 * Split whatever complete `event:`/`data:` blocks the buffer holds.
 * Returns the leftover tail, which may be a partially received block.
 */
export function splitSSEBlocks(buffer: string): {
  blocks: string[]
  rest: string
} {
  const normalized = buffer.replaceAll('\r\n', '\n')
  const blocks: string[] = []
  let rest = normalized
  let boundary = rest.indexOf('\n\n')
  while (boundary !== -1) {
    const block = rest.slice(0, boundary)
    rest = rest.slice(boundary + 2)
    if (block.trim()) blocks.push(block)
    boundary = rest.indexOf('\n\n')
  }
  return { blocks, rest }
}

/**
 * Parse one block. Multi-line `data:` fields are joined with newlines, per the
 * SSE spec, so a pretty-printed JSON payload survives the trip.
 */
export function parseSSEBlock(block: string): SSEEvent | null {
  const lines = block.split('\n')
  const event = lines
    .find((line) => line.startsWith('event:'))
    ?.slice(6)
    .trim()
  const data = lines
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).trim())
    .join('\n')
  if (!event || !data) return null
  return { event, data }
}
