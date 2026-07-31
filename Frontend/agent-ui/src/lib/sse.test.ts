import assert from 'node:assert/strict'
import { test } from 'node:test'

import { parseSSEBlock, splitSSEBlocks } from './sse.ts'

test('splits complete blocks and keeps the partial tail', () => {
  const { blocks, rest } = splitSSEBlocks(
    'event: token\ndata: {"content":"a"}\n\nevent: token\ndata: {"cont'
  )
  assert.equal(blocks.length, 1)
  assert.equal(blocks[0], 'event: token\ndata: {"content":"a"}')
  assert.equal(rest, 'event: token\ndata: {"cont')
})

test('normalizes CRLF framing', () => {
  const { blocks } = splitSSEBlocks('event: final\r\ndata: {"ok":true}\r\n\r\n')
  assert.deepEqual(parseSSEBlock(blocks[0]), {
    event: 'final',
    data: '{"ok":true}'
  })
})

test('joins multi-line data payloads', () => {
  const parsed = parseSSEBlock('event: final\ndata: {\ndata: "a": 1\ndata: }')
  assert.equal(parsed?.data, '{\n"a": 1\n}')
  assert.deepEqual(JSON.parse(parsed!.data), { a: 1 })
})

test('ignores heartbeat and comment-only blocks', () => {
  assert.equal(parseSSEBlock(': keep-alive'), null)
  assert.equal(parseSSEBlock('event: token'), null)
  assert.equal(splitSSEBlocks('\n\n\n\n').blocks.length, 0)
})
