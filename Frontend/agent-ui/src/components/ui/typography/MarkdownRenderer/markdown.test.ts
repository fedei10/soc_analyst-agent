/**
 * Regression cover for how analyst messages are turned into markup.
 *
 * The SOC transcript used to render assistant text into a bare <p>, so
 * `**bold**`, `| tables |`, `### headings` and any raw `<br>`/`<svg>` the
 * model emitted reached the analyst as literal source. These checks pin the
 * plugin chain the renderer uses - notably that raw HTML is dropped rather
 * than parsed, so untrusted evidence never becomes markup.
 *
 * Written with createElement rather than JSX so it runs under the repository's
 * existing `node --experimental-strip-types --test` runner.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import ReactMarkdown from 'react-markdown'
import rehypeSanitize from 'rehype-sanitize'
import remarkGfm from 'remark-gfm'
import { Bot, ShieldAlert } from 'lucide-react'

const render = (markdown: string): string =>
  renderToStaticMarkup(
    createElement(
      ReactMarkdown,
      {
        remarkPlugins: [remarkGfm],
        rehypePlugins: [rehypeSanitize]
      },
      markdown
    )
  )

test('lucide icons render as svg elements, never as the text "svg"', () => {
  for (const icon of [Bot, ShieldAlert]) {
    const html = renderToStaticMarkup(createElement(icon, { size: 16 }))
    assert.match(html, /^<svg\b/)
    assert.ok(html.includes('</svg>'))
    // The tag name must not leak into the document as a text node.
    assert.ok(!/>svg</.test(html))
  }
})

test('bold, headings and lists render as markup', () => {
  const html = render(
    '## Findings\n\n**Confirmed** brute force\n\n- one\n- two'
  )

  assert.ok(html.includes('<h2>Findings</h2>'))
  assert.ok(html.includes('<strong>Confirmed</strong>'))
  assert.ok(html.includes('<li>one</li>'))
  assert.ok(!html.includes('**'))
  assert.ok(!html.includes('## '))
})

test('gfm tables render as a table', () => {
  const html = render('| ip | count |\n| -- | ----- |\n| 192.0.2.10 | 871 |')

  assert.ok(html.includes('<table>'))
  assert.ok(html.includes('<th>ip</th>'))
  assert.ok(html.includes('<td>192.0.2.10</td>'))
  assert.ok(!html.includes('| ip |'))
})

test('fenced code blocks keep their exact contents', () => {
  const command = 'grep -E "sshd.*Failed\\s+password" /var/log/auth.log'
  const html = render(`\`\`\`bash\n${command}\n\`\`\``)

  assert.ok(html.includes('language-bash'))
  // Backslashes and quoting in a suggested shell command survive verbatim;
  // only the HTML entity encoding of the quote differs.
  assert.ok(html.includes('Failed\\s+password'))
  assert.ok(html.includes('grep -E'))
})

test('escaped markdown is unescaped once, not shown with its backslashes', () => {
  const html = render('Escaped \\*\\*bold\\*\\* and \\### heading')

  assert.ok(html.includes('**bold**'))
  assert.ok(html.includes('### heading'))
  // The backslashes are consumed by the parser, not re-emitted.
  assert.ok(!html.includes('\\*'))
  assert.ok(!html.includes('\\#'))
})

test('raw html is dropped rather than rendered or shown as text', () => {
  const html = render(
    'before <svg width="16"><path d="M0 0h16v16H0z"/></svg> ' +
      '<br> <img src=x onerror=alert(1)> after'
  )

  assert.ok(!html.includes('<svg'))
  assert.ok(!html.includes('&lt;svg'))
  assert.ok(!html.includes('svg'))
  assert.ok(!html.includes('onerror'))
  assert.ok(html.includes('before'))
  assert.ok(html.includes('after'))
})

test('script tags and javascript: urls are sanitized away', () => {
  // Separate blocks: a line starting with <script> is an HTML block in
  // CommonMark and would swallow everything after it on the same line.
  const html = render(
    'text <script>alert(1)</script>\n\n' +
      '[click](javascript:alert(2))\n\n' +
      '[ok](https://example.com)'
  )

  assert.ok(!html.includes('<script'))
  assert.ok(!html.includes('javascript:'))
  assert.ok(html.includes('href="https://example.com"'))
})
