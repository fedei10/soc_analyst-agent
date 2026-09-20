import { type FC } from 'react'
import ReactMarkdown from 'react-markdown'
import rehypeSanitize from 'rehype-sanitize'
import remarkGfm from 'remark-gfm'

import { cn } from '@/lib/utils'

import { type MarkdownRendererProps } from './types'
import { inlineComponents } from './inlineStyles'
import { components } from './styles'

// rehype-raw used to sit in front of rehype-sanitize here. It turned
// model-authored raw HTML (`<br>`, `<svg ...>`, `<img onerror=...>`) into real
// nodes that the sanitiser then had to strip back out, leaving either a hole
// or a bare tag in the message. react-markdown's default is to ignore raw HTML
// outright, which is both safer and what a SOC transcript wants: untrusted
// evidence never becomes markup. rehype-sanitize stays as defence in depth
// over the tree the remark plugins produce.
const MarkdownRenderer: FC<MarkdownRendererProps> = ({
  children,
  classname,
  inline = false
}) => (
  <ReactMarkdown
    className={cn('markdown-body', classname)}
    components={{ ...(inline ? inlineComponents : components) }}
    remarkPlugins={[remarkGfm]}
    rehypePlugins={[rehypeSanitize]}
  >
    {children}
  </ReactMarkdown>
)

export default MarkdownRenderer
