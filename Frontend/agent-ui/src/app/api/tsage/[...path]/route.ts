import type { NextRequest } from 'next/server'

export const runtime = 'nodejs'
export const maxDuration = 120
export const dynamic = 'force-dynamic'

const backendUrl = (
  process.env.TSAGE_API_URL || 'http://127.0.0.1:8000'
).replace(/\/$/, '')

const FORWARDED_REQUEST_HEADERS = [
  'accept',
  'authorization',
  'content-type',
  'x-request-id'
]

const FORWARDED_RESPONSE_HEADERS = [
  'content-type',
  'www-authenticate',
  'x-request-id'
]

async function proxy(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  const { path } = await context.params
  const pathname = path.map(encodeURIComponent).join('/')
  const target = `${backendUrl}/${pathname}${request.nextUrl.search}`
  const requestHeaders = new Headers()

  FORWARDED_REQUEST_HEADERS.forEach((name) => {
    const value = request.headers.get(name)
    if (value) requestHeaders.set(name, value)
  })

  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers: requestHeaders,
      body:
        request.method === 'GET' || request.method === 'HEAD'
          ? undefined
          : await request.arrayBuffer(),
      cache: 'no-store',
      signal: AbortSignal.timeout(120_000)
    })
    const responseHeaders = new Headers()
    FORWARDED_RESPONSE_HEADERS.forEach((name) => {
      const value = upstream.headers.get(name)
      if (value) responseHeaders.set(name, value)
    })

    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders
    })
  } catch (error) {
    const timedOut =
      error instanceof Error &&
      (error.name === 'TimeoutError' || error.name === 'AbortError')
    return Response.json(
      {
        error: {
          code: timedOut ? 'upstream_timeout' : 'upstream_unavailable',
          message: timedOut
            ? 'The SOC workflow exceeded the 120-second response limit.'
            : 'The TSAGE backend connection was interrupted.',
          detail: null
        },
        request_id: null
      },
      { status: timedOut ? 504 : 502 }
    )
  }
}

export const GET = proxy
export const POST = proxy
export const PUT = proxy
export const PATCH = proxy
export const DELETE = proxy
