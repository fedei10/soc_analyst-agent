import type {
  AgentChatResponse,
  AlertSummary,
  ApprovalInput,
  ChatActivity,
  Investigation,
  WazuhHealth
} from '@/types/soc'

const BACKEND_ROOT = '/api/tsage'

export class APIError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string
  ) {
    super(message)
    this.name = 'APIError'
  }
}

function headers(token?: string, hasBody = false): HeadersInit {
  const value: Record<string, string> = {}
  if (token) value.Authorization = `Bearer ${token}`
  if (hasBody) value['Content-Type'] = 'application/json'
  return value
}

async function request<T>(
  path: string,
  token?: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${BACKEND_ROOT}${path}`, {
    ...options,
    headers: {
      ...headers(token, Boolean(options.body)),
      ...(options.headers || {})
    },
    cache: 'no-store'
  })
  const body = await response.json().catch(() => ({}))

  if (!response.ok) {
    const error = body?.error
    throw new APIError(
      error?.message || body?.detail || `Request failed (${response.status})`,
      response.status,
      error?.code
    )
  }

  return (body?.data ?? body) as T
}

export function getLiveness(): Promise<{ status: string }> {
  return request('/health')
}

export async function getWazuhHealth(token: string): Promise<WazuhHealth> {
  const response = await fetch(`${BACKEND_ROOT}/api/v1/health/wazuh`, {
    headers: headers(token),
    cache: 'no-store'
  })
  const body = await response.json().catch(() => ({}))
  if (body?.service === 'wazuh') return body as WazuhHealth
  if (!response.ok) {
    throw new APIError(
      body?.error?.message || 'Unable to check Wazuh.',
      response.status,
      body?.error?.code
    )
  }
  return body as WazuhHealth
}

export function getAlertSummary(
  token: string,
  hours = 24
): Promise<AlertSummary> {
  return request(`/api/v1/alerts/summary?hours=${hours}`, token)
}

export async function streamAgentMessage(
  token: string,
  message: string,
  conversationId: string,
  handlers: {
    onActivity?: (activity: ChatActivity) => void
    onToken?: (content: string) => void
  } = {}
): Promise<AgentChatResponse> {
  const response = await fetch(
    `${BACKEND_ROOT}/api/v1/soc/orchestrator/chat/stream`,
    {
      method: 'POST',
      headers: headers(token, true),
      body: JSON.stringify({
        message,
        conversation_id: conversationId
      }),
      cache: 'no-store'
    }
  )

  if (!response.ok || !response.body) {
    const body = await response.json().catch(() => ({}))
    throw new APIError(
      body?.error?.message || `Request failed (${response.status})`,
      response.status,
      body?.error?.code
    )
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let finalResult: AgentChatResponse | null = null

  function processEvent(block: string) {
    const lines = block.split('\n')
    const event = lines
      .find((line) => line.startsWith('event:'))
      ?.slice(6)
      .trim()
    const data = lines
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim())
      .join('\n')
    if (!event || !data) return

    const payload = JSON.parse(data)
    if (event === 'activity') {
      handlers.onActivity?.(payload as ChatActivity)
    } else if (event === 'token') {
      handlers.onToken?.(String(payload.content || ''))
    } else if (event === 'final') {
      finalResult = payload as AgentChatResponse
    } else if (event === 'error') {
      throw new APIError(
        String(payload.message || 'The SOC agent did not respond.'),
        503
      )
    }
  }

  while (true) {
    const { value, done } = await reader.read()
    buffer += decoder.decode(value, { stream: !done }).replaceAll('\r\n', '\n')
    let boundary = buffer.indexOf('\n\n')
    while (boundary !== -1) {
      const block = buffer.slice(0, boundary)
      buffer = buffer.slice(boundary + 2)
      if (block.trim()) processEvent(block)
      boundary = buffer.indexOf('\n\n')
    }
    if (done) break
  }

  if (buffer.trim()) processEvent(buffer)
  if (!finalResult) {
    throw new APIError('The SOC stream ended without a final response.', 502)
  }
  return finalResult
}

export function sendAgentMessage(
  token: string,
  message: string,
  conversationId: string
): Promise<AgentChatResponse> {
  return request('/api/v1/soc/orchestrator/chat', token, {
    method: 'POST',
    body: JSON.stringify({
      message,
      conversation_id: conversationId
    })
  })
}

export function createInvestigation(
  token: string,
  alertId: string,
  agentId?: string
): Promise<Investigation> {
  return request('/api/v1/investigations', token, {
    method: 'POST',
    body: JSON.stringify({
      alert_id: alertId,
      agent_id: agentId || null
    })
  })
}

export function getInvestigation(
  token: string,
  investigationId: string
): Promise<Investigation> {
  return request(
    `/api/v1/investigations/${encodeURIComponent(investigationId)}`,
    token
  )
}

export function submitApproval(
  token: string,
  investigationId: string,
  input: ApprovalInput
): Promise<Investigation> {
  return request(
    `/api/v1/investigations/${encodeURIComponent(investigationId)}/approval`,
    token,
    {
      method: 'POST',
      body: JSON.stringify(input)
    }
  )
}
