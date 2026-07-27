import type {
  AgentChatResponse,
  AlertSummary,
  AnalystReport,
  AnalystReportList,
  ApprovalInput,
  AssistantCommandCatalog,
  ChatActivity,
  CommandExplanation,
  Investigation,
  PrioritizedVulnerabilityList,
  ServicesHealth,
  ShiftHandoff,
  SOCOverview,
  SOCPlatform,
  StorageHealth,
  WazuhAgent,
  WazuhAlert,
  WazuhCollection,
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

function headers(hasBody = false): HeadersInit {
  const value: Record<string, string> = {}
  if (hasBody) value['Content-Type'] = 'application/json'
  return value
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${BACKEND_ROOT}${path}`, {
    ...options,
    headers: {
      ...headers(Boolean(options.body)),
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

export async function getWazuhHealth(): Promise<WazuhHealth> {
  const response = await fetch(`${BACKEND_ROOT}/api/v1/health/wazuh`, {
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

export function getAlertSummary(hours = 24): Promise<AlertSummary> {
  return request(`/api/v1/alerts/summary?hours=${hours}`)
}

export function getSOCOverview(hours = 24): Promise<SOCOverview> {
  return request(`/api/v1/soc/overview?hours=${hours}`)
}

export function getSOCPlatform(): Promise<SOCPlatform> {
  return request('/api/v1/soc/platform')
}

export function getAlerts(
  hours = 24,
  minLevel = 0,
  limit = 50,
  query?: string
): Promise<WazuhCollection<WazuhAlert>> {
  const params = new URLSearchParams({
    hours: String(hours),
    min_level: String(minLevel),
    limit: String(limit)
  })
  if (query) params.set('q', query)
  return request(`/api/v1/alerts?${params.toString()}`)
}

export function getAgents(
  limit = 50,
  query?: string
): Promise<WazuhCollection<WazuhAgent>> {
  const params = new URLSearchParams({ limit: String(limit), offset: '0' })
  if (query) params.set('q', query)
  return request(`/api/v1/agents?${params.toString()}`)
}

async function healthRequest<T>(path: string): Promise<T> {
  const response = await fetch(`${BACKEND_ROOT}${path}`, { cache: 'no-store' })
  const body = await response.json().catch(() => ({}))
  if (body?.status) return body as T
  throw new APIError(
    body?.error?.message || `Request failed (${response.status})`,
    response.status,
    body?.error?.code
  )
}

export function getServicesHealth(): Promise<ServicesHealth> {
  return healthRequest('/api/v1/health/services')
}

export function getStorageHealth(): Promise<StorageHealth> {
  return healthRequest('/api/v1/health/storage')
}

export function getAssistantCommands(): Promise<AssistantCommandCatalog> {
  return request('/api/v1/soc/assistant/commands')
}

export async function streamAgentMessage(
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
      headers: headers(true),
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
        503,
        payload.code ? String(payload.code) : undefined
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
  message: string,
  conversationId: string
): Promise<AgentChatResponse> {
  return request('/api/v1/soc/orchestrator/chat', {
    method: 'POST',
    body: JSON.stringify({
      message,
      conversation_id: conversationId
    })
  })
}

export function submitApproval(
  investigationId: string,
  input: ApprovalInput
): Promise<Investigation> {
  return request(
    `/api/v1/investigations/${encodeURIComponent(investigationId)}/approval`,
    {
      method: 'POST',
      body: JSON.stringify(input)
    }
  )
}

export function getShiftHandoff(hours = 8): Promise<ShiftHandoff> {
  return request(`/api/v1/soc/handoff?hours=${hours}`)
}

export function explainCommand(command: string): Promise<CommandExplanation> {
  return request('/api/v1/soc/explain-command', {
    method: 'POST',
    body: JSON.stringify({ command })
  })
}

export function getPrioritizedVulnerabilities(): Promise<PrioritizedVulnerabilityList> {
  return request('/api/v1/vulnerabilities/prioritized')
}

export function testTelegramConnector(): Promise<{ sent: boolean }> {
  return request('/api/v1/soc/telegram/test', { method: 'POST' })
}

export function getReports(limit = 20): Promise<AnalystReportList> {
  return request(`/api/v1/reports?limit=${limit}`)
}

export function getReport(reportId: string): Promise<AnalystReport> {
  return request(`/api/v1/reports/${encodeURIComponent(reportId)}`)
}
