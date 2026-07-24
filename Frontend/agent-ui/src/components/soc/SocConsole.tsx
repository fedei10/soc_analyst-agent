'use client'

import { UserButton, useUser } from '@clerk/nextjs'
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  Clock3,
  FileSearch,
  ListChecks,
  MessageSquare,
  Plus,
  RefreshCw,
  Send,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
  X
} from 'lucide-react'
import {
  FormEvent,
  KeyboardEvent,
  ReactNode,
  useEffect,
  useMemo,
  useState
} from 'react'
import { toast } from 'sonner'

import {
  createInvestigation,
  executeApprovedResponse,
  getAlertSummary,
  getInvestigation,
  getInvestigationHistory,
  getLiveness,
  getWazuhHealth,
  streamAgentMessage,
  submitApproval
} from '@/api/soc'
import type {
  AlertSummary,
  ApprovalDecision,
  ChatActivity,
  ChatMessage,
  Investigation,
  InvestigationHistoryItem,
  WorkspaceView,
  WazuhHealth
} from '@/types/soc'

const SUGGESTED_PROMPTS = [
  'Use Wazuh to review current high-severity alerts.',
  'Investigate failed logins followed by a successful login on agent 001.',
  'Search archived Wazuh logs for suspicious SSH or PowerShell activity.',
  'Review detection gaps and propose safe response steps for alert ID '
]

function createMessage(
  role: ChatMessage['role'],
  content: string,
  extra: Partial<ChatMessage> = {}
): ChatMessage {
  return {
    id: crypto.randomUUID(),
    role,
    content,
    createdAt: Date.now(),
    ...extra
  }
}

function titleCase(value: string): string {
  return value
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function statusTone(status?: string | null): string {
  if (!status) return 'neutral'
  if (['healthy', 'completed', 'approved', 'success'].includes(status))
    return 'success'
  if (['failed', 'unhealthy', 'rejected', 'critical'].includes(status))
    return 'danger'
  if (['awaiting_approval', 'running', 'high', 'medium'].includes(status))
    return 'warning'
  return 'neutral'
}

function StatusBadge({ value }: { value?: string | null }) {
  return (
    <span className={`status-badge status-${statusTone(value)}`}>
      {value ? titleCase(value) : 'Not available'}
    </span>
  )
}

function Panel({
  title,
  icon,
  action,
  children,
  className = ''
}: {
  title: string
  icon: ReactNode
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`soc-panel ${className}`}>
      <header className="panel-heading">
        <div className="panel-title">
          {icon}
          <h2>{title}</h2>
        </div>
        {action}
      </header>
      {children}
    </section>
  )
}

function ResultDetails({ result }: { result: Record<string, unknown> }) {
  const summary = typeof result.summary === 'string' ? result.summary : null
  const primaryFields = [
    'status',
    'classification',
    'severity',
    'confidence',
    'source_ip',
    'target_user',
    'disposition',
    'containment_recommended',
    'false_positive',
    'escalate'
  ]
  const facts = Object.entries(result).filter(
    ([key, value]) =>
      !['summary', ...primaryFields].includes(key) &&
      value !== null &&
      value !== '' &&
      (!Array.isArray(value) || value.length > 0)
  )

  return (
    <div className="result-details">
      {summary && <p className="result-summary">{summary}</p>}
      <div className="result-facts">
        {primaryFields.map((key) => {
          const value = result[key]
          if (value === undefined || value === null) return null
          return (
            <div key={key}>
              <span>{titleCase(key)}</span>
              <strong>
                {typeof value === 'boolean'
                  ? value
                    ? 'Yes'
                    : 'No'
                  : String(value)}
              </strong>
            </div>
          )
        })}
      </div>
      {facts.length > 0 && (
        <details className="raw-result">
          <summary>View complete structured result</summary>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </details>
      )}
    </div>
  )
}

function ChatMessageItem({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user'
  const isError = message.role === 'error'
  return (
    <article
      className={`chat-message ${isUser ? 'chat-user' : isError ? 'chat-error' : 'chat-agent'}`}
    >
      <div className="message-avatar">
        {isUser ? (
          <Terminal size={16} />
        ) : isError ? (
          <AlertTriangle size={16} />
        ) : (
          <Bot size={16} />
        )}
      </div>
      <div className="message-content">
        <div className="message-meta">
          <strong>
            {isUser ? 'You' : isError ? 'Agent error' : 'SOC Analyst'}
          </strong>
          <time>
            {new Date(message.createdAt).toLocaleTimeString([], {
              hour: '2-digit',
              minute: '2-digit'
            })}
          </time>
        </div>
        <p>{message.content}</p>
        {message.response && Object.keys(message.response).length > 0 && (
          <ResultDetails result={message.response} />
        )}
        {message.activities && message.activities.length > 0 && (
          <details className="message-activity">
            <summary>Investigation activity</summary>
            <div className="trace-list">
              {message.activities.map((activity, index) => (
                <div
                  key={activity.id || `${activity.tool || 'agent'}-${index}`}
                >
                  {activity.status === 'failed' ? (
                    <AlertTriangle size={14} />
                  ) : (
                    <CheckCircle2 size={14} />
                  )}
                  <span>{activity.label}</span>
                </div>
              ))}
            </div>
          </details>
        )}
      </div>
    </article>
  )
}

function Metric({
  label,
  value,
  detail
}: {
  label: string
  value: string | number
  detail?: string
}) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail && <small>{detail}</small>}
    </div>
  )
}

export default function SocConsole() {
  const { user, isLoaded: userLoaded } = useUser()
  const [view, setView] = useState<WorkspaceView>('chat')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatBusy, setChatBusy] = useState(false)
  const [conversationId, setConversationId] = useState('')
  const [liveActivities, setLiveActivities] = useState<ChatActivity[]>([])
  const [liveAnswer, setLiveAnswer] = useState('')
  const [backendOnline, setBackendOnline] = useState(false)
  const [wazuhHealth, setWazuhHealth] = useState<WazuhHealth | null>(null)
  const [alertSummary, setAlertSummary] = useState<AlertSummary | null>(null)
  const [environmentBusy, setEnvironmentBusy] = useState(false)
  const [environmentHydrated, setEnvironmentHydrated] = useState(false)
  const [investigation, setInvestigation] = useState<Investigation | null>(null)
  const [investigationHistory, setInvestigationHistory] = useState<
    InvestigationHistoryItem[]
  >([])
  const [pendingApprovalTotal, setPendingApprovalTotal] = useState(0)
  const [historyBusy, setHistoryBusy] = useState(false)
  const [investigationBusy, setInvestigationBusy] = useState(false)
  const [alertId, setAlertId] = useState('')
  const [agentId, setAgentId] = useState('')
  const [modifiedActions, setModifiedActions] = useState('')
  const userId = user?.id
  const conversationStorageKey = `tsage_conversation_id:${userId || 'none'}`
  const investigationStorageKey = `tsage_investigation_id:${userId || 'none'}`

  const activityTrace = useMemo(
    () =>
      messages
        .flatMap((message) => message.activities || [])
        .filter(
          (activity, index, all) =>
            all.findIndex((candidate) =>
              activity.id && candidate.id
                ? candidate.id === activity.id
                : candidate.tool === activity.tool &&
                  candidate.label === activity.label
            ) === index
        ),
    [messages]
  )

  async function refreshEnvironment() {
    setEnvironmentBusy(true)
    try {
      await getLiveness()
      setBackendOnline(true)
    } catch {
      setBackendOnline(false)
      setWazuhHealth(null)
      setAlertSummary(null)
      setEnvironmentBusy(false)
      setEnvironmentHydrated(true)
      return
    }

    const [healthResult, summaryResult] = await Promise.allSettled([
      getWazuhHealth(),
      getAlertSummary()
    ])
    setWazuhHealth(
      healthResult.status === 'fulfilled' ? healthResult.value : null
    )
    setAlertSummary(
      summaryResult.status === 'fulfilled' ? summaryResult.value : null
    )
    setEnvironmentBusy(false)
    setEnvironmentHydrated(true)
  }

  async function refreshInvestigationHistory() {
    setHistoryBusy(true)
    try {
      const [history, pending] = await Promise.all([
        getInvestigationHistory(),
        getInvestigationHistory(1, 'awaiting_approval')
      ])
      setInvestigationHistory(history.items)
      setPendingApprovalTotal(pending.total)
    } catch {
      setInvestigationHistory([])
      setPendingApprovalTotal(0)
    } finally {
      setHistoryBusy(false)
    }
  }

  useEffect(() => {
    if (!userLoaded || !userId) return
    setMessages([])
    setInvestigation(null)
    const storedInvestigation = sessionStorage.getItem(investigationStorageKey)
    const storedConversation =
      sessionStorage.getItem(conversationStorageKey) || crypto.randomUUID()
    setConversationId(storedConversation)
    sessionStorage.setItem(conversationStorageKey, storedConversation)
    void refreshEnvironment()
    void refreshInvestigationHistory()

    if (storedInvestigation) {
      void getInvestigation(storedInvestigation)
        .then(setInvestigation)
        .catch(() => sessionStorage.removeItem(investigationStorageKey))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userLoaded, userId])

  if (!userLoaded || !userId) {
    return <main className="auth-page">Loading account...</main>
  }

  function resetChat() {
    const nextConversationId = crypto.randomUUID()
    setMessages([])
    setChatInput('')
    setConversationId(nextConversationId)
    setLiveActivities([])
    setLiveAnswer('')
    sessionStorage.setItem(conversationStorageKey, nextConversationId)
  }

  async function handleChatSubmit(event?: FormEvent) {
    event?.preventDefault()
    const prompt = chatInput.trim()
    if (!prompt || chatBusy) return

    setMessages((current) => [...current, createMessage('user', prompt)])
    setChatInput('')
    setChatBusy(true)
    setLiveActivities([])
    setLiveAnswer('')

    try {
      const activeConversationId = conversationId || crypto.randomUUID()
      if (!conversationId) {
        setConversationId(activeConversationId)
        sessionStorage.setItem(conversationStorageKey, activeConversationId)
      }
      const result = await streamAgentMessage(prompt, activeConversationId, {
        onActivity: (activity) => {
          setLiveActivities((current) => {
            const withoutPrior = current.filter(
              (item) =>
                !(activity.id && item.id
                  ? item.id === activity.id
                  : item.tool === activity.tool &&
                    item.label === activity.label)
            )
            return [...withoutPrior, activity]
          })
        },
        onToken: (content) => setLiveAnswer((current) => `${current}${content}`)
      })
      setMessages((current) => [
        ...current,
        createMessage('agent', result.assistant_message, {
          response: result.response,
          tools: result.tools_used,
          activities: result.activities
        })
      ])
      setConversationId(result.conversation_id)
      sessionStorage.setItem(conversationStorageKey, result.conversation_id)
      if (result.investigation) {
        setInvestigation(result.investigation)
        sessionStorage.setItem(
          investigationStorageKey,
          result.investigation.investigation_id
        )
        void refreshInvestigationHistory()
      }
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : 'The SOC agent did not respond.'
      setMessages((current) => [...current, createMessage('error', message)])
    } finally {
      setChatBusy(false)
      setLiveActivities([])
      setLiveAnswer('')
    }
  }

  function handleChatKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (
      event.key === 'Enter' &&
      !event.shiftKey &&
      !event.nativeEvent.isComposing
    ) {
      event.preventDefault()
      void handleChatSubmit()
    }
  }

  async function handleCreateInvestigation(event: FormEvent) {
    event.preventDefault()

    setInvestigationBusy(true)
    try {
      const result = await createInvestigation(
        alertId.trim(),
        agentId.trim() || undefined
      )
      setInvestigation(result)
      sessionStorage.setItem(investigationStorageKey, result.investigation_id)
      void refreshInvestigationHistory()
      if (result.approval_request) {
        setModifiedActions(
          JSON.stringify(result.approval_request.proposed_actions, null, 2)
        )
      }
      toast.success(`Investigation ${result.investigation_id} started.`)
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'Investigation could not be started.'
      )
    } finally {
      setInvestigationBusy(false)
    }
  }

  async function refreshInvestigation() {
    if (!investigation) return
    setInvestigationBusy(true)
    try {
      const result = await getInvestigation(investigation.investigation_id)
      setInvestigation(result)
      void refreshInvestigationHistory()
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'Investigation could not be refreshed.'
      )
    } finally {
      setInvestigationBusy(false)
    }
  }

  async function selectInvestigation(investigationId: string) {
    if (investigationBusy) return
    setInvestigationBusy(true)
    try {
      const result = await getInvestigation(investigationId)
      setInvestigation(result)
      sessionStorage.setItem(investigationStorageKey, investigationId)
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'Investigation could not be loaded.'
      )
    } finally {
      setInvestigationBusy(false)
    }
  }

  async function handleApproval(decision: ApprovalDecision) {
    const request = investigation?.approval_request
    if (!investigation || !request) return

    let changes: Record<string, unknown>[] | undefined
    if (decision === 'modify') {
      try {
        changes = JSON.parse(modifiedActions) as Record<string, unknown>[]
        if (!Array.isArray(changes)) throw new Error('Expected an array')
      } catch {
        toast.error('Modified actions must be a valid JSON array.')
        return
      }
    }

    setInvestigationBusy(true)
    try {
      const result = await submitApproval(investigation.investigation_id, {
        decision,
        approval_id: request.approval_id,
        ...(changes ? { modified_actions: changes } : {})
      })
      setInvestigation(result)
      void refreshInvestigationHistory()
      toast.success(`Decision recorded: ${decision}.`)
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'Approval could not be submitted.'
      )
    } finally {
      setInvestigationBusy(false)
    }
  }

  async function handleExecution() {
    const request = investigation?.approval_request
    if (!investigation || !request) return

    setInvestigationBusy(true)
    try {
      const result = await executeApprovedResponse(
        investigation.investigation_id,
        request.approval_id
      )
      setInvestigation(result)
      void refreshInvestigationHistory()
      toast.success('Approved response executed and verification recorded.')
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'Approved response could not be executed.'
      )
    } finally {
      setInvestigationBusy(false)
    }
  }

  return (
    <div className="soc-shell">
      <aside className="soc-sidebar">
        <div className="brand-lockup">
          <div className="brand-symbol">
            <Shield size={21} strokeWidth={2.2} />
          </div>
          <div>
            <strong>TSAGE</strong>
            <span>Security operations</span>
          </div>
        </div>

        <nav className="workspace-nav" aria-label="SOC workspace">
          <button
            className={view === 'chat' ? 'active' : ''}
            onClick={() => setView('chat')}
          >
            <MessageSquare size={17} />
            Agent workspace
          </button>
          <button
            className={view === 'alert-triage' ? 'active' : ''}
            onClick={() => setView('alert-triage')}
          >
            <ShieldAlert size={17} />
            Alert Triage
          </button>
          <button
            className={view === 'investigations' ? 'active' : ''}
            onClick={() => {
              setView('investigations')
              void refreshInvestigationHistory()
            }}
          >
            <FileSearch size={17} />
            Investigations
            {pendingApprovalTotal > 0 && (
              <span className="nav-count" title="Pending human approvals">
                {pendingApprovalTotal}
              </span>
            )}
          </button>
        </nav>

        <div className="sidebar-spacer" />

        <div className="service-indicator">
          <span
            className={`service-dot ${backendOnline ? 'online' : 'offline'}`}
          />
          <div>
            <strong>{backendOnline ? 'API connected' : 'API offline'}</strong>
            <span>
              {!environmentHydrated
                ? 'Loading configuration'
                : wazuhHealth?.status === 'healthy'
                  ? 'Wazuh services healthy'
                  : 'Wazuh connection unavailable'}
            </span>
          </div>
        </div>
      </aside>

      <main className="soc-main">
        <header className="soc-topbar">
          <div>
            <span className="eyebrow">SOC operations console</span>
            <h1>
              {view === 'chat'
                ? 'Agent workspace'
                : view === 'alert-triage'
                  ? 'Alert Triage'
                  : 'Investigation workflow'}
            </h1>
          </div>
          <div className="topbar-actions">
            <div className="clerk-controls">
              <UserButton />
            </div>
            <div
              className={`health-pill ${wazuhHealth?.status === 'healthy' ? 'healthy' : 'unhealthy'}`}
            >
              <Server size={15} />
              {wazuhHealth?.status === 'healthy'
                ? 'Wazuh online'
                : 'Wazuh offline'}
            </div>
            <button
              className="icon-button"
              onClick={() => void refreshEnvironment()}
              title="Refresh environment"
              aria-label="Refresh environment"
              disabled={environmentBusy}
            >
              <RefreshCw size={17} className={environmentBusy ? 'spin' : ''} />
            </button>
          </div>
        </header>

        {view === 'chat' ? (
          <div className="chat-workspace">
            <section className="chat-column">
              <div className="orchestrator-bar">
                <div className="orchestrator-node">
                  <Bot size={17} />
                  <div>
                    <strong>SOC conversational analyst</strong>
                    <span>Conversation memory and read-only Wazuh tools</span>
                  </div>
                </div>
                <ChevronRight size={16} />
                <div
                  className="specialist-nodes"
                  aria-label="SOC workflow boundaries"
                >
                  <span>Formal investigation</span>
                  <span>Human approval gate</span>
                </div>
              </div>

              <div className="chat-feed">
                {messages.length === 0 ? (
                  <div className="chat-empty">
                    <div className="empty-icon">
                      <ShieldAlert size={26} />
                    </div>
                    <span>Conversational SOC</span>
                    <h2>Analyst ready</h2>
                    <p>
                      Ask about current Wazuh evidence or continue an active
                      investigation in the same conversation.
                    </p>
                    <div className="prompt-list">
                      {SUGGESTED_PROMPTS.map((prompt) => (
                        <button
                          key={prompt}
                          onClick={() => setChatInput(prompt)}
                        >
                          <ChevronRight size={15} />
                          {prompt}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  messages.map((message) => (
                    <ChatMessageItem key={message.id} message={message} />
                  ))
                )}
                {chatBusy &&
                  (liveAnswer ? (
                    <article className="chat-message chat-agent live-response">
                      <div className="message-avatar">
                        <Bot size={16} />
                      </div>
                      <div className="message-content">
                        <div className="message-meta">
                          <strong>SOC Analyst</strong>
                        </div>
                        <p>{liveAnswer}</p>
                      </div>
                    </article>
                  ) : (
                    <div className="agent-working">
                      <span />
                      <span />
                      <span />
                      {liveActivities.at(-1)?.label ||
                        'Understanding the request'}
                    </div>
                  ))}
              </div>

              <form className="chat-composer" onSubmit={handleChatSubmit}>
                <textarea
                  value={chatInput}
                  onChange={(event) => setChatInput(event.target.value)}
                  onKeyDown={handleChatKeyDown}
                  placeholder="Ask the SOC analyst to inspect Wazuh or continue an investigation..."
                  rows={3}
                  disabled={chatBusy}
                />
                <div className="composer-footer">
                  <div>
                    <span className="read-only-indicator">
                      <Shield size={13} />
                      Agent tools are read-only
                    </span>
                    {messages.length > 0 && (
                      <button
                        type="button"
                        className="text-button"
                        onClick={resetChat}
                      >
                        <Plus size={13} />
                        New conversation
                      </button>
                    )}
                  </div>
                  <button
                    className="send-button"
                    type="submit"
                    disabled={!chatInput.trim() || chatBusy}
                    title="Send query"
                  >
                    <Send size={17} />
                    Send
                  </button>
                </div>
              </form>
            </section>

            <aside className="context-column">
              <Panel title="Environment" icon={<Activity size={16} />}>
                <div className="environment-grid">
                  <Metric
                    label="Alerts"
                    value={alertSummary?.total_alerts ?? '-'}
                    detail="Last 24 hours"
                  />
                  <Metric
                    label="Agent"
                    value="Conversational"
                    detail="Tool loop + memory"
                  />
                </div>
                <div className="connection-list">
                  <div>
                    <span
                      className={`service-dot ${backendOnline ? 'online' : 'offline'}`}
                    />
                    <span>FastAPI</span>
                    <strong>{backendOnline ? 'Ready' : 'Offline'}</strong>
                  </div>
                  <div>
                    <span
                      className={`service-dot ${wazuhHealth?.status === 'healthy' ? 'online' : 'offline'}`}
                    />
                    <span>Wazuh</span>
                    <strong>
                      {wazuhHealth?.status === 'healthy'
                        ? 'Ready'
                        : 'Unavailable'}
                    </strong>
                  </div>
                </div>
              </Panel>

              <Panel
                title="Investigation activity"
                icon={<Terminal size={16} />}
              >
                {[...activityTrace, ...liveActivities].length > 0 ? (
                  <div className="trace-list">
                    {[...activityTrace, ...liveActivities].map(
                      (activity, index) => (
                        <div
                          key={
                            activity.id ||
                            `${activity.tool || 'agent'}-${index}`
                          }
                        >
                          {activity.status === 'completed' ? (
                            <CheckCircle2 size={14} />
                          ) : activity.status === 'failed' ? (
                            <AlertTriangle size={14} />
                          ) : (
                            <RefreshCw size={14} className="spin" />
                          )}
                          <span>{activity.label}</span>
                        </div>
                      )
                    )}
                  </div>
                ) : (
                  <div className="panel-empty">
                    <Terminal size={20} />
                    <span>No investigation activity yet</span>
                  </div>
                )}
              </Panel>

              {wazuhHealth?.status === 'unhealthy' && (
                <div className="diagnostic-callout">
                  <AlertTriangle size={17} />
                  <div>
                    <strong>Wazuh tunnel required</strong>
                    <span>
                      Start the PC1 SSH tunnel, then refresh this workspace.
                    </span>
                  </div>
                </div>
              )}
            </aside>
          </div>
        ) : view === 'alert-triage' ? (
          <div className="investigation-workspace">
            <div className="investigation-empty">
              <ShieldAlert size={28} />
              <h2>Alert Triage</h2>
              <p>No triage run selected</p>
            </div>
          </div>
        ) : (
          <div className="investigation-workspace">
            <Panel title="Start investigation" icon={<FileSearch size={17} />}>
              <form
                className="investigation-form"
                onSubmit={handleCreateInvestigation}
              >
                <div className="field">
                  <label htmlFor="alert-id">Wazuh alert document ID</label>
                  <input
                    id="alert-id"
                    value={alertId}
                    onChange={(event) => setAlertId(event.target.value)}
                    placeholder="Required"
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="agent-id">Agent ID</label>
                  <input
                    id="agent-id"
                    value={agentId}
                    onChange={(event) => setAgentId(event.target.value)}
                    placeholder="001"
                    pattern="[0-9]+"
                  />
                </div>
                <button
                  className="button button-primary"
                  type="submit"
                  disabled={investigationBusy}
                >
                  <CircleGauge size={16} />
                  Run workflow
                </button>
              </form>
            </Panel>

            <Panel
              title="Investigation history"
              icon={<Clock3 size={17} />}
              action={
                <button
                  className="icon-button"
                  onClick={() => void refreshInvestigationHistory()}
                  title="Refresh investigation history"
                  aria-label="Refresh investigation history"
                  disabled={historyBusy}
                >
                  <RefreshCw size={16} className={historyBusy ? 'spin' : ''} />
                </button>
              }
            >
              <div className="history-list">
                {investigationHistory.map((item) => (
                  <button
                    key={item.investigation_id}
                    className={
                      investigation?.investigation_id === item.investigation_id
                        ? 'active'
                        : ''
                    }
                    onClick={() =>
                      void selectInvestigation(item.investigation_id)
                    }
                    disabled={investigationBusy}
                  >
                    <div>
                      <strong>{item.alert_id}</strong>
                      <span>{item.investigation_id}</span>
                    </div>
                    <div className="history-tiers">
                      {item.completed_tiers.length > 0
                        ? item.completed_tiers
                            .map((tier) => tier.toUpperCase())
                            .join(' / ')
                        : 'Queued'}
                    </div>
                    <StatusBadge value={item.status} />
                    <time>
                      {item.updated_at
                        ? new Date(item.updated_at).toLocaleString()
                        : '-'}
                    </time>
                    <ChevronRight size={16} />
                  </button>
                ))}
                {!historyBusy && investigationHistory.length === 0 && (
                  <div className="panel-empty">
                    <Clock3 size={20} />
                    <span>No persisted investigations</span>
                  </div>
                )}
              </div>
            </Panel>

            {investigation ? (
              <>
                <section className="investigation-header">
                  <div>
                    <span className="eyebrow">Active investigation</span>
                    <h2>{investigation.investigation_id}</h2>
                  </div>
                  <button
                    className="icon-button"
                    onClick={() => void refreshInvestigation()}
                    title="Refresh investigation"
                    aria-label="Refresh investigation"
                    disabled={investigationBusy}
                  >
                    <RefreshCw
                      size={17}
                      className={investigationBusy ? 'spin' : ''}
                    />
                  </button>
                </section>

                <div className="summary-grid">
                  <Metric
                    label="Status"
                    value={titleCase(investigation.status)}
                  />
                  <Metric
                    label="Current stage"
                    value={titleCase(investigation.current_stage)}
                  />
                  <Metric
                    label="Severity"
                    value={
                      investigation.severity
                        ? titleCase(investigation.severity)
                        : '-'
                    }
                  />
                  <Metric
                    label="Confidence"
                    value={
                      investigation.confidence === null ||
                      investigation.confidence === undefined
                        ? '-'
                        : `${Math.round(investigation.confidence * 100)}%`
                    }
                  />
                </div>

                <div className="investigation-columns">
                  <Panel title="Agent results" icon={<Bot size={17} />}>
                    <div className="agent-result-list">
                      {[
                        ['L1 triage', investigation.l1_result],
                        ['L2 investigation', investigation.l2_result],
                        ['L3 analysis', investigation.l3_result]
                      ].map(([label, result]) =>
                        result ? (
                          <details key={label as string} open>
                            <summary>
                              <CheckCircle2 size={15} />
                              {label as string}
                            </summary>
                            <ResultDetails
                              result={result as Record<string, unknown>}
                            />
                          </details>
                        ) : null
                      )}
                      {!investigation.l1_result && (
                        <div className="panel-empty">
                          <Bot size={20} />
                          <span>No agent result was produced</span>
                        </div>
                      )}
                    </div>
                  </Panel>

                  <Panel title="Audit trail" icon={<ListChecks size={17} />}>
                    <div className="audit-list">
                      {investigation.audit_events
                        .slice()
                        .reverse()
                        .map((event) => (
                          <div key={`${event.timestamp}-${event.event}`}>
                            <span className="audit-marker" />
                            <div>
                              <strong>{titleCase(event.event)}</strong>
                              <span>{titleCase(event.stage)}</span>
                              <time>
                                {new Date(event.timestamp).toLocaleString()}
                              </time>
                            </div>
                          </div>
                        ))}
                      {investigation.audit_events.length === 0 && (
                        <div className="panel-empty">
                          <Clock3 size={20} />
                          <span>No transitions recorded</span>
                        </div>
                      )}
                    </div>
                  </Panel>
                </div>

                {investigation.errors.length > 0 && (
                  <Panel
                    title="Workflow errors"
                    icon={<AlertTriangle size={17} />}
                    className="error-panel"
                  >
                    <pre>{JSON.stringify(investigation.errors, null, 2)}</pre>
                  </Panel>
                )}

                {investigation.approval_request &&
                  investigation.pending_nodes.includes('human_approval') && (
                    <Panel
                      title="Human approval checkpoint"
                      icon={<ShieldAlert size={17} />}
                      action={<StatusBadge value="awaiting_approval" />}
                      className="approval-panel"
                    >
                      <div className="approval-actions">
                        {investigation.approval_request.proposed_actions.map(
                          (action) => (
                            <article
                              key={`${action.action_type}-${action.target}`}
                            >
                              <div>
                                <strong>{titleCase(action.action_type)}</strong>
                                <StatusBadge value={action.risk_level} />
                              </div>
                              <span>{action.target}</span>
                              <code>{action.execution_preview}</code>
                              <p>{action.reason}</p>
                              <small>{action.operational_impact}</small>
                            </article>
                          )
                        )}
                      </div>
                      <div className="approval-form">
                        <div className="field field-full">
                          <label htmlFor="modified-actions">
                            Modified actions JSON
                          </label>
                          <textarea
                            id="modified-actions"
                            value={modifiedActions}
                            onChange={(event) =>
                              setModifiedActions(event.target.value)
                            }
                            rows={6}
                          />
                        </div>
                        <div className="approval-buttons field-full">
                          <button
                            className="button button-danger"
                            onClick={() => void handleApproval('reject')}
                            disabled={investigationBusy}
                          >
                            <X size={16} />
                            Reject all
                          </button>
                          <button
                            className="button button-secondary"
                            onClick={() => void handleApproval('modify')}
                            disabled={investigationBusy}
                          >
                            <ListChecks size={16} />
                            Save changes for re-review
                          </button>
                          <button
                            className="button button-primary"
                            onClick={() => void handleApproval('approve')}
                            disabled={investigationBusy}
                          >
                            <Check size={16} />
                            Approve response
                          </button>
                        </div>
                      </div>
                    </Panel>
                  )}

                {investigation.approval_request &&
                  investigation.pending_nodes.includes(
                    'execution_authorization'
                  ) && (
                    <Panel
                      title="Approved response"
                      icon={<ShieldAlert size={17} />}
                      action={<StatusBadge value="approved" />}
                      className="approval-panel"
                    >
                      <div className="approval-actions">
                        {investigation.approval_request.proposed_actions.map(
                          (action) => (
                            <article
                              key={`${action.action_type}-${action.target}`}
                            >
                              <div>
                                <strong>{titleCase(action.action_type)}</strong>
                                <StatusBadge value={action.risk_level} />
                              </div>
                              <span>{action.target}</span>
                              <code>{action.execution_preview}</code>
                              <p>{action.reason}</p>
                            </article>
                          )
                        )}
                      </div>
                      <div className="approval-buttons">
                        <button
                          className="button button-danger"
                          onClick={() => void handleExecution()}
                          disabled={investigationBusy}
                        >
                          <Terminal size={16} />
                          Execute approved response
                        </button>
                      </div>
                    </Panel>
                  )}

                {investigation.final_report && (
                  <Panel title="Final report" icon={<CheckCircle2 size={17} />}>
                    <pre className="report-output">
                      {JSON.stringify(investigation.final_report, null, 2)}
                    </pre>
                  </Panel>
                )}
              </>
            ) : (
              <div className="investigation-empty">
                <FileSearch size={28} />
                <h2>No investigation selected</h2>
                <p>
                  Enter a real Wazuh alert document ID to run the LangGraph
                  workflow.
                </p>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
