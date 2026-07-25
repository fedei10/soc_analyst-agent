'use client'

import { UserButton, useUser } from '@clerk/nextjs'
import {
  Activity,
  AlertTriangle,
  Bell,
  Bot,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  Clock3,
  FileSearch,
  GitBranch,
  History,
  LayoutDashboard,
  ListChecks,
  MessageSquare,
  Network,
  Plus,
  RefreshCw,
  Search,
  Send,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  Sparkles,
  TrendingDown,
  Terminal,
  Workflow,
  Zap,
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
  getAssistantCommands,
  getFinding,
  getFindings,
  getInvestigation,
  getInvestigationHistory,
  getLiveness,
  getSOCOverview,
  getSOCPlatform,
  getWazuhHealth,
  streamAgentMessage,
  submitApproval,
  submitFindingFeedback
} from '@/api/soc'
import type {
  AlertSummary,
  ApprovalDecision,
  AssistantCommand,
  ChatActivity,
  ChatMessage,
  FeedbackDisposition,
  Finding,
  Investigation,
  InvestigationHistoryItem,
  SOCOverview,
  SOCPlatform,
  WorkspaceView,
  WazuhAlert,
  WazuhHealth
} from '@/types/soc'
import PlatformWorkspaces from '@/components/soc/PlatformWorkspaces'

const FEEDBACK_OPTIONS: Array<{ value: FeedbackDisposition; label: string }> = [
  { value: 'confirmed_malicious', label: 'Confirmed malicious' },
  { value: 'confirmed_benign', label: 'Confirmed benign' },
  { value: 'expected_admin_activity', label: 'Expected admin activity' },
  { value: 'wrong_asset_context', label: 'Wrong asset context' },
  { value: 'wrong_severity', label: 'Wrong severity' },
  { value: 'duplicate_incident', label: 'Duplicate incident' },
  { value: 'insufficient_evidence', label: 'Insufficient evidence' }
]

const SUGGESTED_PROMPTS = [
  '/alerts --min-level 10 --hours 24',
  '/summary --hours 24',
  '/hunt 192.0.2.10 --type ip',
  '/investigate ALERT-ID --agent 001'
]

const WORKSPACE_TITLES: Record<WorkspaceView, string> = {
  overview: 'Operations overview',
  chat: 'SOC Assistant',
  alerts: 'Alerts',
  'alert-triage': 'Findings',
  investigations: 'Incidents',
  'threat-hunting': 'Threat Hunting',
  assets: 'Assets',
  playbooks: 'Playbooks',
  approvals: 'Approval Center',
  executions: 'Execution Center',
  integrations: 'Integrations',
  'ai-models': 'AI Models',
  'audit-log': 'Audit Log',
  settings: 'Settings'
}

function createClientId(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID()
  }
  return `id-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 10)}`
}

function createMessage(
  role: ChatMessage['role'],
  content: string,
  extra: Partial<ChatMessage> = {}
): ChatMessage {
  return {
    id: createClientId(),
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
  if (
    ['healthy', 'completed', 'approved', 'success', 'benign'].includes(status)
  )
    return 'success'
  if (
    ['failed', 'unhealthy', 'rejected', 'critical', 'malicious'].includes(
      status
    )
  )
    return 'danger'
  if (
    ['awaiting_approval', 'running', 'high', 'medium', 'suspicious'].includes(
      status
    )
  )
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

function shouldShowResultDetails(result?: Record<string, unknown>): boolean {
  if (!result || Object.keys(result).length === 0) return false
  if (result.display_mode === 'conversation') return false
  const visibleKeys = Object.keys(result).filter(
    (key) => !['intent', 'token_usage', 'display_mode'].includes(key)
  )
  return visibleKeys.length > 0
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
        {shouldShowResultDetails(message.response) && message.response && (
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
  const [view, setView] = useState<WorkspaceView>('overview')
  const [overview, setOverview] = useState<SOCOverview | null>(null)
  const [overviewBusy, setOverviewBusy] = useState(false)
  const [platform, setPlatform] = useState<SOCPlatform | null>(null)
  const [platformBusy, setPlatformBusy] = useState(false)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatBusy, setChatBusy] = useState(false)
  const [assistantCommands, setAssistantCommands] = useState<
    AssistantCommand[]
  >([])
  const [selectedCommandIndex, setSelectedCommandIndex] = useState(0)
  const [slashMenuDismissed, setSlashMenuDismissed] = useState(false)
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
  const [findings, setFindings] = useState<Finding[]>([])
  const [findingsBusy, setFindingsBusy] = useState(false)
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [findingBusy, setFindingBusy] = useState(false)
  const [feedbackNotes, setFeedbackNotes] = useState('')
  const [feedbackBusy, setFeedbackBusy] = useState(false)
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
  const visibleActivities = useMemo(() => {
    const byKey = new Map<string, ChatActivity>()
    ;[...activityTrace, ...liveActivities].forEach((activity) => {
      const key = activity.id || `${activity.tool || 'agent'}:${activity.label}`
      byKey.set(key, activity)
    })
    return Array.from(byKey.entries())
  }, [activityTrace, liveActivities])
  const slashMatches = useMemo(() => {
    const input = chatInput.trim().toLowerCase()
    if (
      slashMenuDismissed ||
      !input.startsWith('/') ||
      input.slice(1).includes(' ')
    ) {
      return []
    }
    return assistantCommands.filter((command) => {
      const searchable = [
        command.slash,
        ...command.aliases,
        command.title,
        command.description,
        command.category
      ]
        .join(' ')
        .toLowerCase()
      return input === '/' || searchable.includes(input)
    })
  }, [assistantCommands, chatInput, slashMenuDismissed])
  const pipelineMax = useMemo(
    () => Math.max(1, ...(overview?.pipeline.map((item) => item.count) || [])),
    [overview]
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

  async function refreshOverview() {
    setOverviewBusy(true)
    try {
      setOverview(await getSOCOverview())
    } catch {
      setOverview(null)
    } finally {
      setOverviewBusy(false)
    }
  }

  async function refreshPlatform() {
    setPlatformBusy(true)
    try {
      setPlatform(await getSOCPlatform())
    } catch {
      setPlatform(null)
    } finally {
      setPlatformBusy(false)
    }
  }

  useEffect(() => {
    if (!userLoaded || !userId) return
    setMessages([])
    setInvestigation(null)
    const storedInvestigation = sessionStorage.getItem(investigationStorageKey)
    const storedConversation =
      sessionStorage.getItem(conversationStorageKey) || createClientId()
    setConversationId(storedConversation)
    sessionStorage.setItem(conversationStorageKey, storedConversation)
    void refreshEnvironment()
    void refreshOverview()
    void refreshPlatform()
    void refreshInvestigationHistory()
    void getAssistantCommands()
      .then((catalog) => setAssistantCommands(catalog.items))
      .catch(() => setAssistantCommands([]))

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
    const nextConversationId = createClientId()
    setMessages([])
    setChatInput('')
    setConversationId(nextConversationId)
    setLiveActivities([])
    setLiveAnswer('')
    setSlashMenuDismissed(false)
    sessionStorage.setItem(conversationStorageKey, nextConversationId)
  }

  function selectAssistantCommand(command: AssistantCommand) {
    setChatInput(`${command.slash} `)
    setSlashMenuDismissed(true)
    setSelectedCommandIndex(0)
  }

  async function submitChatPrompt(rawPrompt: string) {
    const prompt = rawPrompt.trim()
    if (!prompt || chatBusy) return

    setMessages((current) => [...current, createMessage('user', prompt)])
    setChatInput('')
    setChatBusy(true)
    setLiveActivities([])
    setLiveAnswer('')

    try {
      const activeConversationId = conversationId || createClientId()
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

  async function handleChatSubmit(event?: FormEvent) {
    event?.preventDefault()
    await submitChatPrompt(chatInput)
  }

  function openAssistantPrompt(prompt: string) {
    setView('chat')
    if (prompt.endsWith(' ')) {
      setChatInput(prompt)
      return
    }
    void submitChatPrompt(prompt)
  }

  function investigateAlert(alert: WazuhAlert) {
    setAlertId(alert.alert_id)
    setAgentId(alert.agent_id || '')
    setView('investigations')
  }

  function openInvestigation(investigationId: string) {
    setView('investigations')
    void selectInvestigation(investigationId)
  }

  function handleChatKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (slashMatches.length > 0) {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault()
        const direction = event.key === 'ArrowDown' ? 1 : -1
        setSelectedCommandIndex(
          (current) =>
            (current + direction + slashMatches.length) % slashMatches.length
        )
        return
      }
      if (event.key === 'Tab' || event.key === 'Enter') {
        event.preventDefault()
        selectAssistantCommand(
          slashMatches[selectedCommandIndex] || slashMatches[0]
        )
        return
      }
      if (event.key === 'Escape') {
        event.preventDefault()
        setSlashMenuDismissed(true)
        return
      }
    }
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

    setInvestigationBusy(true)
    try {
      const result = await submitApproval(investigation.investigation_id, {
        decision,
        approval_id: request.approval_id
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

  async function refreshFindings() {
    setFindingsBusy(true)
    try {
      const result = await getFindings()
      setFindings(result.items)
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : 'Findings could not be loaded.'
      )
    } finally {
      setFindingsBusy(false)
    }
  }

  async function selectFinding(findingId: string) {
    if (findingBusy) return
    setFindingBusy(true)
    try {
      const result = await getFinding(findingId)
      setSelectedFinding(result)
      setFeedbackNotes('')
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : 'Finding could not be loaded.'
      )
    } finally {
      setFindingBusy(false)
    }
  }

  async function handleFindingFeedback(disposition: FeedbackDisposition) {
    if (!selectedFinding) return
    setFeedbackBusy(true)
    try {
      await submitFindingFeedback(
        selectedFinding.finding_id,
        disposition,
        feedbackNotes.trim() || undefined
      )
      toast.success('Feedback recorded.')
      setFeedbackNotes('')
      await selectFinding(selectedFinding.finding_id)
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'Feedback could not be recorded.'
      )
    } finally {
      setFeedbackBusy(false)
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
          <span className="nav-section-label">Operations</span>
          <button
            className={view === 'overview' ? 'active' : ''}
            onClick={() => {
              setView('overview')
              void refreshOverview()
            }}
          >
            <LayoutDashboard size={17} />
            Overview
          </button>
          <button
            className={view === 'chat' ? 'active' : ''}
            onClick={() => setView('chat')}
          >
            <MessageSquare size={17} />
            SOC Assistant
          </button>
          <button
            className={view === 'alerts' ? 'active' : ''}
            onClick={() => setView('alerts')}
          >
            <Bell size={17} />
            Alerts
          </button>
          <button
            className={view === 'alert-triage' ? 'active' : ''}
            onClick={() => {
              setView('alert-triage')
              void refreshFindings()
            }}
          >
            <ShieldAlert size={17} />
            Findings
          </button>
          <button
            className={view === 'investigations' ? 'active' : ''}
            onClick={() => {
              setView('investigations')
              void refreshInvestigationHistory()
            }}
          >
            <FileSearch size={17} />
            Incidents
          </button>
          <button
            className={view === 'threat-hunting' ? 'active' : ''}
            onClick={() => setView('threat-hunting')}
          >
            <Search size={17} />
            Threat Hunting
          </button>
          <button
            className={view === 'assets' ? 'active' : ''}
            onClick={() => setView('assets')}
          >
            <Server size={17} />
            Assets
          </button>

          <span className="nav-section-label">Automation</span>
          <button
            className={view === 'playbooks' ? 'active' : ''}
            onClick={() => setView('playbooks')}
          >
            <Workflow size={17} />
            Playbooks
          </button>
          <button
            className={view === 'approvals' ? 'active' : ''}
            onClick={() => {
              setView('approvals')
              void refreshPlatform()
            }}
          >
            <CheckCircle2 size={17} />
            Approval Center
            {pendingApprovalTotal > 0 && (
              <span className="nav-count" title="Pending human approvals">
                {pendingApprovalTotal}
              </span>
            )}
          </button>
          <button
            className={view === 'executions' ? 'active' : ''}
            onClick={() => {
              setView('executions')
              void refreshPlatform()
            }}
          >
            <Zap size={17} />
            Execution Center
          </button>

          <span className="nav-section-label">Platform</span>
          <button
            className={view === 'integrations' ? 'active' : ''}
            onClick={() => setView('integrations')}
          >
            <Network size={17} />
            Integrations
          </button>
          <button
            className={view === 'ai-models' ? 'active' : ''}
            onClick={() => {
              setView('ai-models')
              void refreshPlatform()
            }}
          >
            <Sparkles size={17} />
            AI Models
          </button>
          <button
            className={view === 'audit-log' ? 'active' : ''}
            onClick={() => {
              setView('audit-log')
              void refreshPlatform()
            }}
          >
            <History size={17} />
            Audit Log
          </button>
          <button
            className={view === 'settings' ? 'active' : ''}
            onClick={() => {
              setView('settings')
              void refreshPlatform()
            }}
          >
            <Settings2 size={17} />
            Settings
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
            <h1>{WORKSPACE_TITLES[view]}</h1>
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

        {view === 'overview' ? (
          <div className="overview-workspace">
            <section className="overview-heading">
              <div>
                <span className="eyebrow">Live operational picture</span>
                <h2>Security operations</h2>
                <p>
                  Current investigation workload and response readiness, with
                  Wazuh triage metrics for the last{' '}
                  {overview?.window_hours ?? 24} hours.
                </p>
              </div>
              <button
                className="icon-button"
                onClick={() => void refreshOverview()}
                title="Refresh operations overview"
                aria-label="Refresh operations overview"
                disabled={overviewBusy}
              >
                <RefreshCw size={17} className={overviewBusy ? 'spin' : ''} />
              </button>
            </section>

            <div className="overview-metrics">
              <Metric
                label="Active investigations"
                value={overview?.metrics.active_investigations?.value ?? '-'}
                detail={`${overview?.metrics.total_investigations?.value ?? 0} persisted`}
              />
              <Metric
                label="Security findings"
                value={overview?.metrics.security_findings?.value ?? '-'}
                detail={`${overview?.metrics.malicious_findings?.value ?? 0} malicious`}
              />
              <Metric
                label="Pending approvals"
                value={overview?.metrics.pending_approvals?.value ?? '-'}
                detail="Human decisions required"
              />
              <Metric
                label="Wazuh alerts"
                value={overview?.metrics.wazuh_alerts?.value ?? '-'}
                detail={
                  overview?.wazuh_status === 'available'
                    ? 'Indexer connected'
                    : 'Indexer unavailable'
                }
              />
              <Metric
                label="Executed actions"
                value={overview?.metrics.executed_actions?.value ?? '-'}
                detail="Approved response activity"
              />
            </div>

            {!overview && !overviewBusy && (
              <div className="diagnostic-callout">
                <AlertTriangle size={17} />
                <div>
                  <strong>Overview unavailable</strong>
                  <span>
                    FastAPI could not load the operations summary. Check the
                    backend connection and refresh.
                  </span>
                </div>
              </div>
            )}

            <div className="overview-columns">
              <Panel title="MAPE-K workflow" icon={<GitBranch size={17} />}>
                <div className="pipeline-list">
                  {overview?.pipeline.map((item) => (
                    <div key={item.stage}>
                      <div>
                        <span>{titleCase(item.stage)}</span>
                        <strong>{item.count}</strong>
                      </div>
                      <span className="pipeline-track">
                        <span
                          style={{
                            width: `${Math.max(
                              item.count > 0 ? 8 : 0,
                              (item.count / pipelineMax) * 100
                            )}%`
                          }}
                        />
                      </span>
                    </div>
                  ))}
                  {!overview && (
                    <div className="panel-empty">
                      <GitBranch size={20} />
                      <span>No workflow data available</span>
                    </div>
                  )}
                </div>
                {overview && (
                  <div className="severity-summary">
                    {['critical', 'high', 'medium', 'low', 'informational'].map(
                      (severity) => (
                        <div key={severity}>
                          <span>{titleCase(severity)}</span>
                          <strong>
                            {overview.severity_distribution[severity] ?? 0}
                          </strong>
                        </div>
                      )
                    )}
                  </div>
                )}
              </Panel>

              <Panel title="Alert reduction" icon={<TrendingDown size={17} />}>
                <div className="reduction-score">
                  <strong>
                    {overview?.alert_reduction.reduction_percent === null ||
                    overview?.alert_reduction.reduction_percent === undefined
                      ? '-'
                      : `${overview.alert_reduction.reduction_percent}%`}
                  </strong>
                  <span>raw alerts compressed into findings</span>
                </div>
                <div className="reduction-flow">
                  <div>
                    <span>Raw alerts</span>
                    <strong>
                      {overview?.alert_reduction.raw_alerts ?? '-'}
                    </strong>
                  </div>
                  <ChevronRight size={15} />
                  <div>
                    <span>Represented</span>
                    <strong>
                      {overview?.alert_reduction.represented_alerts ?? '-'}
                    </strong>
                  </div>
                  <ChevronRight size={15} />
                  <div>
                    <span>Findings</span>
                    <strong>{overview?.alert_reduction.findings ?? '-'}</strong>
                  </div>
                </div>
              </Panel>
            </div>

            <div className="overview-columns">
              <Panel
                title="Recent investigations"
                icon={<FileSearch size={17} />}
              >
                <div className="overview-list">
                  {overview?.recent_investigations.map((item) => (
                    <button
                      key={item.investigation_id}
                      onClick={() => {
                        setView('investigations')
                        void selectInvestigation(item.investigation_id)
                      }}
                    >
                      <div>
                        <strong>{item.alert_id}</strong>
                        <span>{item.investigation_id}</span>
                      </div>
                      <StatusBadge value={item.status} />
                      <ChevronRight size={15} />
                    </button>
                  ))}
                  {overview?.recent_investigations.length === 0 && (
                    <div className="panel-empty">
                      <FileSearch size={20} />
                      <span>No persisted investigations</span>
                    </div>
                  )}
                </div>
              </Panel>

              <Panel title="Recent findings" icon={<ShieldAlert size={17} />}>
                <div className="overview-list">
                  {overview?.recent_findings.map((item) => (
                    <button
                      key={item.finding_id}
                      onClick={() => {
                        setView('alert-triage')
                        void selectFinding(item.finding_id)
                      }}
                    >
                      <div>
                        <strong>{item.title || item.finding_id}</strong>
                        <span>
                          {item.alert_count} alert
                          {item.alert_count === 1 ? '' : 's'}
                        </span>
                      </div>
                      <StatusBadge value={item.verdict} />
                      <ChevronRight size={15} />
                    </button>
                  ))}
                  {overview?.recent_findings.length === 0 && (
                    <div className="panel-empty">
                      <ShieldAlert size={20} />
                      <span>No persisted findings</span>
                    </div>
                  )}
                </div>
              </Panel>
            </div>
          </div>
        ) : view === 'chat' ? (
          <div className="chat-workspace">
            <section className="chat-column">
              <div className="orchestrator-bar">
                <div className="orchestrator-node">
                  <Bot size={17} />
                  <div>
                    <strong>Bounded SOC command router</strong>
                    <span>Slash commands or natural-language requests</span>
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
                    <span>SOC Assistant</span>
                    <h2>Choose a capability</h2>
                    <p>
                      Type <strong>/</strong> for commands or describe the SOC
                      task in your own words.
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
                {slashMatches.length > 0 && (
                  <div
                    className="slash-command-menu"
                    id="soc-command-menu"
                    role="listbox"
                    aria-label="SOC assistant commands"
                  >
                    <div className="slash-command-heading">
                      <span>Commands</span>
                      <kbd>↑↓ select</kbd>
                      <kbd>Enter insert</kbd>
                    </div>
                    {slashMatches.map((command, index) => (
                      <button
                        key={command.name}
                        type="button"
                        role="option"
                        aria-selected={index === selectedCommandIndex}
                        className={
                          index === selectedCommandIndex ? 'selected' : ''
                        }
                        onMouseDown={(event) => event.preventDefault()}
                        onClick={() => selectAssistantCommand(command)}
                      >
                        <Terminal size={16} />
                        <div>
                          <div>
                            <strong>{command.slash}</strong>
                            <span>{command.title}</span>
                          </div>
                          <p>{command.description}</p>
                          <code>{command.usage}</code>
                        </div>
                        <small>{command.category}</small>
                      </button>
                    ))}
                  </div>
                )}
                <textarea
                  value={chatInput}
                  onChange={(event) => {
                    setChatInput(event.target.value)
                    setSlashMenuDismissed(false)
                    setSelectedCommandIndex(0)
                  }}
                  onKeyDown={handleChatKeyDown}
                  placeholder="Type / for commands or describe a SOC task..."
                  rows={3}
                  disabled={chatBusy}
                  aria-controls="soc-command-menu"
                />
                <div className="composer-footer">
                  <div>
                    <span className="read-only-indicator">
                      <Shield size={13} />
                      Commands are allowlisted; actions require approval
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
                    label="Commands"
                    value={assistantCommands.length || '-'}
                    detail="Server-managed catalog"
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
                {visibleActivities.length > 0 ? (
                  <div className="trace-list">
                    {visibleActivities.map(([key, activity]) => (
                      <div key={key}>
                        {activity.status === 'completed' ? (
                          <CheckCircle2 size={14} />
                        ) : activity.status === 'failed' ? (
                          <AlertTriangle size={14} />
                        ) : (
                          <RefreshCw size={14} className="spin" />
                        )}
                        <span>{activity.label}</span>
                      </div>
                    ))}
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
            <Panel
              title="Findings"
              icon={<ShieldAlert size={17} />}
              action={
                <button
                  className="icon-button"
                  onClick={() => void refreshFindings()}
                  title="Refresh findings"
                  aria-label="Refresh findings"
                  disabled={findingsBusy}
                >
                  <RefreshCw size={16} className={findingsBusy ? 'spin' : ''} />
                </button>
              }
            >
              <div className="history-list">
                {findings.map((item) => (
                  <button
                    key={item.finding_id}
                    className={
                      selectedFinding?.finding_id === item.finding_id
                        ? 'active'
                        : ''
                    }
                    onClick={() => void selectFinding(item.finding_id)}
                    disabled={findingBusy}
                  >
                    <div>
                      <strong>{item.finding.title}</strong>
                      <span>{item.finding_id}</span>
                    </div>
                    <div className="history-tiers">
                      {item.alert_count} alert
                      {item.alert_count === 1 ? '' : 's'}
                    </div>
                    <StatusBadge value={item.verdict.verdict} />
                    <time>{new Date(item.last_seen).toLocaleString()}</time>
                    <ChevronRight size={16} />
                  </button>
                ))}
                {!findingsBusy && findings.length === 0 && (
                  <div className="panel-empty">
                    <ShieldAlert size={20} />
                    <span>No findings in the selected window</span>
                  </div>
                )}
              </div>
            </Panel>

            {selectedFinding ? (
              <>
                <section className="investigation-header">
                  <div>
                    <span className="eyebrow">Selected finding</span>
                    <h2>{selectedFinding.finding.title}</h2>
                  </div>
                  <button
                    className="icon-button"
                    onClick={() =>
                      void selectFinding(selectedFinding.finding_id)
                    }
                    title="Refresh finding"
                    aria-label="Refresh finding"
                    disabled={findingBusy}
                  >
                    <RefreshCw
                      size={17}
                      className={findingBusy ? 'spin' : ''}
                    />
                  </button>
                </section>

                <div className="summary-grid">
                  <Metric
                    label="Severity"
                    value={titleCase(selectedFinding.severity)}
                  />
                  <Metric
                    label="Verdict"
                    value={titleCase(selectedFinding.verdict.verdict)}
                    detail={`${Math.round(selectedFinding.verdict.confidence * 100)}% confidence`}
                  />
                  <Metric
                    label="Alert count"
                    value={selectedFinding.alert_count}
                  />
                  <Metric
                    label="Escalation"
                    value={
                      selectedFinding.verdict.escalation_recommended
                        ? 'Recommended'
                        : 'Not needed'
                    }
                  />
                </div>

                <div className="investigation-columns">
                  <Panel title="Verdict" icon={<CircleGauge size={17} />}>
                    <ResultDetails
                      result={
                        selectedFinding.verdict as unknown as Record<
                          string,
                          unknown
                        >
                      }
                    />
                    {selectedFinding.verdict.false_positive_indicators.length >
                      0 && (
                      <div className="panel-empty">
                        <AlertTriangle size={16} />
                        <span>
                          {selectedFinding.verdict.false_positive_indicators.join(
                            ' '
                          )}
                        </span>
                      </div>
                    )}
                    {selectedFinding.verdict.missing_evidence.length > 0 && (
                      <div className="panel-empty">
                        <FileSearch size={16} />
                        <span>
                          {selectedFinding.verdict.missing_evidence.join(' ')}
                        </span>
                      </div>
                    )}
                  </Panel>

                  <Panel title="Enrichment" icon={<Activity size={17} />}>
                    {selectedFinding.enrichment.length > 0 ? (
                      <div className="agent-result-list">
                        {selectedFinding.enrichment.map((item, index) => (
                          <details
                            key={`${item.indicator}-${item.source}-${index}`}
                            open
                          >
                            <summary>
                              <CheckCircle2 size={15} />
                              {item.indicator} ({item.source})
                            </summary>
                            <ResultDetails
                              result={
                                item as unknown as Record<string, unknown>
                              }
                            />
                          </details>
                        ))}
                      </div>
                    ) : (
                      <div className="panel-empty">
                        <Activity size={20} />
                        <span>No indicators were enriched</span>
                      </div>
                    )}
                  </Panel>
                </div>

                <Panel title="Evidence" icon={<ListChecks size={17} />}>
                  <div className="audit-list">
                    {selectedFinding.evidence_refs.map((ref) => (
                      <div key={ref}>
                        <span className="audit-marker" />
                        <div>
                          <strong>{ref}</strong>
                        </div>
                      </div>
                    ))}
                    {selectedFinding.evidence_refs.length === 0 && (
                      <div className="panel-empty">
                        <ListChecks size={20} />
                        <span>No evidence references recorded</span>
                      </div>
                    )}
                  </div>
                </Panel>

                <Panel title="Analyst feedback" icon={<Check size={17} />}>
                  <div className="approval-form">
                    <div className="field field-full">
                      <label htmlFor="feedback-notes">Notes</label>
                      <input
                        id="feedback-notes"
                        value={feedbackNotes}
                        onChange={(event) =>
                          setFeedbackNotes(event.target.value)
                        }
                        placeholder="Optional context for this disposition"
                      />
                    </div>
                    <div
                      className="approval-buttons field-full"
                      style={{ flexWrap: 'wrap', justifyContent: 'flex-start' }}
                    >
                      {FEEDBACK_OPTIONS.map((option) => (
                        <button
                          key={option.value}
                          className="button button-secondary"
                          onClick={() =>
                            void handleFindingFeedback(option.value)
                          }
                          disabled={feedbackBusy}
                        >
                          {option.label}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="audit-list">
                    {selectedFinding.feedback.map((entry) => (
                      <div key={entry.feedback_id}>
                        <span className="audit-marker" />
                        <div>
                          <strong>{titleCase(entry.disposition)}</strong>
                          <span>
                            {entry.reviewer_user_id}
                            {entry.notes ? ` — ${entry.notes}` : ''}
                          </span>
                          <time>
                            {new Date(entry.created_at).toLocaleString()}
                          </time>
                        </div>
                      </div>
                    ))}
                    {selectedFinding.feedback.length === 0 && (
                      <div className="panel-empty">
                        <Check size={20} />
                        <span>No analyst feedback recorded yet</span>
                      </div>
                    )}
                  </div>
                </Panel>
              </>
            ) : (
              <div className="investigation-empty">
                <ShieldAlert size={28} />
                <h2>No finding selected</h2>
                <p>Select a finding to review its evidence-backed verdict.</p>
              </div>
            )}
          </div>
        ) : view === 'investigations' ? (
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
                  <Panel
                    title="MAPE-K analysis"
                    icon={<CircleGauge size={17} />}
                  >
                    <div className="agent-result-list">
                      {[
                        ['Diagnosis', investigation.diagnosis],
                        ['Remediation plan', investigation.remediation_plan],
                        ['Policy decision', investigation.policy_decision],
                        ['Verification', investigation.verification],
                        ['Rollback', investigation.rollback]
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
                      {!investigation.diagnosis && (
                        <div className="panel-empty">
                          <CircleGauge size={20} />
                          <span>No workflow analysis was produced</span>
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

                {investigation.tier_reports &&
                  investigation.tier_reports.length > 0 && (
                    <Panel
                      title="Analyst handoff reports"
                      icon={<FileSearch size={17} />}
                    >
                      <div className="agent-result-list">
                        {investigation.tier_reports.map((report) => (
                          <details key={report.report_id} open>
                            <summary>
                              <CheckCircle2 size={15} />
                              {report.tier.toUpperCase()} incident report
                            </summary>
                            <ResultDetails
                              result={
                                report as unknown as Record<string, unknown>
                              }
                            />
                          </details>
                        ))}
                      </div>
                    </Panel>
                  )}

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
                                <StatusBadge
                                  value={String(action.risk_level)}
                                />
                              </div>
                              <span>{action.target}</span>
                              <code>
                                TTL {action.ttl_seconds ?? 'not applicable'}{' '}
                                seconds
                              </code>
                              <p>
                                Evidence:{' '}
                                {action.evidence_refs.join(', ') || 'none'}
                              </p>
                            </article>
                          )
                        )}
                      </div>
                      <div className="approval-form">
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
                                <StatusBadge
                                  value={String(action.risk_level)}
                                />
                              </div>
                              <span>{action.target}</span>
                              <code>
                                TTL {action.ttl_seconds ?? 'not applicable'}{' '}
                                seconds
                              </code>
                              <p>
                                Evidence:{' '}
                                {action.evidence_refs.join(', ') || 'none'}
                              </p>
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
        ) : (
          <PlatformWorkspaces
            view={view}
            commands={assistantCommands}
            platform={platform}
            platformBusy={platformBusy}
            onRefreshPlatform={refreshPlatform}
            onOpenInvestigation={openInvestigation}
            onInvestigateAlert={investigateAlert}
            onRunCommand={openAssistantPrompt}
          />
        )}
      </main>
    </div>
  )
}
