'use client'

import { UserButton, useUser } from '@clerk/nextjs'
import {
  Activity,
  AlertTriangle,
  Bell,
  Bot,
  CheckCircle2,
  ChevronRight,
  ClipboardList,
  FileText,
  GitBranch,
  History,
  LayoutDashboard,
  MessageSquare,
  Network,
  Plus,
  RefreshCw,
  ScrollText,
  Send,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  Sparkles,
  TrendingDown,
  Terminal,
  Workflow,
  Zap
} from 'lucide-react'
import {
  FormEvent,
  KeyboardEvent,
  ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState
} from 'react'
import { toast } from 'sonner'

import {
  explainCommand,
  getAlertSummary,
  getAssistantCommands,
  getInvestigation,
  getLiveness,
  getReports,
  getShiftHandoff,
  getSOCOverview,
  getSOCPlatform,
  getWazuhHealth,
  streamAgentMessage
} from '@/api/soc'
import type {
  AlertSummary,
  AnalystReport,
  AssistantCommand,
  ChatActivity,
  ChatMessage,
  CommandExplanation,
  Investigation,
  ShiftHandoff,
  SOCOverview,
  SOCPlatform,
  WorkspaceView,
  WazuhHealth
} from '@/types/soc'
import PlatformWorkspaces from '@/components/soc/PlatformWorkspaces'
import MarkdownRenderer from '@/components/ui/typography/MarkdownRenderer'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle
} from '@/components/ui/dialog'

const SUGGESTED_PROMPTS = [
  '/alerts --min-level 10 --hours 24',
  '/summary --hours 24',
  '/hunt 192.0.2.10 --type ip',
  '/investigate ALERT-ID --agent 001'
]

// A real investigation runs monitor + two LLM stages behind a worker that
// wakes every few seconds, so the old 6 x 2s budget almost always gave up
// while the work was still in flight. Back off instead, up to ~5 minutes.
const INVESTIGATION_POLL_ATTEMPTS = 40
const INVESTIGATION_POLL_INTERVAL_MS = 2000
const INVESTIGATION_POLL_MAX_INTERVAL_MS = 15000
const TERMINAL_INVESTIGATION_STATUSES = new Set([
  'awaiting_approval',
  'completed',
  'escalated',
  'failed',
  'rejected'
])

const WORKSPACE_TITLES: Record<WorkspaceView, string> = {
  overview: 'Operations overview',
  chat: 'SOC Assistant',
  alerts: 'Alerts',
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
    [
      'queued',
      'waiting_verification',
      'awaiting_approval',
      'escalated',
      'running',
      'high',
      'medium',
      'suspicious'
    ].includes(status)
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
        {message.investigation && (
          <div className="result-details investigation-summary">
            <div className="result-facts">
              <div>
                <span>Investigation</span>
                <strong>{message.investigation.investigation_id}</strong>
              </div>
              <div>
                <span>Status</span>
                <StatusBadge value={message.investigation.status} />
              </div>
              <div>
                <span>Stage</span>
                <strong>
                  {titleCase(message.investigation.current_stage)}
                </strong>
              </div>
            </div>
          </div>
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

function OpsClock() {
  const [now, setNow] = useState<Date | null>(null)

  useEffect(() => {
    const tick = () => setNow(new Date())
    tick()
    const timer = setInterval(tick, 1000)
    return () => clearInterval(timer)
  }, [])

  if (!now) return null
  const utc = now.toISOString()
  return (
    <div className="ops-clock" title="Coordinated Universal Time">
      <strong>UTC</strong>
      {utc.slice(11, 19)}
      <span>{utc.slice(0, 10)}</span>
    </div>
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
  // Generation gate for in-flight investigation polls. Unmount and chat reset
  // bump it, so loops started before the bump retire themselves without also
  // disabling loops started after it.
  const pollGenerationRef = useRef(0)
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
  const [handoff, setHandoff] = useState<ShiftHandoff | null>(null)
  const [handoffBusy, setHandoffBusy] = useState(false)
  const [explainInput, setExplainInput] = useState('')
  const [explanation, setExplanation] = useState<CommandExplanation | null>(
    null
  )
  const [explainBusy, setExplainBusy] = useState(false)
  const [reports, setReports] = useState<AnalystReport[]>([])
  const [reportsBusy, setReportsBusy] = useState(false)
  const [openReport, setOpenReport] = useState<AnalystReport | null>(null)
  const userId = user?.id
  const conversationStorageKey = `tsage_conversation_id:${userId || 'none'}`
  const pendingApprovalTotal =
    platform?.pending_approvals.filter((item) => item.status === 'pending')
      .length ?? 0

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

  function updateInvestigationProgress(
    investigationId: string,
    status: string,
    currentStage: string
  ) {
    setMessages((current) =>
      current.map((message) =>
        message.investigation?.investigation_id === investigationId
          ? {
              ...message,
              investigation: {
                ...message.investigation,
                status,
                current_stage: currentStage
              }
            }
          : message
      )
    )
  }

  async function trackInvestigation(investigation: Investigation) {
    const generation = pollGenerationRef.current
    // The user navigated away, signed out, or reset the chat - stop polling
    // rather than keep writing into state nobody is showing any more.
    const live = () => pollGenerationRef.current === generation
    let delay = INVESTIGATION_POLL_INTERVAL_MS
    for (let attempt = 0; attempt < INVESTIGATION_POLL_ATTEMPTS; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, delay))
      if (!live()) return
      delay = Math.min(delay * 1.5, INVESTIGATION_POLL_MAX_INTERVAL_MS)
      try {
        const latest = await getInvestigation(investigation.investigation_id)
        if (!live()) return
        updateInvestigationProgress(
          latest.investigation_id,
          latest.status,
          latest.current_stage
        )
        if (TERMINAL_INVESTIGATION_STATUSES.has(latest.status)) break
      } catch {
        break
      }
    }
    if (!live()) return
    await refreshOverview()
    await refreshPlatform()
  }

  function handleInvestigationQueued(investigation: Investigation) {
    setMessages((current) => [
      ...current,
      createMessage(
        'agent',
        `Investigation ${investigation.investigation_id} was queued for alert ${investigation.alert_id || 'unknown'}.`,
        { investigation }
      )
    ])
    setView('chat')
    void trackInvestigation(investigation)
  }

  useEffect(
    () => () => {
      pollGenerationRef.current += 1
    },
    []
  )

  useEffect(() => {
    if (!userLoaded || !userId) return
    setMessages([])
    const storedConversation =
      sessionStorage.getItem(conversationStorageKey) || createClientId()
    setConversationId(storedConversation)
    sessionStorage.setItem(conversationStorageKey, storedConversation)
    void refreshEnvironment()
    void refreshOverview()
    void refreshPlatform()
    void getAssistantCommands()
      .then((catalog) => setAssistantCommands(catalog.items))
      .catch(() => setAssistantCommands([]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userLoaded, userId])

  if (!userLoaded || !userId) {
    return <main className="auth-page">Loading account...</main>
  }

  function resetChat() {
    // Abandon polls for investigations whose chat cards are about to vanish.
    pollGenerationRef.current += 1
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
          investigation: result.investigation || undefined,
          tools: result.tools_used,
          activities: result.activities
        })
      ])
      setConversationId(result.conversation_id)
      sessionStorage.setItem(conversationStorageKey, result.conversation_id)
      if (result.tools_used?.includes('save_report')) {
        void refreshReports()
      }
      if (result.tools_used?.includes('start_investigation')) {
        void Promise.all([refreshOverview(), refreshPlatform()])
      }
      if (result.investigation) {
        void trackInvestigation(result.investigation)
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

  async function generateHandoff() {
    setHandoffBusy(true)
    try {
      setHandoff(await getShiftHandoff())
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'Handoff notes could not be generated.'
      )
    } finally {
      setHandoffBusy(false)
    }
  }

  async function handleExplainCommand() {
    const command = explainInput.trim()
    if (!command || explainBusy) return
    setExplainBusy(true)
    setExplanation(null)
    try {
      setExplanation(await explainCommand(command))
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'The command could not be explained.'
      )
    } finally {
      setExplainBusy(false)
    }
  }

  async function refreshReports() {
    setReportsBusy(true)
    try {
      setReports((await getReports()).items)
    } catch {
      setReports([])
    } finally {
      setReportsBusy(false)
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
            onClick={() => {
              setView('chat')
              void refreshReports()
            }}
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
            <OpsClock />
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

            <Panel
              title="Shift handoff"
              icon={<ClipboardList size={17} />}
              action={
                <button
                  className="button button-secondary"
                  onClick={() => void generateHandoff()}
                  disabled={handoffBusy}
                >
                  <RefreshCw size={14} className={handoffBusy ? 'spin' : ''} />
                  {handoff ? 'Regenerate' : 'Generate notes'}
                </button>
              }
            >
              {handoff ? (
                <div className="handoff-body">
                  <p className="result-summary">{handoff.summary}</p>
                  <div className="handoff-columns">
                    {(
                      [
                        ['Highlights', handoff.highlights],
                        ['Open items', handoff.open_items],
                        ['Recommendations', handoff.recommendations]
                      ] as const
                    ).map(([label, items]) => (
                      <div key={label} className="handoff-block">
                        <h3>{label}</h3>
                        {items.length > 0 ? (
                          <ul>
                            {items.map((item) => (
                              <li key={item}>{item}</li>
                            ))}
                          </ul>
                        ) : (
                          <span>Nothing recorded</span>
                        )}
                      </div>
                    ))}
                  </div>
                  <small className="handoff-meta">
                    Last {handoff.window_hours}h · {handoff.finding_count}{' '}
                    findings · {handoff.investigation_count} investigations ·
                    generated{' '}
                    {new Date(handoff.generated_at).toLocaleTimeString()}
                  </small>
                </div>
              ) : (
                <div className="panel-empty">
                  <ClipboardList size={20} />
                  <span>
                    Generate plain-language notes for the incoming shift
                  </span>
                </div>
              )}
            </Panel>
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

              <Panel
                title="Saved reports"
                icon={<FileText size={16} />}
                action={
                  <button
                    className="icon-button"
                    onClick={() => void refreshReports()}
                    title="Refresh saved reports"
                    aria-label="Refresh saved reports"
                    disabled={reportsBusy}
                  >
                    <RefreshCw
                      size={14}
                      className={reportsBusy ? 'spin' : ''}
                    />
                  </button>
                }
              >
                {reports.length > 0 ? (
                  <div className="overview-list">
                    {reports.map((report) => (
                      <button
                        key={report.report_id}
                        onClick={() => setOpenReport(report)}
                      >
                        <div>
                          <strong>{report.title}</strong>
                          <span>
                            {new Date(report.created_at).toLocaleString()}
                          </span>
                        </div>
                        <StatusBadge value={report.severity} />
                        <ChevronRight size={15} />
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="panel-empty">
                    <FileText size={20} />
                    <span>
                      Ask the assistant to write up and save a report - it will
                      appear here
                    </span>
                  </div>
                )}
              </Panel>

              <Panel title="Command explainer" icon={<Terminal size={16} />}>
                <div className="explainer-form">
                  <textarea
                    value={explainInput}
                    onChange={(event) => setExplainInput(event.target.value)}
                    placeholder="Paste a suspicious command line..."
                    rows={2}
                    disabled={explainBusy}
                  />
                  <button
                    className="button button-secondary"
                    onClick={() => void handleExplainCommand()}
                    disabled={!explainInput.trim() || explainBusy}
                  >
                    {explainBusy ? (
                      <RefreshCw size={14} className="spin" />
                    ) : (
                      <Terminal size={14} />
                    )}
                    Explain command
                  </button>
                </div>
                {explanation && (
                  <div className="result-details">
                    <div className="explainer-risk">
                      <StatusBadge value={explanation.risk} />
                    </div>
                    <p className="result-summary">
                      {explanation.plain_english}
                    </p>
                    {explanation.indicators.length > 0 && (
                      <p className="result-summary">
                        Indicators: {explanation.indicators.join(' · ')}
                      </p>
                    )}
                    {explanation.recommended_checks.length > 0 && (
                      <p className="result-summary">
                        Check next: {explanation.recommended_checks.join(' · ')}
                      </p>
                    )}
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
        ) : (
          <PlatformWorkspaces
            view={view}
            commands={assistantCommands}
            platform={platform}
            platformBusy={platformBusy}
            onRefreshPlatform={refreshPlatform}
            onRunCommand={openAssistantPrompt}
            onInvestigationQueued={handleInvestigationQueued}
          />
        )}
      </main>

      <Dialog
        open={openReport !== null}
        onOpenChange={(open) => {
          if (!open) setOpenReport(null)
        }}
      >
        <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
          {openReport && (
            <>
              <DialogHeader>
                <DialogTitle>{openReport.title}</DialogTitle>
              </DialogHeader>
              <div className="report-dialog-meta">
                <StatusBadge value={openReport.severity} />
                <span>{openReport.created_by}</span>
                <time>{new Date(openReport.created_at).toLocaleString()}</time>
                <a
                  className="text-button"
                  href={`/api/tsage/api/v1/reports/${encodeURIComponent(openReport.report_id)}.pdf`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <ScrollText size={13} />
                  Download PDF
                </a>
              </div>
              <div className="report-dialog-body">
                <MarkdownRenderer>{openReport.body_markdown}</MarkdownRenderer>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
