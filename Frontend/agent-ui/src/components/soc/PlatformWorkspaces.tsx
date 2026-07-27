'use client'

import {
  Activity,
  Bot,
  Box,
  Check,
  CheckCircle2,
  Clock3,
  Database,
  ExternalLink,
  FileClock,
  Gauge,
  History,
  Network,
  Play,
  RefreshCw,
  Search,
  Send,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  X
} from 'lucide-react'
import { FormEvent, ReactNode, useEffect, useState } from 'react'
import { toast } from 'sonner'

import {
  getAgents,
  getAlerts,
  getPrioritizedVulnerabilities,
  getServicesHealth,
  getStorageHealth,
  submitApproval,
  testTelegramConnector
} from '@/api/soc'
import type {
  AssistantCommand,
  PrioritizedVulnerability,
  ServicesHealth,
  SOCPlatform,
  StorageHealth,
  WazuhAgent,
  WazuhAlert,
  WorkspaceView
} from '@/types/soc'

function titleCase(value: string): string {
  return value
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function tone(value?: string | null): string {
  if (!value) return 'neutral'
  if (
    [
      'healthy',
      'active',
      'completed',
      'executed',
      'approved',
      'success'
    ].includes(value)
  )
    return 'success'
  if (
    ['failed', 'unhealthy', 'critical', 'rejected', 'disconnected'].includes(
      value
    )
  )
    return 'danger'
  if (
    ['pending', 'awaiting_approval', 'proposed', 'degraded', 'high'].includes(
      value
    )
  )
    return 'warning'
  return 'neutral'
}

function Status({ value }: { value?: string | null }) {
  return (
    <span className={`status-badge status-${tone(value)}`}>
      {value ? titleCase(value) : 'Unknown'}
    </span>
  )
}

function WorkspaceHeader({
  eyebrow,
  title,
  detail,
  action
}: {
  eyebrow: string
  title: string
  detail: string
  action?: ReactNode
}) {
  return (
    <section className="platform-heading">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
        <p>{detail}</p>
      </div>
      {action}
    </section>
  )
}

function Panel({
  title,
  icon,
  action,
  children
}: {
  title: string
  icon: ReactNode
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="soc-panel">
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

function EmptyState({
  icon,
  title,
  detail
}: {
  icon: ReactNode
  title: string
  detail: string
}) {
  return (
    <div className="platform-empty">
      {icon}
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  )
}

interface PlatformWorkspacesProps {
  view: WorkspaceView
  commands: AssistantCommand[]
  platform: SOCPlatform | null
  platformBusy: boolean
  onRefreshPlatform: () => Promise<void>
  onRunCommand: (prompt: string) => void
}

export default function PlatformWorkspaces({
  view,
  commands,
  platform,
  platformBusy,
  onRefreshPlatform,
  onRunCommand
}: PlatformWorkspacesProps) {
  const [alerts, setAlerts] = useState<WazuhAlert[]>([])
  const [alertTotal, setAlertTotal] = useState(0)
  const [alertsBusy, setAlertsBusy] = useState(false)
  const [agents, setAgents] = useState<WazuhAgent[]>([])
  const [agentTotal, setAgentTotal] = useState(0)
  const [agentQuery, setAgentQuery] = useState('')
  const [agentsBusy, setAgentsBusy] = useState(false)
  const [vulns, setVulns] = useState<PrioritizedVulnerability[]>([])
  const [vulnsBusy, setVulnsBusy] = useState(false)
  const [telegramTestBusy, setTelegramTestBusy] = useState(false)
  const [services, setServices] = useState<ServicesHealth | null>(null)
  const [storage, setStorage] = useState<StorageHealth | null>(null)
  const [healthBusy, setHealthBusy] = useState(false)

  async function loadAlerts() {
    setAlertsBusy(true)
    try {
      const result = await getAlerts(24, 7, 10)
      setAlerts(result.affected_items)
      setAlertTotal(result.total_affected_items)
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : 'Alerts could not be loaded.'
      )
    } finally {
      setAlertsBusy(false)
    }
  }

  async function loadAgents() {
    setAgentsBusy(true)
    try {
      const result = await getAgents(50, agentQuery.trim() || undefined)
      setAgents(result.affected_items)
      setAgentTotal(result.total_affected_items)
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : 'Assets could not be loaded.'
      )
    } finally {
      setAgentsBusy(false)
    }
  }

  async function loadVulnerabilities() {
    setVulnsBusy(true)
    try {
      setVulns((await getPrioritizedVulnerabilities()).items)
    } catch {
      setVulns([])
    } finally {
      setVulnsBusy(false)
    }
  }

  async function handleTelegramTest() {
    setTelegramTestBusy(true)
    try {
      await testTelegramConnector()
      toast.success('Test message sent. Check your Telegram chat.')
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'The Telegram test message could not be sent.'
      )
    } finally {
      setTelegramTestBusy(false)
    }
  }

  async function loadHealth() {
    setHealthBusy(true)
    const [serviceResult, storageResult] = await Promise.allSettled([
      getServicesHealth(),
      getStorageHealth()
    ])
    setServices(
      serviceResult.status === 'fulfilled' ? serviceResult.value : null
    )
    setStorage(
      storageResult.status === 'fulfilled' ? storageResult.value : null
    )
    setHealthBusy(false)
  }

  useEffect(() => {
    if (view === 'alerts' && alerts.length === 0) void loadAlerts()
    if (view === 'assets' && agents.length === 0) {
      void loadAgents()
      void loadVulnerabilities()
    }
    if (view === 'integrations') void loadHealth()
    // Each workspace loads its bounded data only when first opened.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view])

  function handleAgentSearch(event: FormEvent) {
    event.preventDefault()
    void loadAgents()
  }

  async function handleApproval(
    investigationId: string,
    approvalId: string,
    decision: 'approve' | 'reject'
  ) {
    try {
      await submitApproval(investigationId, {
        approval_id: approvalId,
        decision
      })
      toast.success(
        decision === 'approve'
          ? 'Response plan approved.'
          : 'Response plan rejected.'
      )
      await onRefreshPlatform()
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : 'Decision could not be saved.'
      )
    }
  }

  if (view === 'alerts') {
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="Wazuh indexer"
          title="Alerts"
          detail="Quick glance at the most recent level 7+ events. Use the SOC Assistant to filter, correlate, or hunt."
          action={
            <div className="header-actions">
              {platform?.wazuh_dashboard_url && (
                <a
                  className="button button-secondary"
                  href={platform.wazuh_dashboard_url}
                  target="_blank"
                  rel="noreferrer"
                >
                  <ExternalLink size={14} />
                  Open in Wazuh
                </a>
              )}
              <button
                className="icon-button"
                onClick={() => void loadAlerts()}
                disabled={alertsBusy}
                title="Refresh alerts"
                aria-label="Refresh alerts"
              >
                <RefreshCw size={17} className={alertsBusy ? 'spin' : ''} />
              </button>
            </div>
          }
        />
        <Panel
          title={`${alertTotal} matching alerts (last 24h, level 7+)`}
          icon={<ShieldAlert size={17} />}
        >
          <div className="platform-table">
            {alerts.map((alert) => (
              <article key={alert.alert_id}>
                <div className="table-primary">
                  <strong>{alert.description}</strong>
                  <span>
                    {alert.agent_name || alert.agent_id || 'Unknown agent'} ·
                    Rule {alert.rule_id}
                  </span>
                </div>
                <Status value={`level_${alert.rule_level}`} />
                <span>{alert.source_ip || alert.target_user || '-'}</span>
                <time>{new Date(alert.timestamp).toLocaleString()}</time>
              </article>
            ))}
            {!alertsBusy && alerts.length === 0 && (
              <EmptyState
                icon={<ShieldAlert size={24} />}
                title="No matching alerts"
                detail="Nothing at level 7+ in the last 24 hours."
              />
            )}
          </div>
        </Panel>
      </div>
    )
  }

  if (view === 'assets') {
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="Endpoint inventory"
          title="Assets"
          detail="Wazuh agents registered with the connected manager."
          action={
            <div className="header-actions">
              {platform?.wazuh_dashboard_url && (
                <a
                  className="button button-secondary"
                  href={platform.wazuh_dashboard_url}
                  target="_blank"
                  rel="noreferrer"
                >
                  <ExternalLink size={14} />
                  Open in Wazuh
                </a>
              )}
              <button
                className="icon-button"
                onClick={() => void loadAgents()}
                disabled={agentsBusy}
                title="Refresh assets"
                aria-label="Refresh assets"
              >
                <RefreshCw size={17} className={agentsBusy ? 'spin' : ''} />
              </button>
            </div>
          }
        />
        <Panel
          title={`${agentTotal} registered assets`}
          icon={<Server size={17} />}
        >
          <form className="compact-search" onSubmit={handleAgentSearch}>
            <Search size={15} />
            <input
              value={agentQuery}
              onChange={(event) => setAgentQuery(event.target.value)}
              placeholder="Search by agent name or address"
            />
            <button className="button button-secondary" type="submit">
              Search
            </button>
          </form>
          <div className="asset-grid">
            {agents.map((agent) => (
              <article key={agent.id}>
                <header>
                  <div>
                    <strong>{agent.name || `Agent ${agent.id}`}</strong>
                    <span>{agent.ip || 'No address reported'}</span>
                  </div>
                  <Status value={agent.status} />
                </header>
                <dl>
                  <div>
                    <dt>Agent ID</dt>
                    <dd>{agent.id}</dd>
                  </div>
                  <div>
                    <dt>Operating system</dt>
                    <dd>{agent.os?.name || '-'}</dd>
                  </div>
                  <div>
                    <dt>Version</dt>
                    <dd>{agent.version || '-'}</dd>
                  </div>
                  <div>
                    <dt>Last keepalive</dt>
                    <dd>
                      {agent.lastKeepAlive
                        ? new Date(agent.lastKeepAlive).toLocaleString()
                        : '-'}
                    </dd>
                  </div>
                </dl>
              </article>
            ))}
            {!agentsBusy && agents.length === 0 && (
              <EmptyState
                icon={<Server size={24} />}
                title="No agents returned"
                detail="Check the Wazuh manager connection or search filter."
              />
            )}
          </div>
        </Panel>

        <Panel
          title="Vulnerability priorities"
          icon={<ShieldAlert size={17} />}
          action={
            <button
              className="icon-button"
              onClick={() => void loadVulnerabilities()}
              disabled={vulnsBusy}
              title="Refresh vulnerability priorities"
              aria-label="Refresh vulnerability priorities"
            >
              <RefreshCw size={16} className={vulnsBusy ? 'spin' : ''} />
            </button>
          }
        >
          <div className="vuln-list">
            {vulns.map((vuln, index) => (
              <article key={`${vuln.cve}-${vuln.agent_id}-${index}`}>
                <header>
                  <strong>{vuln.cve}</strong>
                  {vuln.known_exploited && (
                    <span className="status-badge status-danger">
                      Actively exploited
                    </span>
                  )}
                  <Status value={vuln.severity.toLowerCase()} />
                  <span className="vuln-score">
                    {vuln.priority_score.toFixed(1)}
                  </span>
                </header>
                <p>
                  {vuln.package || 'unknown package'} on{' '}
                  {vuln.agent_name || vuln.agent_id || 'unknown agent'}
                  {vuln.epss != null &&
                    ` - EPSS ${(vuln.epss * 100).toFixed(1)}%`}
                  {vuln.cvss != null && ` - CVSS ${vuln.cvss}`}
                </p>
                <span>{vuln.reasons.join(' ')}</span>
              </article>
            ))}
            {!vulnsBusy && vulns.length === 0 && (
              <EmptyState
                icon={<ShieldAlert size={24} />}
                title="No vulnerability data"
                detail="Requires the Wazuh vulnerability module (4.8+) and an indexer connection."
              />
            )}
          </div>
        </Panel>
      </div>
    )
  }

  if (view === 'playbooks') {
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="Controlled workflows"
          title="Playbooks"
          detail="Server-managed SOC capabilities available to the orchestrator."
        />
        <div className="playbook-grid">
          {commands.map((command) => (
            <article key={command.name} className="soc-panel">
              <header>
                <Terminal size={17} />
                <Status value={command.category.toLowerCase()} />
              </header>
              <strong>{command.title}</strong>
              <p>{command.description}</p>
              <code>{command.usage}</code>
              <button
                className="button button-secondary"
                onClick={() => onRunCommand(`${command.slash} `)}
              >
                <Play size={14} />
                Open in assistant
              </button>
            </article>
          ))}
        </div>
      </div>
    )
  }

  if (view === 'approvals') {
    const pending =
      platform?.pending_approvals.filter((item) => item.status === 'pending') ||
      []
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="Human in the loop"
          title="Approval Center"
          detail="Review proposed response actions before execution authorization."
          action={
            <button
              className="icon-button"
              onClick={() => void onRefreshPlatform()}
              disabled={platformBusy}
              title="Refresh approvals"
              aria-label="Refresh approvals"
            >
              <RefreshCw size={17} className={platformBusy ? 'spin' : ''} />
            </button>
          }
        />
        <div className="platform-summary">
          <div>
            <span>Pending</span>
            <strong>{pending.length}</strong>
          </div>
          <div>
            <span>Approved</span>
            <strong>
              {platform?.pending_approvals.filter(
                (item) => item.status === 'approve'
              ).length || 0}
            </strong>
          </div>
          <div>
            <span>Rejected</span>
            <strong>
              {platform?.pending_approvals.filter(
                (item) => item.status === 'reject'
              ).length || 0}
            </strong>
          </div>
        </div>
        <Panel title="Pending decisions" icon={<Clock3 size={17} />}>
          <div className="approval-queue">
            {pending.map((approval) => (
              <article key={approval.approval_id}>
                <header>
                  <div className="queue-title">
                    <strong>{approval.investigation_id}</strong>
                    <span>
                      {approval.proposed_actions.length} proposed action
                      {approval.proposed_actions.length === 1 ? '' : 's'}
                    </span>
                  </div>
                  <Status value={approval.required_role || 'pending'} />
                </header>
                <div className="queue-actions">
                  {approval.proposed_actions.map((action) => (
                    <div key={action.action_id}>
                      <strong>{titleCase(action.action_type)}</strong>
                      <span>{action.target}</span>
                      <small>Risk {action.risk_level}</small>
                    </div>
                  ))}
                </div>
                <footer>
                  <span>
                    Expires {new Date(approval.expires_at).toLocaleString()}
                  </span>
                  <div>
                    <button
                      className="button button-danger"
                      onClick={() =>
                        void handleApproval(
                          approval.investigation_id,
                          approval.approval_id,
                          'reject'
                        )
                      }
                    >
                      <X size={14} />
                      Reject
                    </button>
                    <button
                      className="button button-primary"
                      onClick={() =>
                        void handleApproval(
                          approval.investigation_id,
                          approval.approval_id,
                          'approve'
                        )
                      }
                    >
                      <Check size={14} />
                      Approve
                    </button>
                  </div>
                </footer>
              </article>
            ))}
            {!platformBusy && pending.length === 0 && (
              <EmptyState
                icon={<CheckCircle2 size={24} />}
                title="No pending approvals"
                detail="Proposed response actions will appear here."
              />
            )}
          </div>
        </Panel>
      </div>
    )
  }

  if (view === 'executions') {
    const actions = platform?.response_actions || []
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="Response operations"
          title="Execution Center"
          detail="Track proposed, approved, rejected, and executed response actions."
          action={
            <button
              className="icon-button"
              onClick={() => void onRefreshPlatform()}
              disabled={platformBusy}
              title="Refresh executions"
              aria-label="Refresh executions"
            >
              <RefreshCw size={17} className={platformBusy ? 'spin' : ''} />
            </button>
          }
        />
        <div className="platform-summary">
          {['awaiting_approval', 'approved', 'executed', 'rejected'].map(
            (status) => (
              <div key={status}>
                <span>{titleCase(status)}</span>
                <strong>
                  {actions.filter((item) => item.status === status).length}
                </strong>
              </div>
            )
          )}
        </div>
        <Panel title="Response action history" icon={<Activity size={17} />}>
          <div className="platform-table action-table">
            {actions.map((action, index) => (
              <article
                key={action.action_id || `${action.investigation_id}-${index}`}
              >
                <div className="table-primary">
                  <strong>
                    {titleCase(action.action_type || 'response action')}
                  </strong>
                  <span>{action.investigation_id}</span>
                </div>
                <Status value={action.status} />
                <span>{action.target || '-'}</span>
                <span>Risk {action.risk_level ?? '-'}</span>
              </article>
            ))}
            {!platformBusy && actions.length === 0 && (
              <EmptyState
                icon={<Activity size={24} />}
                title="No response actions"
                detail="Actions created by approved incident plans will appear here."
              />
            )}
          </div>
        </Panel>
      </div>
    )
  }

  if (view === 'integrations') {
    const integrations = [
      {
        name: 'Wazuh',
        detail: 'Manager API and OpenSearch indexer',
        status: services?.services.wazuh?.status,
        icon: <ShieldAlert size={18} />
      },
      {
        name: 'Central LLM',
        detail: services?.services.central_llm?.detail || 'Inference provider',
        status: services?.services.central_llm?.status,
        icon: <Sparkles size={18} />
      },
      {
        name: 'PostgreSQL',
        detail: 'Investigations, reports, conversations, and audit data',
        status: storage?.postgresql,
        icon: <Database size={18} />
      },
      {
        name: 'Redis',
        detail: 'Ephemeral cache, progress replay, locks, and rate limits',
        status: storage?.redis,
        icon: <Network size={18} />
      },
      {
        name: 'Telegram',
        detail:
          services?.services.telegram?.detail ||
          'Alert push and /alerts, /status chat commands',
        status: services?.services.telegram?.status,
        icon: <Send size={18} />,
        action:
          services?.services.telegram?.status === 'healthy' ? (
            <button
              className="button button-secondary"
              onClick={(event) => {
                event.stopPropagation()
                void handleTelegramTest()
              }}
              disabled={telegramTestBusy}
            >
              <RefreshCw size={13} className={telegramTestBusy ? 'spin' : ''} />
              Send test
            </button>
          ) : null
      }
    ]
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="External dependencies"
          title="Integrations"
          detail="Live service state for the systems TSAGE currently uses."
          action={
            <button
              className="icon-button"
              onClick={() => void loadHealth()}
              disabled={healthBusy}
              title="Refresh integrations"
              aria-label="Refresh integrations"
            >
              <RefreshCw size={17} className={healthBusy ? 'spin' : ''} />
            </button>
          }
        />
        <div className="integration-grid">
          {integrations.map((integration) => (
            <article className="soc-panel" key={integration.name}>
              <header>
                {integration.icon}
                <Status value={integration.status} />
              </header>
              <strong>{integration.name}</strong>
              <p>{integration.detail}</p>
              {integration.action}
            </article>
          ))}
        </div>
      </div>
    )
  }

  if (view === 'ai-models') {
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="Inference routing"
          title="AI Models"
          detail="Fixed provider assignments for the SOC orchestrator and analyst tiers."
        />
        <Panel title="Role assignments" icon={<Bot size={17} />}>
          <div className="model-grid">
            {platform?.model_assignments.map((assignment) => (
              <article key={assignment.role}>
                <span>{titleCase(assignment.role)}</span>
                <strong>{titleCase(assignment.provider)}</strong>
                <code>{assignment.model || 'Provider default model'}</code>
              </article>
            ))}
            {!platformBusy && !platform?.model_assignments.length && (
              <EmptyState
                icon={<Bot size={24} />}
                title="Model assignments unavailable"
                detail="Refresh the platform metadata."
              />
            )}
          </div>
        </Panel>
        <Panel title="Execution limits" icon={<Gauge size={17} />}>
          <div className="settings-list">
            <div>
              <span>Tool calls per MAPE-K stage</span>
              <strong>
                {String(
                  platform?.response_policy.max_tool_calls_per_stage ?? '-'
                )}
              </strong>
            </div>
            <div>
              <span>Provider routing</span>
              <strong>Fixed by SOC role</strong>
            </div>
            <div>
              <span>Structured output</span>
              <Status value="active" />
            </div>
          </div>
        </Panel>
      </div>
    )
  }

  if (view === 'audit-log') {
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="Immutable activity"
          title="Audit Log"
          detail="Persisted investigation transitions and security decisions."
          action={
            <button
              className="icon-button"
              onClick={() => void onRefreshPlatform()}
              disabled={platformBusy}
              title="Refresh audit log"
              aria-label="Refresh audit log"
            >
              <RefreshCw size={17} className={platformBusy ? 'spin' : ''} />
            </button>
          }
        />
        <Panel title="Recent events" icon={<History size={17} />}>
          <div className="audit-table">
            {platform?.audit_events.map((event, index) => (
              <div
                key={`${event.investigation_id}-${event.timestamp}-${event.event}-${index}`}
              >
                <span className="audit-marker" />
                <div>
                  <strong>{titleCase(event.event)}</strong>
                  <span>
                    {event.investigation_id} · {titleCase(event.stage)}
                  </span>
                </div>
                <time>{new Date(event.timestamp).toLocaleString()}</time>
              </div>
            ))}
            {!platformBusy && !platform?.audit_events.length && (
              <EmptyState
                icon={<History size={24} />}
                title="No audit events"
                detail="Investigation transitions will be recorded here."
              />
            )}
          </div>
        </Panel>
      </div>
    )
  }

  if (view === 'settings') {
    return (
      <div className="platform-workspace">
        <WorkspaceHeader
          eyebrow="Runtime policy"
          title="Settings"
          detail="Effective safety and retention settings exposed by FastAPI."
        />
        <div className="platform-columns">
          <Panel title="Response safety" icon={<Shield size={17} />}>
            <div className="settings-list">
              {Object.entries(platform?.response_policy || {}).map(
                ([key, value]) => (
                  <div key={key}>
                    <span>{titleCase(key)}</span>
                    {typeof value === 'boolean' ? (
                      <Status value={value ? 'active' : 'disabled'} />
                    ) : (
                      <strong>{String(value)}</strong>
                    )}
                  </div>
                )
              )}
            </div>
          </Panel>
          <Panel title="Retention" icon={<FileClock size={17} />}>
            <div className="settings-list">
              {Object.entries(platform?.retention || {}).map(([key, value]) => (
                <div key={key}>
                  <span>{titleCase(key)}</span>
                  <strong>
                    {typeof value === 'number' ? `${value} days` : value}
                  </strong>
                </div>
              ))}
            </div>
          </Panel>
        </div>
        <div className="platform-note">
          <Settings2 size={18} />
          <span>
            These values are server controlled. Secrets, credentials, and
            environment variables are never returned to the browser.
          </span>
        </div>
      </div>
    )
  }

  return (
    <div className="platform-workspace">
      <EmptyState
        icon={<Box size={24} />}
        title="Workspace unavailable"
        detail="Select another SOC workspace."
      />
    </div>
  )
}
