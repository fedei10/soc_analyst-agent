export type WorkspaceView =
  | 'overview'
  | 'chat'
  | 'alerts'
  | 'alert-triage'
  | 'investigations'
  | 'threat-hunting'
  | 'assets'
  | 'playbooks'
  | 'approvals'
  | 'executions'
  | 'integrations'
  | 'ai-models'
  | 'audit-log'
  | 'settings'
export type ApprovalDecision = 'approve' | 'reject'

export interface ChatActivity {
  id?: string | null
  tool: string | null
  label: string
  status: 'running' | 'completed' | 'failed'
}

export interface AssistantCommand {
  name: string
  slash: string
  aliases: string[]
  title: string
  description: string
  usage: string
  category: string
  examples: string[]
}

export interface AssistantCommandCatalog {
  items: AssistantCommand[]
  count: number
}

export interface AgentChatResponse {
  conversation_id: string
  assistant_message: string
  response: Record<string, unknown>
  tools_used: string[]
  activities: ChatActivity[]
  active_investigation_id?: string | null
  active_alert_id?: string | null
  active_agent_id?: string | null
  investigation?: Investigation | null
  investigation_progress?: InvestigationProgress | null
  missing_evidence?: string[]
  tool_errors?: Array<Record<string, unknown>>
}

export interface InvestigationProgress {
  known_facts: string[]
  missing_evidence: string[]
  next_tool?: string | null
  reason: string
  complete: boolean
  steps_completed: number
  max_steps: number
  attribution_status: string
  evidence_checked: Array<Record<string, unknown>>
  tool_errors: Array<Record<string, unknown>>
}

export interface ChatMessage {
  id: string
  role: 'user' | 'agent' | 'error'
  content: string
  response?: Record<string, unknown>
  tools?: string[]
  activities?: ChatActivity[]
  createdAt: number
}

export interface WazuhCheck {
  status: string
  error_code?: string
  meaning?: string
  fix?: string
}

export interface WazuhHealth {
  service: string
  status: 'healthy' | 'unhealthy'
  checks: Record<string, WazuhCheck>
}

export interface AlertSummary {
  total_alerts?: number
  by_level?: Record<string, number>
  by_agent?: Record<string, number>
  by_rule_group?: Record<string, number>
}

export interface OverviewMetric {
  value: number | null
  trend?: string | null
}

export interface OverviewPipelineStage {
  stage:
    | 'monitor'
    | 'analyze'
    | 'plan'
    | 'approval'
    | 'execute'
    | 'verify'
    | 'complete'
    | 'failed'
  count: number
}

export interface SOCOverview {
  generated_at: string
  window_hours: number
  wazuh_status: 'available' | 'unavailable'
  metrics: Record<string, OverviewMetric>
  pipeline: OverviewPipelineStage[]
  severity_distribution: Record<string, number>
  alert_reduction: {
    raw_alerts: number | null
    represented_alerts: number
    findings: number
    reduction_percent: number | null
  }
  recent_investigations: Array<{
    investigation_id: string
    alert_id: string
    status: string
    current_stage: string
    severity?: string | null
    confidence?: number | null
    updated_at?: string | null
  }>
  recent_findings: Array<{
    finding_id: string
    title?: string | null
    severity: string
    verdict?: string | null
    confidence?: number | null
    alert_count: number
    last_seen?: string | null
  }>
}

export interface WazuhAlert {
  alert_id: string
  timestamp: string
  agent_id?: string | null
  agent_name?: string | null
  rule_id: string
  rule_level: number
  description: string
  source_ip?: string | null
  target_user?: string | null
  mitre_ids: string[]
  event_outcome?: string | null
}

export interface WazuhAgent {
  id: string
  name?: string | null
  ip?: string | null
  status?: string | null
  version?: string | null
  lastKeepAlive?: string | null
  os?: {
    name?: string | null
    platform?: string | null
    version?: string | null
  }
}

export interface WazuhCollection<T> {
  affected_items: T[]
  total_affected_items: number
}

export interface ServiceHealth {
  status: string
  error_code?: string | number
  detail?: string
  meaning?: string
  fix?: string
}

export interface ServicesHealth {
  status: 'healthy' | 'unhealthy'
  services: Record<string, ServiceHealth>
}

export interface StorageHealth {
  service: 'storage'
  status: 'healthy' | 'degraded' | 'unhealthy'
  postgresql: string
  redis: string
  durable_memory: boolean
  detail?: string | null
}

export interface SOCPlatform {
  generated_at: string
  pending_approvals: Array<{
    investigation_id: string
    approval_id: string
    incident_id: string
    expires_at: string
    required_role?: string | null
    status: string
    proposed_actions: ProposedAction[]
  }>
  response_actions: Array<{
    investigation_id: string
    action_id?: string | null
    action_type?: string | null
    target?: string | null
    risk_level?: number | null
    status: string
    evidence_refs: string[]
  }>
  audit_events: Array<AuditEvent>
  model_assignments: Array<{
    role: string
    provider: string
    model?: string | null
  }>
  response_policy: Record<string, boolean | number | string>
  retention: Record<string, number | string>
}

export interface ProposedAction {
  action_id: string
  action_type: string
  target: string
  parameters?: Record<string, unknown>
  timeout_seconds: number
  ttl_seconds?: number | null
  risk_level: number
  evidence_refs: string[]
}

export interface ApprovalRequest {
  investigation_id: string
  incident_id: string
  approval_id: string
  expires_at: string
  required_role?: 'soc_l2' | 'soc_l3' | 'security_admin' | null
  proposed_actions: ProposedAction[]
}

export interface AuditEvent {
  investigation_id: string
  stage: string
  event: string
  timestamp: string
}

export interface TierReport {
  report_id: string
  investigation_id: string
  tier: 'l1' | 'l2' | 'l3'
  status: 'completed'
  summary: string
  generated_at: string
  alert_context: Record<string, unknown>
  triage: Record<string, unknown>
  initial_investigation: Record<string, unknown>
  advanced_analysis: Record<string, unknown>
  containment: Record<string, unknown>
  detection_engineering: Record<string, unknown>
  post_incident_review: Record<string, unknown>
  escalation: Record<string, unknown>
  analyst_activity: Array<Record<string, unknown>>
  evidence_refs: string[]
  result: Record<string, unknown>
}

export interface Investigation {
  incident_id: string
  investigation_id: string
  alert_id?: string
  agent_id?: string | null
  status: string
  stage?: string
  current_stage: string
  severity?: string | null
  confidence?: number | null
  diagnosis?: Record<string, unknown> | null
  remediation_plan?: Record<string, unknown> | null
  policy_decision?: Record<string, unknown> | null
  proposed_actions: ProposedAction[]
  approval_request?: ApprovalRequest | null
  approval_decision?: Record<string, unknown> | null
  executed_actions: Record<string, unknown>[]
  execution_results?: Record<string, unknown>[]
  verification?: Record<string, unknown> | null
  rollback?: Record<string, unknown> | null
  final_report?: Record<string, unknown> | null
  tier_reports?: TierReport[]
  errors: Array<Record<string, unknown>>
  audit_events: AuditEvent[]
  pending_nodes: string[]
}

export interface InvestigationHistoryItem {
  investigation_id: string
  alert_id: string
  agent_id?: string | null
  status: string
  current_stage: string
  severity?: string | null
  confidence?: number | null
  initiated_by?: string | null
  initiation_reason?: string | null
  completed_tiers: Array<'l1' | 'l2' | 'l3'>
  created_at?: string | null
  updated_at?: string | null
}

export interface InvestigationHistory {
  items: InvestigationHistoryItem[]
  count: number
  total: number
  limit: number
  offset: number
}

export interface ApprovalInput {
  decision: ApprovalDecision
  approval_id: string
  modified_actions?: Record<string, unknown>[]
}

export type VerdictLabel =
  | 'benign'
  | 'suspicious'
  | 'malicious'
  | 'inconclusive'

export interface TriageVerdict {
  verdict: VerdictLabel
  confidence: number
  severity: string
  summary: string
  evidence_refs: string[]
  false_positive_indicators: string[]
  escalation_recommended: boolean
  missing_evidence: string[]
  deterministic: boolean
  reason_code?: string | null
}

export interface EnrichmentResult {
  indicator: string
  indicator_type: 'ip' | 'domain' | 'hash'
  is_internal: boolean
  reputation: 'unknown' | 'malicious' | 'suspicious' | 'clean'
  known_asset: boolean
  asset_owner?: string | null
  allowlisted: boolean
  previous_incidents: number
  source: string
}

export interface SecurityFindingSummary {
  finding_id: string
  title: string
  summary: string
  severity: string
  confidence: number
  first_seen: string
  last_seen: string
  affected_assets: string[]
  source_ips: string[]
  target_users: string[]
  mitre_techniques: string[]
  alert_count: number
  representative_alert_id: string
  evidence_refs: string[]
  investigation_recommended: boolean
}

export type FeedbackDisposition =
  | 'confirmed_malicious'
  | 'confirmed_benign'
  | 'expected_admin_activity'
  | 'wrong_asset_context'
  | 'wrong_severity'
  | 'duplicate_incident'
  | 'insufficient_evidence'

export interface FindingFeedback {
  feedback_id: string
  finding_id: string
  reviewer_user_id: string
  disposition: FeedbackDisposition
  notes?: string | null
  created_at: string
}

export interface Finding {
  finding_id: string
  category: string
  attack_family: string
  event_type: string
  severity: string
  severity_score: number
  first_seen: string
  last_seen: string
  alert_count: number
  representative_alert_id: string
  evidence_refs: string[]
  finding: SecurityFindingSummary
  verdict: TriageVerdict
  enrichment: EnrichmentResult[]
  created_at: string
  updated_at: string
  feedback: FindingFeedback[]
}

export interface FindingList {
  items: Finding[]
  count: number
}
