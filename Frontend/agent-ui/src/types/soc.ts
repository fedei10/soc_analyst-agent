export type WorkspaceView = 'chat' | 'alert-triage' | 'investigations'
export type ApprovalDecision = 'approve' | 'reject' | 'modify'

export interface ChatActivity {
  id?: string | null
  tool: string | null
  label: string
  status: 'running' | 'completed' | 'failed'
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

export interface ProposedAction {
  action_type: string
  target: string
  reason: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  operational_impact: string
  requires_approval: boolean
  execution_preview: string
}

export interface ApprovalRequest {
  investigation_id: string
  approval_id: string
  expires_at: string
  status: 'awaiting_approval'
  proposed_actions: ProposedAction[]
  allowed_decisions: ApprovalDecision[]
}

export interface AuditEvent {
  investigation_id: string
  stage: string
  event: string
  timestamp: string
}

export interface Investigation {
  investigation_id: string
  alert_id?: string
  agent_id?: string | null
  status: string
  current_stage: string
  severity?: string | null
  confidence?: number | null
  l1_result?: Record<string, unknown> | null
  l2_result?: Record<string, unknown> | null
  l3_result?: Record<string, unknown> | null
  proposed_actions: ProposedAction[]
  approval_request?: ApprovalRequest | null
  approval_decision?: Record<string, unknown> | null
  executed_actions: Record<string, unknown>[]
  final_report?: Record<string, unknown> | null
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
