"""Validated structured outputs for SOC analysis agents."""

from enum import Enum
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


WRITE_ACTIONS = {
    "block_ip",
    "restart_agent",
    "restart_service",
}
READ_ACTIONS = {"collect_more_evidence", "monitor", "no_action"}
ActionType = Literal[
    "block_ip",
    "restart_agent",
    "restart_service",
    "collect_more_evidence",
    "monitor",
    "no_action",
]

Classification = Literal[
    "benign",
    "false_positive",
    "suspicious",
    "malicious",
    "unknown",
]
ActionRisk = Literal["low", "medium", "high", "critical"]
ApprovalChoice = Literal["approve", "reject", "modify"]
AgentTier = Literal["l1", "l2", "l3"]
SpecialistStatus = Literal["completed", "failed"]
AttributionStatus = Literal[
    "identified",
    "partially_identified",
    "not_identified",
    "insufficient_telemetry",
]


class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SpecialistToolActivity(StrictModel):
    """Sanitized tool activity suitable for durable audit storage."""

    name: str = Field(min_length=1, max_length=100)
    arguments_hash: str = Field(min_length=16, max_length=64)
    status: Literal[
        "requested",
        "completed",
        "failed",
        "duplicate_rejected",
        "limit_rejected",
    ]


class SpecialistRunRecord(StrictModel):
    """Bounded metadata for a specialist or supervisor execution."""

    run_id: str = Field(min_length=1, max_length=100)
    parent_run_id: str | None = Field(default=None, max_length=100)
    tier: AgentTier
    role: str = Field(min_length=1, max_length=100)
    attempt: int = Field(default=1, ge=1)
    status: SpecialistStatus
    started_at: datetime
    completed_at: datetime
    duration_ms: int = Field(ge=0)
    provider: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=200)
    tool_activity: list[SpecialistToolActivity] = Field(default_factory=list)
    error_code: str | None = Field(default=None, max_length=100)
    error_summary: str | None = Field(default=None, max_length=500)
    input_summary: dict[str, Any] = Field(default_factory=dict)
    result_summary: dict[str, Any] = Field(default_factory=dict)


class L1AlertContextFindings(StrictModel):
    summary: str = Field(min_length=1)
    verified_alert: dict[str, Any] = Field(default_factory=dict)
    affected_entities: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class L1RiskClassificationFindings(StrictModel):
    summary: str = Field(min_length=1)
    classification: Classification
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    false_positive_indicators: list[str] = Field(default_factory=list)
    escalation_indicators: list[str] = Field(default_factory=list)


class L2CorrelationFindings(StrictModel):
    summary: str = Field(min_length=1)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    attack_chain: list[str] = Field(default_factory=list)
    supporting_evidence: list[dict[str, Any]] = Field(default_factory=list)
    contradictory_evidence: list[dict[str, Any]] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class L2AssetInvestigationFindings(StrictModel):
    summary: str = Field(min_length=1)
    affected_assets: list[str] = Field(default_factory=list)
    compromise_indicators: list[str] = Field(default_factory=list)
    benign_indicators: list[str] = Field(default_factory=list)
    detection_gap: bool = False
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class L3DetectionEngineeringFindings(StrictModel):
    summary: str = Field(min_length=1)
    root_cause: str | None = None
    detection_gaps: list[str] = Field(default_factory=list)
    rule_recommendations: list[dict[str, Any]] = Field(default_factory=list)
    supporting_evidence: list[dict[str, Any]] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class L3ResponsePlanningFindings(StrictModel):
    summary: str = Field(min_length=1)
    remediation_steps: list[str] = Field(default_factory=list)
    proposed_actions: list["ProposedAction"] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    rollback_considerations: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class InvestigationProgress(StrictModel):
    known_facts: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    next_tool: str | None = None
    reason: str = Field(min_length=1)
    complete: bool = False
    steps_completed: int = Field(default=0, ge=0, le=8)
    max_steps: int = Field(default=8, ge=8, le=8)
    attribution_status: AttributionStatus = "not_identified"
    evidence_checked: list[dict[str, Any]] = Field(default_factory=list)
    tool_errors: list[dict[str, Any]] = Field(default_factory=list)


class L1Result(StrictModel):
    summary: str = Field(min_length=1)
    classification: Classification
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_user: str | None = None
    affected_host: str | None = None
    source_ip: str | None = None
    false_positive: bool = False
    escalate: bool = False
    escalation_reason: str | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class L2Result(StrictModel):
    summary: str = Field(min_length=1)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    attack_chain: list[str] = Field(default_factory=list)
    false_positive_confirmed: bool = False
    detection_gap: bool = False
    requires_l3: bool = False
    escalation_reason: str | None = None
    recommended_next_steps: list[str] = Field(default_factory=list)


class ProposedAction(StrictModel):
    action_type: ActionType
    target: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1)
    risk_level: ActionRisk
    operational_impact: str = Field(min_length=1)

    @computed_field
    @property
    def requires_approval(self) -> bool:
        return self.action_type in WRITE_ACTIONS

    @computed_field
    @property
    def execution_preview(self) -> str:
        previews = {
            "block_ip": (
                f"Wazuh active response: firewall-drop target={self.target}"
            ),
            "restart_agent": (
                f"Wazuh manager API: restart agent {self.target}"
            ),
            "restart_service": f"systemctl restart {self.target}",
            "collect_more_evidence": (
                f"Read-only evidence collection: {self.target}"
            ),
            "monitor": f"Monitor without changes: {self.target}",
            "no_action": f"No execution: {self.target}",
        }
        return previews[self.action_type]


class L3Result(StrictModel):
    summary: str = Field(min_length=1)
    root_cause: str | None = None
    detection_gaps: list[str] = Field(default_factory=list)
    rule_recommendations: list[dict[str, Any]] = Field(default_factory=list)
    remediation_steps: list[str] = Field(default_factory=list)
    proposed_actions: list[ProposedAction] = Field(default_factory=list)


class OrchestratorDecision(StrictModel):
    selected_agent: AgentTier
    reason: str = Field(min_length=1, max_length=500)


class ApprovalDecision(StrictModel):
    decision: ApprovalChoice
    approved_by: str = Field(min_length=1, max_length=100)
    approval_id: str = Field(min_length=1, max_length=100)
    modified_actions: list[dict[str, Any]] | None = None

    @model_validator(mode="after")
    def validate_modified_actions(self):
        if self.decision == "modify" and not self.modified_actions:
            raise ValueError(
                "modified_actions is required when decision is modify."
            )
        if self.decision != "modify" and self.modified_actions is not None:
            raise ValueError(
                "modified_actions is only allowed when decision is modify."
            )
        return self


class ApprovalRequest(StrictModel):
    investigation_id: str = Field(min_length=1)
    approval_id: str = Field(min_length=1, max_length=100)
    expires_at: datetime
    status: Literal["awaiting_approval"] = "awaiting_approval"
    proposed_actions: list[ProposedAction] = Field(min_length=1)
    allowed_decisions: list[ApprovalChoice] = Field(
        default_factory=lambda: ["approve", "reject", "modify"]
    )


class StartInvestigationInput(StrictModel):
    alert_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[\w.-]+$",
        description="Exact Wazuh alert document ID observed in tool evidence.",
    )
    reason: str = Field(
        min_length=5,
        max_length=500,
        description="Evidence-based reason for starting the formal workflow.",
    )


class InvestigationStatusInput(StrictModel):
    investigation_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^INV-[A-Z0-9-]+$",
    )


class OpenInvestigationsInput(StrictModel):
    limit: int = Field(default=10, ge=1, le=50)


class RuntimeStartInvestigationInput(StartInvestigationInput):
    model_config = ConfigDict(extra="ignore")


class RuntimeInvestigationStatusInput(InvestigationStatusInput):
    model_config = ConfigDict(extra="ignore")
