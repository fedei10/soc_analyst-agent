"""Validated structured outputs for SOC analysis agents."""

from enum import Enum
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


WRITE_ACTIONS = {
    "block_ip",
    "isolate_agent",
    "kill_process",
    "delete_file",
    "disable_user",
    "restart_service",
    "modify_rule",
}

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
    action_type: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1)
    risk_level: ActionRisk
    operational_impact: str = Field(min_length=1)

    @computed_field
    @property
    def requires_approval(self) -> bool:
        return self.action_type in WRITE_ACTIONS


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
