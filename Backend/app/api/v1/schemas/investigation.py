"""HTTP contracts and compatibility exports for investigation workflows.

HTTP-only investigation request and response models can remain in this module
when the investigation API is added. Internal graph models live under
app.coreAgents.orchestration.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.coreAgents.orchestration.schemas import (
    ActionRisk,
    ApprovalChoice,
    ApprovalDecision,
    ApprovalRequest,
    Classification,
    L1Result,
    L2Result,
    L3Result,
    ProposedAction,
    Severity,
    StrictModel,
    TierReport,
    WRITE_ACTIONS,
)
from app.coreAgents.orchestration.state import (
    InvestigationStage,
    InvestigationState,
    InvestigationStatus,
)


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InvestigationCreate(APIModel):
    alert_id: str = Field(min_length=1, max_length=256)
    agent_id: str | None = Field(
        default=None,
        pattern=r"^\d+$",
        max_length=32,
    )


class InvestigationHistoryItem(APIModel):
    investigation_id: str
    alert_id: str
    agent_id: str | None = None
    status: InvestigationStatus
    current_stage: str
    severity: str | None = None
    confidence: float | None = None
    initiated_by: str | None = None
    initiation_reason: str | None = None
    completed_tiers: list[Literal["l1", "l2", "l3"]] = Field(
        default_factory=list
    )
    created_at: str | None = None
    updated_at: str | None = None


class AgentRunHistoryItem(APIModel):
    run_id: str
    parent_run_id: str | None = None
    investigation_id: str
    tier: Literal["l1", "l2", "l3"]
    role: str
    attempt: int = Field(ge=1)
    status: str
    provider: str | None = None
    model_name: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    tool_activity: list[dict[str, Any]] = Field(default_factory=list)
    error_code: str | None = None
    error_summary: str | None = None
    result: dict[str, Any]
    started_at: str | None = None
    completed_at: str | None = None


class AuditHistoryItem(APIModel):
    event_id: str | None = None
    investigation_id: str
    stage: str
    event: str
    timestamp: str


class ResponseActionHistoryItem(APIModel):
    action_id: str | None = None
    investigation_id: str | None = None
    action_type: str
    target: str
    status: str | None = None
    approval_id: str | None = None
    approved_by: str | None = None
    details: dict[str, Any] | None = None


class ApprovalDecisionInput(APIModel):
    decision: ApprovalChoice
    approval_id: str = Field(min_length=1, max_length=100)
    modified_actions: list[dict[str, Any]] | None = Field(
        default=None,
        max_length=10,
    )


class ResponseExecutionInput(APIModel):
    approval_id: str = Field(min_length=1, max_length=100)


class ChatHistoryMessage(APIModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=8000)


class AgentChatRequest(APIModel):
    tier: Literal["l1", "l2", "l3"]
    message: str = Field(min_length=1, max_length=8000)
    history: list[ChatHistoryMessage] = Field(
        default_factory=list,
        max_length=20,
    )


class OrchestratorChatRequest(APIModel):
    message: str = Field(min_length=1, max_length=8000)
    conversation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
    history: list[ChatHistoryMessage] = Field(
        default_factory=list,
        max_length=20,
    )


__all__ = [
    "APIModel",
    "ActionRisk",
    "AgentChatRequest",
    "ApprovalChoice",
    "ApprovalDecision",
    "ApprovalDecisionInput",
    "ApprovalRequest",
    "AgentRunHistoryItem",
    "AuditHistoryItem",
    "ChatHistoryMessage",
    "Classification",
    "InvestigationStage",
    "InvestigationState",
    "InvestigationStatus",
    "InvestigationCreate",
    "InvestigationHistoryItem",
    "L1Result",
    "L2Result",
    "L3Result",
    "OrchestratorChatRequest",
    "ProposedAction",
    "ResponseActionHistoryItem",
    "ResponseExecutionInput",
    "Severity",
    "StrictModel",
    "TierReport",
    "WRITE_ACTIONS",
]
