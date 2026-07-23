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


class ApprovalDecisionInput(APIModel):
    decision: ApprovalChoice
    approved_by: str = Field(min_length=1, max_length=100)
    approval_id: str = Field(min_length=1, max_length=100)
    modified_actions: list[dict[str, Any]] | None = Field(
        default=None,
        max_length=10,
    )


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
    "ChatHistoryMessage",
    "Classification",
    "InvestigationStage",
    "InvestigationState",
    "InvestigationStatus",
    "InvestigationCreate",
    "L1Result",
    "L2Result",
    "L3Result",
    "OrchestratorChatRequest",
    "ProposedAction",
    "Severity",
    "StrictModel",
    "WRITE_ACTIONS",
]
