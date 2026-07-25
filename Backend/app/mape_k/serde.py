"""Strict checkpoint serializer allowlist for MAPE-K state types."""

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from app.mape_k.schemas import (
    ActionType,
    ApprovalDecision,
    Diagnosis,
    EvidenceReference,
    ExecutionResult,
    IncidentWorkflowState,
    PolicyDecision,
    RemediationAction,
    RemediationPlan,
    RollbackResult,
    VerificationResult,
    WorkflowError,
    WorkflowStage,
    WorkflowStatus,
)
from app.services.wazuh.normalization.schemas import NormalizedAlert


CHECKPOINT_TYPES = (
    ActionType,
    ApprovalDecision,
    Diagnosis,
    EvidenceReference,
    ExecutionResult,
    IncidentWorkflowState,
    NormalizedAlert,
    PolicyDecision,
    RemediationAction,
    RemediationPlan,
    RollbackResult,
    VerificationResult,
    WorkflowError,
    WorkflowStage,
    WorkflowStatus,
)


def create_checkpoint_serializer() -> JsonPlusSerializer:
    return JsonPlusSerializer(allowed_msgpack_modules=CHECKPOINT_TYPES)

