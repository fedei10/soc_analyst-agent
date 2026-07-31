"""Strict checkpoint serializer allowlist for MAPE-K state types."""

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from app.mape_k.schemas import (
    ActionType,
    AdvisoryPlan,
    ApprovalDecision,
    ApprovalRequestRecord,
    ApprovalSubmission,
    AuthenticationEvidenceSummary,
    Diagnosis,
    DiagnosisVerdict,
    EvidenceCollectionResult,
    EvidenceCollectionStatus,
    EvidenceReference,
    ExecutionAuthorization,
    ExecutionResult,
    IncidentWorkflowState,
    PolicyDecision,
    RemediationAction,
    RemediationPlan,
    RollbackResult,
    SSHDetectionPolicy,
    TrustedApprovalSubmission,
    VerificationOutcome,
    VerificationResult,
    WorkflowError,
    WorkflowStage,
    WorkflowStatus,
)
from app.services.wazuh.normalization.schemas import NormalizedAlert


CHECKPOINT_TYPES = (
    ActionType,
    AdvisoryPlan,
    ApprovalDecision,
    ApprovalRequestRecord,
    ApprovalSubmission,
    AuthenticationEvidenceSummary,
    Diagnosis,
    DiagnosisVerdict,
    EvidenceCollectionResult,
    EvidenceCollectionStatus,
    EvidenceReference,
    ExecutionAuthorization,
    ExecutionResult,
    IncidentWorkflowState,
    NormalizedAlert,
    PolicyDecision,
    RemediationAction,
    RemediationPlan,
    RollbackResult,
    SSHDetectionPolicy,
    TrustedApprovalSubmission,
    VerificationOutcome,
    VerificationResult,
    WorkflowError,
    WorkflowStage,
    WorkflowStatus,
)


def create_checkpoint_serializer() -> JsonPlusSerializer:
    return JsonPlusSerializer(allowed_msgpack_modules=CHECKPOINT_TYPES)
