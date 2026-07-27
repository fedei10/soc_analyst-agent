"""Database model registry."""

from app.db.models.alert_memory import (
    ConversationReferenceRecord,
    FindingAlertRecord,
    IngestionCheckpointRecord,
    InvestigationStepRecord,
    NormalizedEventRecord,
    UserAlertCursorRecord,
    WazuhAlertRecord,
)
from app.db.models.finding import FindingFeedbackRecord, FindingRecord
from app.db.models.investigation import (
    AgentRunRecord,
    ApprovalRecord,
    AuditEventRecord,
    ConversationMessageRecord,
    ConversationRecord,
    ConversationSummaryRecord,
    CuratedMemoryRecord,
    EvidenceRecord,
    InvestigationRecord,
    InvestigationResourceLeaseRecord,
    InvestigationReportRecord,
    TierReportRecord,
    ResponseActionRecord,
    ToolExecutionRecord,
    UserRecord,
)
from app.db.models.report import AnalystReportRecord

__all__ = [
    "AnalystReportRecord",
    "AgentRunRecord",
    "ApprovalRecord",
    "AuditEventRecord",
    "ConversationMessageRecord",
    "ConversationReferenceRecord",
    "ConversationRecord",
    "ConversationSummaryRecord",
    "CuratedMemoryRecord",
    "EvidenceRecord",
    "FindingFeedbackRecord",
    "FindingAlertRecord",
    "FindingRecord",
    "InvestigationRecord",
    "InvestigationResourceLeaseRecord",
    "InvestigationStepRecord",
    "InvestigationReportRecord",
    "TierReportRecord",
    "ResponseActionRecord",
    "IngestionCheckpointRecord",
    "NormalizedEventRecord",
    "ToolExecutionRecord",
    "UserRecord",
    "UserAlertCursorRecord",
    "WazuhAlertRecord",
]
