"""Apply bounded SOC retention without deleting durable decisions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, inspect, select, text

from app.config import settings
from app.db.models.investigation import (
    AgentRunRecord,
    AuditEventRecord,
    ConversationMessageRecord,
    ConversationSummaryRecord,
    EvidenceRecord,
    InvestigationRecord,
    ToolExecutionRecord,
)
from app.db.session import get_session_factory


CHECKPOINT_TABLES = (
    "checkpoint_writes",
    "checkpoints",
    "checkpoint_blobs",
)


def apply_retention(*, now: datetime | None = None) -> dict[str, int]:
    current = now or datetime.now(UTC)
    message_cutoff = current - timedelta(
        days=settings.RETENTION_MESSAGES_DAYS
    )
    tool_cutoff = current - timedelta(
        days=settings.RETENTION_TOOL_PAYLOAD_DAYS
    )
    checkpoint_cutoff = current - timedelta(
        days=settings.RETENTION_CHECKPOINT_DAYS
    )
    investigation_cutoff = current - timedelta(
        days=settings.RETENTION_INVESTIGATION_DAYS
    )
    counts: dict[str, int] = {}

    with get_session_factory().begin() as session:
        counts["messages"] = int(session.execute(
            delete(ConversationMessageRecord).where(
                ConversationMessageRecord.retention_until.is_not(None),
                ConversationMessageRecord.retention_until <= current,
            )
        ).rowcount or 0)
        counts["summaries"] = int(session.execute(
            delete(ConversationSummaryRecord).where(
                ConversationSummaryRecord.created_at <= message_cutoff,
            )
        ).rowcount or 0)
        counts["tool_executions"] = int(session.execute(
            delete(ToolExecutionRecord).where(
                ToolExecutionRecord.completed_at.is_not(None),
                ToolExecutionRecord.completed_at <= tool_cutoff,
            )
        ).rowcount or 0)
        counts["audit_events"] = int(session.execute(
            delete(AuditEventRecord).where(
                AuditEventRecord.occurred_at <= investigation_cutoff,
            )
        ).rowcount or 0)
        counts["evidence"] = int(session.execute(
            delete(EvidenceRecord).where(
                EvidenceRecord.created_at <= investigation_cutoff,
            )
        ).rowcount or 0)
        counts["agent_runs"] = int(session.execute(
            delete(AgentRunRecord).where(
                AgentRunRecord.completed_at.is_not(None),
                AgentRunRecord.completed_at <= investigation_cutoff,
            )
        ).rowcount or 0)

        terminal_ids = list(session.scalars(
            select(InvestigationRecord.investigation_id).where(
                InvestigationRecord.completed_at.is_not(None),
                InvestigationRecord.completed_at <= checkpoint_cutoff,
            )
        ))
        connection = session.connection()
        available_tables = {
            table
            for table in CHECKPOINT_TABLES
            if inspect(connection).has_table(table)
        }
        checkpoint_rows = 0
        for investigation_id in terminal_ids:
            for table in CHECKPOINT_TABLES:
                if table not in available_tables:
                    continue
                checkpoint_rows += int(connection.execute(
                    text(
                        f"DELETE FROM {table} WHERE thread_id = :thread_id"
                    ),
                    {"thread_id": investigation_id},
                ).rowcount or 0)
        counts["checkpoint_rows"] = checkpoint_rows

        old_records = session.scalars(
            select(InvestigationRecord).where(
                InvestigationRecord.completed_at.is_not(None),
                InvestigationRecord.completed_at <= investigation_cutoff,
            )
        ).all()
        for record in old_records:
            record.snapshot = {
                "investigation_id": record.investigation_id,
                "organization_id": record.organization_id,
                "owner_user_id": record.owner_user_id,
                "alert_id": record.alert_id,
                "agent_id": record.agent_id,
                "status": record.status,
                "current_stage": record.current_stage,
                "severity": record.severity,
                "confidence": record.confidence,
                "retained_record": True,
            }
        counts["investigations_archived"] = len(old_records)

    return counts


def main() -> None:
    counts = apply_retention()
    print(
        "Retention complete: "
        + ", ".join(f"{name}={count}" for name, count in counts.items())
    )


if __name__ == "__main__":
    main()
