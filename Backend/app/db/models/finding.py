"""Durable, organization-scoped triage findings and analyst feedback."""

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.investigation import JSON_VALUE, utc_now


class FindingRecord(Base):
    __tablename__ = "soc_findings"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    correlation_key: Mapped[str] = mapped_column(String(256), index=True)
    status: Mapped[str] = mapped_column(
        String(32),
        default="open",
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
    category: Mapped[str] = mapped_column(String(64), index=True)
    attack_family: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    severity_score: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    alert_count: Mapped[int] = mapped_column(Integer)
    representative_alert_id: Mapped[str] = mapped_column(String(256))
    evidence_refs: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    finding: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)
    verdict: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)
    verdict_label: Mapped[str] = mapped_column(String(32), index=True)
    verdict_confidence: Mapped[float] = mapped_column(Float)
    enrichment: Mapped[list[dict[str, Any]]] = mapped_column(JSON_VALUE, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )

    __table_args__ = (
        Index(
            "ix_soc_findings_org_severity_updated",
            "organization_id",
            "severity",
            "updated_at",
        ),
        Index(
            "ix_soc_findings_org_status_updated",
            "organization_id",
            "status",
            "updated_at",
        ),
    )


class FindingFeedbackRecord(Base):
    __tablename__ = "soc_finding_feedback"

    feedback_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("soc_findings.finding_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    reviewer_user_id: Mapped[str] = mapped_column(String(128), index=True)
    disposition: Mapped[str] = mapped_column(String(64), index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
    )
