"""Durable, organization-scoped analyst reports saved from the SOC chat."""

from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.investigation import JSON_VALUE, utc_now


class AnalystReportRecord(Base):
    __tablename__ = "soc_reports"

    report_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(256))
    summary: Mapped[str] = mapped_column(Text)
    body_markdown: Mapped[str] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(32), default="chat", index=True)
    created_by: Mapped[str] = mapped_column(String(128), index=True)
    conversation_id: Mapped[str | None] = mapped_column(String(64), index=True)
    related_alert_ids: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    related_finding_ids: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
    )

    __table_args__ = (
        Index(
            "ix_soc_reports_org_created",
            "organization_id",
            "created_at",
        ),
    )
