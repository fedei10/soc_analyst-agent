"""Persistence boundary for chat-generated analyst reports."""

from __future__ import annotations

import hashlib
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from functools import lru_cache
from threading import RLock
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.db.models.report import AnalystReportRecord
from app.db.session import (
    DatabaseNotConfiguredError,
    database_url,
    get_session_factory,
    init_database,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _report_id(idempotency_key: str | None = None) -> str:
    if idempotency_key:
        digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        return f"RPT-{digest[:40].upper()}"
    return f"RPT-{uuid.uuid4().hex[:12].upper()}"


class ReportRepository(Protocol):
    def create(
        self,
        *,
        organization_id: str,
        title: str,
        summary: str,
        body_markdown: str,
        created_by: str,
        conversation_id: str | None = None,
        severity: str | None = None,
        related_alert_ids: list[str] | None = None,
        related_finding_ids: list[str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]: ...

    def get(
        self,
        report_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None: ...

    def list(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...


class InMemoryReportRepository:
    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    def create(
        self,
        *,
        organization_id: str,
        title: str,
        summary: str,
        body_markdown: str,
        created_by: str,
        conversation_id: str | None = None,
        severity: str | None = None,
        related_alert_ids: list[str] | None = None,
        related_finding_ids: list[str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            report_id = _report_id(idempotency_key)
            existing = self._records.get(report_id)
            if existing is not None:
                return deepcopy(existing)
            record = {
                "report_id": report_id,
                "organization_id": organization_id,
                "title": title,
                "summary": summary,
                "body_markdown": body_markdown,
                "severity": severity,
                "source": "chat",
                "created_by": created_by,
                "conversation_id": conversation_id,
                "related_alert_ids": list(related_alert_ids or []),
                "related_finding_ids": list(related_finding_ids or []),
                "created_at": _utc_now(),
            }
            self._records[record["report_id"]] = record
            return deepcopy(record)

    def get(
        self,
        report_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get(report_id)
            if record is None or record["organization_id"] != organization_id:
                return None
            return deepcopy(record)

    def list(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._lock:
            items = [
                record
                for record in self._records.values()
                if record["organization_id"] == organization_id
            ]
            items.sort(key=lambda item: item["created_at"], reverse=True)
            return deepcopy(items[offset : offset + limit])


def _report_record_dict(record: AnalystReportRecord) -> dict[str, Any]:
    return {
        "report_id": record.report_id,
        "organization_id": record.organization_id,
        "title": record.title,
        "summary": record.summary,
        "body_markdown": record.body_markdown,
        "severity": record.severity,
        "source": record.source,
        "created_by": record.created_by,
        "conversation_id": record.conversation_id,
        "related_alert_ids": list(record.related_alert_ids or []),
        "related_finding_ids": list(record.related_finding_ids or []),
        "created_at": record.created_at,
    }


class SQLAlchemyReportRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create(
        self,
        *,
        organization_id: str,
        title: str,
        summary: str,
        body_markdown: str,
        created_by: str,
        conversation_id: str | None = None,
        severity: str | None = None,
        related_alert_ids: list[str] | None = None,
        related_finding_ids: list[str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        with self._session_factory.begin() as session:
            report_id = _report_id(idempotency_key)
            existing = session.get(AnalystReportRecord, report_id)
            if existing is not None:
                return _report_record_dict(existing)
            record = AnalystReportRecord(
                report_id=report_id,
                organization_id=organization_id,
                title=title,
                summary=summary,
                body_markdown=body_markdown,
                severity=severity,
                source="chat",
                created_by=created_by,
                conversation_id=conversation_id,
                related_alert_ids=list(related_alert_ids or []),
                related_finding_ids=list(related_finding_ids or []),
                created_at=_utc_now(),
            )
            session.add(record)
            session.flush()
            data = _report_record_dict(record)
        return data

    def get(
        self,
        report_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.get(AnalystReportRecord, report_id)
            if record is None or record.organization_id != organization_id:
                return None
            return _report_record_dict(record)

    def list(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        statement = (
            select(AnalystReportRecord)
            .where(AnalystReportRecord.organization_id == organization_id)
            .order_by(AnalystReportRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        with self._session_factory() as session:
            return [
                _report_record_dict(record)
                for record in session.scalars(statement).all()
            ]


@lru_cache(maxsize=1)
def get_report_repository() -> ReportRepository:
    if not database_url():
        if settings.DATABASE_REQUIRED:
            raise DatabaseNotConfiguredError(
                "DATABASE_REQUIRED is true but DATABASE_URL is empty."
            )
        return InMemoryReportRepository()
    if settings.DATABASE_AUTO_CREATE:
        init_database()
    return SQLAlchemyReportRepository(get_session_factory())


def close_report_repository() -> None:
    get_report_repository.cache_clear()
