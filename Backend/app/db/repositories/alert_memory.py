"""Persistence for Wazuh ingestion, analyst cursors, and conversation context."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from functools import lru_cache
from threading import RLock
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.db.models.alert_memory import (
    ConversationReferenceRecord,
    FindingAlertRecord,
    IngestionCheckpointRecord,
    NormalizedEventRecord,
    UserAlertCursorRecord,
    WazuhAlertRecord,
)
from app.db.models.finding import FindingRecord
from app.db.sanitization import bounded_excerpt, sanitize_for_storage
from app.db.session import database_url, get_session_factory, init_database
from app.services.wazuh.models import AlertIngestionDocument
from app.services.wazuh.normalization.registry import normalize_alerts


def _now() -> datetime:
    return datetime.now(UTC)


def _fingerprint(document: AlertIngestionDocument) -> str:
    alert = document.normalized
    payload = [
        alert.agent_id,
        alert.rule_id,
        alert.source_ip,
        alert.target_user,
        alert.timestamp.isoformat(),
        alert.description,
    ]
    return hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _alert_dict(record: WazuhAlertRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "wazuh_document_id": record.wazuh_document_id,
        "wazuh_index": record.wazuh_index,
        "event_timestamp": record.event_timestamp,
        "agent_id": record.agent_id,
        "agent_name": record.agent_name,
        "rule_id": record.rule_id,
        "rule_level": record.rule_level,
        "source_ip": record.source_ip,
        "destination_ip": record.destination_ip,
        "target_user": record.target_user,
        "event_type": record.event_type,
        "raw_alert": deepcopy(record.raw_alert),
        "correlation_status": record.correlation_status,
    }


class InMemoryAlertMemoryRepository:
    durable = False

    def __init__(self) -> None:
        self._alerts: dict[str, dict[str, Any]] = {}
        self._cursors: dict[str, datetime] = {}
        self._references: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self._lock = RLock()

    def get_alert_by_document_id(
        self,
        document_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            value = self._alerts.get(document_id)
            return deepcopy(value) if value else None

    def remember_alert_document(
        self,
        document: AlertIngestionDocument,
    ) -> dict[str, Any]:
        alert = document.normalized
        with self._lock:
            record = self._alerts.setdefault(
                document.document_id,
                {
                    "id": len(self._alerts) + 1,
                    "wazuh_document_id": document.document_id,
                    "wazuh_index": document.index_name,
                    "event_timestamp": alert.timestamp,
                    "agent_id": alert.agent_id,
                    "agent_name": alert.agent_name,
                    "rule_id": alert.rule_id,
                    "rule_level": alert.rule_level,
                    "source_ip": alert.source_ip,
                    "destination_ip": None,
                    "target_user": alert.target_user,
                    "event_type": None,
                    "raw_alert": deepcopy(document.raw_document),
                    "correlation_status": "pending",
                },
            )
            return deepcopy(record)

    def get_user_cursor(self, user_id: str) -> datetime | None:
        with self._lock:
            return self._cursors.get(user_id)

    def advance_user_cursor(
        self,
        user_id: str,
        checked_at: datetime,
        finding_version: int | None = None,
    ) -> None:
        with self._lock:
            self._cursors[user_id] = checked_at

    def count_alerts_since(
        self,
        since: datetime,
        *,
        agent_id: str | None = None,
        min_level: int = 0,
    ) -> int:
        with self._lock:
            alerts = list(self._alerts.values())
        return sum(
            alert["event_timestamp"] > since
            and alert["rule_level"] >= min_level
            and (agent_id is None or alert["agent_id"] == agent_id)
            for alert in alerts
        )

    def finding_ids_for_agent(self, agent_id: str) -> set[str]:
        return set()

    def add_conversation_reference(
        self,
        *,
        conversation_id: str,
        message_id: str,
        organization_id: str,
        reference_type: str,
        reference_value: str,
    ) -> None:
        with self._lock:
            self._references.setdefault(
                (organization_id, conversation_id),
                [],
            ).append(
                {
                    "message_id": message_id,
                    "reference_type": reference_type,
                    "reference_value": reference_value,
                    "created_at": _now(),
                }
            )

    def recent_conversation_references(
        self,
        *,
        conversation_id: str,
        organization_id: str,
    ) -> dict[str, str]:
        with self._lock:
            rows = list(
                self._references.get((organization_id, conversation_id), [])
            )
        result: dict[str, str] = {}
        for row in reversed(rows):
            result.setdefault(row["reference_type"], row["reference_value"])
        return result


class SQLAlchemyAlertMemoryRepository:
    durable = True

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def get_alert_by_document_id(
        self,
        document_id: str,
    ) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(WazuhAlertRecord)
                .where(WazuhAlertRecord.wazuh_document_id == document_id)
                .order_by(WazuhAlertRecord.event_timestamp.desc())
                .limit(1)
            )
            return _alert_dict(record) if record else None

    def remember_alert_document(
        self,
        document: AlertIngestionDocument,
    ) -> dict[str, Any]:
        """Idempotently persist one alert obtained during validation."""

        self.ingest_page(
            source_name="wazuh-validation",
            documents=[document],
            search_after=document.sort_values or None,
        )
        record = self.get_alert_by_document_id(document.document_id)
        if record is None:
            raise RuntimeError("Alert persistence did not produce a record.")
        return record

    def checkpoint(self, source_name: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.get(IngestionCheckpointRecord, source_name)
            if record is None:
                return None
            return {
                "source_name": record.source_name,
                "last_event_timestamp": record.last_event_timestamp,
                "last_document_id": record.last_document_id,
                "search_after": deepcopy(record.search_after),
                "last_run_started_at": record.last_run_started_at,
                "last_run_completed_at": record.last_run_completed_at,
                "last_alert_count": record.last_alert_count,
                "status": record.status,
                "error_message": record.error_message,
            }

    def mark_ingestion_started(self, source_name: str) -> None:
        now = _now()
        with self._session_factory.begin() as session:
            record = session.get(IngestionCheckpointRecord, source_name)
            if record is None:
                record = IngestionCheckpointRecord(
                    source_name=source_name,
                    last_alert_count=0,
                )
                session.add(record)
            record.status = "running"
            record.error_message = None
            record.last_run_started_at = now
            record.updated_at = now

    def mark_ingestion_failed(self, source_name: str, error: Exception) -> None:
        now = _now()
        with self._session_factory.begin() as session:
            record = session.get(IngestionCheckpointRecord, source_name)
            if record is None:
                record = IngestionCheckpointRecord(
                    source_name=source_name,
                    last_alert_count=0,
                )
                session.add(record)
            record.status = "failed"
            record.error_message = bounded_excerpt(str(error), max_length=2000)
            record.updated_at = now

    def mark_ingestion_completed(
        self,
        source_name: str,
        *,
        alert_count: int,
    ) -> None:
        now = _now()
        with self._session_factory.begin() as session:
            record = session.get(IngestionCheckpointRecord, source_name)
            if record is None:
                record = IngestionCheckpointRecord(source_name=source_name)
                session.add(record)
            record.last_run_completed_at = now
            record.last_alert_count = alert_count
            record.status = "idle"
            record.error_message = None
            record.updated_at = now

    def ingest_page(
        self,
        *,
        source_name: str,
        documents: list[AlertIngestionDocument],
        search_after: list[Any] | None,
    ) -> int:
        """Insert and normalize a page, then atomically commit its checkpoint."""

        inserted = 0
        now = _now()
        with self._session_factory.begin() as session:
            dialect_insert = (
                insert
                if session.bind is not None
                and session.bind.dialect.name == "postgresql"
                else sqlite_insert
            )
            for document in documents:
                alert = document.normalized
                normalization_input = deepcopy(document.raw_document)
                normalization_input.setdefault(
                    "alert_id",
                    document.document_id,
                )
                envelope = normalize_alerts([normalization_input])[0]
                normalized = envelope.normalized
                statement = (
                    dialect_insert(WazuhAlertRecord)
                    .values(
                        wazuh_document_id=document.document_id,
                        wazuh_index=document.index_name,
                        event_timestamp=alert.timestamp,
                        agent_id=alert.agent_id,
                        agent_name=alert.agent_name,
                        rule_id=alert.rule_id,
                        rule_level=alert.rule_level,
                        source_ip=alert.source_ip,
                        destination_ip=normalized.destination_ip,
                        target_user=alert.target_user,
                        event_type=normalized.event_type,
                        fingerprint=_fingerprint(document),
                        raw_alert=sanitize_for_storage(document.raw_document),
                        normalized_at=now,
                        correlation_status="pending",
                        ingested_at=now,
                    )
                    .on_conflict_do_nothing(
                        index_elements=["wazuh_index", "wazuh_document_id"]
                    )
                    .returning(WazuhAlertRecord.id)
                )
                alert_id = session.scalar(statement)
                if alert_id is None:
                    continue
                session.add(
                    NormalizedEventRecord(
                        alert_id=alert_id,
                        event_type=normalized.event_type,
                        category=normalized.category,
                        attack_family=normalized.attack_family,
                        severity_score=normalized.rule_level,
                        confidence=(
                            0.9
                            if normalized.normalization_quality == "complete"
                            else 0.6
                        ),
                        asset_id=normalized.hostname or normalized.agent_id,
                        source_ip=normalized.source_ip,
                        destination_ip=normalized.destination_ip,
                        target_user=normalized.target_user,
                        process_name=normalized.process_name,
                        mitre_techniques=list(normalized.mitre_techniques),
                        normalized_data=envelope.model_dump(mode="json"),
                    )
                )
                inserted += 1

            checkpoint = session.get(IngestionCheckpointRecord, source_name)
            if checkpoint is None:
                checkpoint = IngestionCheckpointRecord(
                    source_name=source_name,
                )
                session.add(checkpoint)
            last = documents[-1] if documents else None
            checkpoint.last_event_timestamp = (
                last.normalized.timestamp
                if last
                else checkpoint.last_event_timestamp
            )
            checkpoint.last_document_id = (
                last.document_id if last else checkpoint.last_document_id
            )
            if documents:
                checkpoint.search_after = search_after
            checkpoint.updated_at = now
        return inserted

    def get_user_cursor(self, user_id: str) -> datetime | None:
        with self._session_factory() as session:
            record = session.get(UserAlertCursorRecord, user_id)
            return record.last_checked_at if record else None

    def advance_user_cursor(
        self,
        user_id: str,
        checked_at: datetime,
        finding_version: int | None = None,
    ) -> None:
        with self._session_factory.begin() as session:
            record = session.get(UserAlertCursorRecord, user_id)
            if record is None:
                session.add(
                    UserAlertCursorRecord(
                        user_id=user_id,
                        last_checked_at=checked_at,
                        last_seen_finding_version=finding_version,
                        updated_at=checked_at,
                    )
                )
            else:
                record.last_checked_at = checked_at
                if finding_version is not None:
                    record.last_seen_finding_version = finding_version
                record.updated_at = checked_at

    def count_alerts_since(
        self,
        since: datetime,
        *,
        agent_id: str | None = None,
        min_level: int = 0,
    ) -> int:
        statement = select(func.count(WazuhAlertRecord.id)).where(
            WazuhAlertRecord.event_timestamp > since,
            WazuhAlertRecord.rule_level >= min_level,
        )
        if agent_id:
            statement = statement.where(
                WazuhAlertRecord.agent_id == agent_id
            )
        with self._session_factory() as session:
            return int(session.scalar(statement) or 0)

    def finding_ids_for_agent(self, agent_id: str) -> set[str]:
        statement = (
            select(FindingAlertRecord.finding_id)
            .join(
                WazuhAlertRecord,
                WazuhAlertRecord.id == FindingAlertRecord.alert_id,
            )
            .where(WazuhAlertRecord.agent_id == agent_id)
            .distinct()
        )
        with self._session_factory() as session:
            return set(session.scalars(statement).all())

    def add_conversation_reference(
        self,
        *,
        conversation_id: str,
        message_id: str,
        organization_id: str,
        reference_type: str,
        reference_value: str,
    ) -> None:
        with self._session_factory.begin() as session:
            session.add(
                ConversationReferenceRecord(
                    conversation_id=conversation_id,
                    message_id=message_id,
                    organization_id=organization_id,
                    reference_type=reference_type,
                    reference_value=reference_value,
                )
            )

    def recent_conversation_references(
        self,
        *,
        conversation_id: str,
        organization_id: str,
    ) -> dict[str, str]:
        statement = (
            select(ConversationReferenceRecord)
            .where(
                ConversationReferenceRecord.conversation_id == conversation_id,
                ConversationReferenceRecord.organization_id == organization_id,
            )
            .order_by(ConversationReferenceRecord.created_at.desc())
            .limit(30)
        )
        with self._session_factory() as session:
            rows = list(session.scalars(statement).all())
        result: dict[str, str] = {}
        for row in rows:
            result.setdefault(row.reference_type, row.reference_value)
        return result

    def pending_normalized_events(
        self,
        *,
        limit: int = 500,
    ) -> list[tuple[int, dict[str, Any]]]:
        statement = (
            select(WazuhAlertRecord.id, NormalizedEventRecord.normalized_data)
            .join(
                NormalizedEventRecord,
                NormalizedEventRecord.alert_id == WazuhAlertRecord.id,
            )
            .where(WazuhAlertRecord.correlation_status == "pending")
            .order_by(WazuhAlertRecord.event_timestamp.asc())
            .limit(limit)
        )
        with self._session_factory() as session:
            return [
                (int(alert_id), deepcopy(data))
                for alert_id, data in session.execute(statement).all()
            ]

    def attach_finding(
        self,
        *,
        finding_id: str,
        alert_ids: list[int],
    ) -> None:
        with self._session_factory.begin() as session:
            dialect_insert = (
                insert
                if session.bind is not None
                and session.bind.dialect.name == "postgresql"
                else sqlite_insert
            )
            for alert_id in alert_ids:
                statement = (
                    dialect_insert(FindingAlertRecord)
                    .values(finding_id=finding_id, alert_id=alert_id)
                    .on_conflict_do_nothing(
                        index_elements=["finding_id", "alert_id"]
                    )
                )
                session.execute(statement)
                alert = session.get(WazuhAlertRecord, alert_id)
                if alert is not None:
                    alert.correlation_status = "correlated"
            finding = session.get(FindingRecord, finding_id)
            if finding is not None:
                count = session.query(FindingAlertRecord).filter(
                    FindingAlertRecord.finding_id == finding_id
                ).count()
                finding.alert_count = count
                finding.finding = {
                    **finding.finding,
                    "alert_count": count,
                }


_memory_repository = InMemoryAlertMemoryRepository()


@lru_cache(maxsize=1)
def get_alert_memory_repository():
    if not database_url():
        return _memory_repository
    if settings.DATABASE_AUTO_CREATE:
        init_database()
    return SQLAlchemyAlertMemoryRepository(get_session_factory())


def close_alert_memory_repository() -> None:
    get_alert_memory_repository.cache_clear()
