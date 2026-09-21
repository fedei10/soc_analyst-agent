"""Persistence boundary for triage findings and analyst feedback."""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import UTC, datetime
from functools import lru_cache
from threading import RLock
from typing import Any, Protocol

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.db.models.finding import FindingFeedbackRecord, FindingRecord
from app.db.sanitization import sanitize_for_storage
from app.db.session import (
    DatabaseNotConfiguredError,
    database_url,
    get_session_factory,
    init_database,
)
from app.services.wazuh.normalization.schemas import SecurityFinding
from app.services.wazuh.triage.schemas import EnrichmentResult, TriageVerdict


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _unique(values: list[Any]) -> list[Any]:
    return list(dict.fromkeys(values))


def _merge_finding_data(
    existing: dict[str, Any],
    incoming: dict[str, Any],
    *,
    first_seen: datetime,
    last_seen: datetime,
    alert_count: int,
    evidence_refs: list[str],
) -> dict[str, Any]:
    merged = {**existing, **incoming}
    for key in (
        "affected_assets",
        "source_ips",
        "target_users",
        "mitre_techniques",
    ):
        merged[key] = _unique(
            list(existing.get(key) or []) + list(incoming.get(key) or [])
        )
    merged.update(
        {
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "alert_count": alert_count,
            "evidence_refs": evidence_refs,
        }
    )
    return merged


def _feedback_id() -> str:
    return f"FB-{uuid.uuid4().hex[:20].upper()}"


def _status_for_disposition(disposition: str) -> str | None:
    if disposition in {"confirmed_benign", "expected_admin_activity"}:
        return "false_positive"
    if disposition == "confirmed_malicious":
        return "investigating"
    if disposition == "duplicate_incident":
        return "resolved"
    return None


class FindingOwnershipError(PermissionError):
    pass


class FindingRepository(Protocol):
    def upsert(
        self,
        *,
        organization_id: str,
        finding: SecurityFinding,
        verdict: TriageVerdict,
        enrichment: list[EnrichmentResult],
    ) -> dict[str, Any]: ...

    def get(
        self,
        finding_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None: ...

    def list(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
        severity: str | None = None,
        verdict: str | None = None,
        status: str | None = None,
        has_verdict: bool | None = None,
        finding_ids: set[str] | None = None,
        text: str | None = None,
        created_after: datetime | None = None,
        updated_after: datetime | None = None,
        created_on_or_before: datetime | None = None,
        changed_after: datetime | None = None,
    ) -> list[dict[str, Any]]: ...

    def count(
        self,
        *,
        organization_id: str,
        severity: str | None = None,
        verdict: str | None = None,
        status: str | None = None,
        has_verdict: bool | None = None,
        finding_ids: set[str] | None = None,
        text: str | None = None,
        created_after: datetime | None = None,
        updated_after: datetime | None = None,
        created_on_or_before: datetime | None = None,
        changed_after: datetime | None = None,
    ) -> int: ...

    def add_feedback(
        self,
        *,
        finding_id: str,
        organization_id: str,
        reviewer_user_id: str,
        disposition: str,
        notes: str | None,
    ) -> dict[str, Any]: ...

    def list_feedback(
        self,
        finding_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]: ...


class InMemoryFindingRepository:
    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {}
        self._feedback: dict[str, list[dict[str, Any]]] = {}
        self._lock = RLock()

    def upsert(
        self,
        *,
        organization_id: str,
        finding: SecurityFinding,
        verdict: TriageVerdict,
        enrichment: list[EnrichmentResult],
    ) -> dict[str, Any]:
        with self._lock:
            existing = self._records.get(finding.finding_id)
            if existing is not None and existing["organization_id"] != organization_id:
                raise FindingOwnershipError("Finding belongs to another organization.")
            now = _utc_now()
            incoming_data = finding.model_dump(mode="json")
            evidence_refs = _unique(
                list(existing["evidence_refs"] if existing else [])
                + list(finding.evidence_refs)
            )
            new_references = (
                len(
                    set(finding.evidence_refs)
                    - set(existing["evidence_refs"])
                )
                if existing
                else len(finding.evidence_refs)
            )
            first_seen = min(
                existing["first_seen"] if existing else finding.first_seen,
                finding.first_seen,
            )
            last_seen = max(
                existing["last_seen"] if existing else finding.last_seen,
                finding.last_seen,
            )
            alert_count = (
                existing["alert_count"] + new_references
                if existing
                else finding.alert_count
            )
            verdict_data = verdict.model_dump(mode="json")
            enrichment_data = [
                item.model_dump(mode="json") for item in enrichment
            ]
            changed = bool(
                existing is None
                or new_references
                or finding.last_seen > existing["last_seen"]
                or verdict_data != existing["verdict"]
                or enrichment_data != existing["enrichment"]
            )
            finding_data = _merge_finding_data(
                existing["finding"] if existing else {},
                incoming_data,
                first_seen=first_seen,
                last_seen=last_seen,
                alert_count=alert_count,
                evidence_refs=evidence_refs,
            )
            record = {
                "finding_id": finding.finding_id,
                "organization_id": organization_id,
                "correlation_key": finding.finding_id,
                "status": existing["status"] if existing else "open",
                "version": (
                    existing["version"] + 1
                    if existing and changed
                    else existing["version"]
                    if existing
                    else 1
                ),
                "category": finding.category,
                "attack_family": finding.attack_family,
                "event_type": finding.event_type,
                "severity": finding.severity,
                "severity_score": finding.severity_score,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "alert_count": alert_count,
                "representative_alert_id": finding.representative_alert_id,
                "evidence_refs": evidence_refs,
                "finding": finding_data,
                "verdict": verdict_data,
                "enrichment": enrichment_data,
                "created_at": existing["created_at"] if existing else now,
                "updated_at": (
                    now if changed else existing["updated_at"]
                ),
            }
            self._records[finding.finding_id] = record
            return deepcopy(record) | {
                "feedback": deepcopy(self._feedback.get(finding.finding_id, []))
            }

    def get(self, finding_id: str, *, organization_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get(finding_id)
            if record is None or record["organization_id"] != organization_id:
                return None
            return deepcopy(record) | {
                "feedback": deepcopy(self._feedback.get(finding_id, []))
            }

    def list(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
        severity: str | None = None,
        verdict: str | None = None,
        status: str | None = None,
        has_verdict: bool | None = None,
        finding_ids: set[str] | None = None,
        text: str | None = None,
        created_after: datetime | None = None,
        updated_after: datetime | None = None,
        created_on_or_before: datetime | None = None,
        changed_after: datetime | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            values = [
                deepcopy(item)
                for item in self._records.values()
                if item["organization_id"] == organization_id
            ]
        if severity:
            values = [item for item in values if item["severity"] == severity]
        if verdict:
            values = [item for item in values if item["verdict"]["verdict"] == verdict]
        if status:
            values = [item for item in values if item["status"] == status]
        if has_verdict is not None:
            values = [
                item
                for item in values
                if bool((item.get("verdict") or {}).get("verdict")) is has_verdict
            ]
        if finding_ids is not None:
            values = [item for item in values if item["finding_id"] in finding_ids]
        if text:
            needle = text.strip().lower()
            values = [
                item
                for item in values
                if needle
                in " ".join(
                    (
                        str(item["finding"].get("title") or ""),
                        str(item["finding"].get("summary") or ""),
                        str(item.get("event_type") or ""),
                    )
                ).lower()
            ]
        if created_after is not None:
            values = [item for item in values if item["created_at"] > created_after]
        if updated_after is not None:
            values = [item for item in values if item["updated_at"] > updated_after]
        if created_on_or_before is not None:
            values = [
                item for item in values if item["created_at"] <= created_on_or_before
            ]
        if changed_after is not None:
            values = [
                item
                for item in values
                if item["created_at"] > changed_after
                or item["updated_at"] > changed_after
            ]
        values.sort(key=lambda item: item["updated_at"], reverse=True)
        return values[offset : offset + limit]

    def count(self, **filters: Any) -> int:
        return len(self.list(limit=len(self._records) + 1, offset=0, **filters))

    def add_feedback(
        self,
        *,
        finding_id: str,
        organization_id: str,
        reviewer_user_id: str,
        disposition: str,
        notes: str | None,
    ) -> dict[str, Any]:
        with self._lock:
            record = self._records.get(finding_id)
            if record is None or record["organization_id"] != organization_id:
                raise LookupError(f"Finding {finding_id} not found.")
            entry = {
                "feedback_id": _feedback_id(),
                "finding_id": finding_id,
                "organization_id": organization_id,
                "reviewer_user_id": reviewer_user_id,
                "disposition": disposition,
                "notes": notes,
                "created_at": _utc_now(),
            }
            self._feedback.setdefault(finding_id, []).append(entry)
            status = _status_for_disposition(disposition)
            if status and record["status"] != status:
                record["status"] = status
                record["version"] += 1
                record["updated_at"] = entry["created_at"]
            return deepcopy(entry)

    def list_feedback(
        self,
        finding_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        with self._lock:
            record = self._records.get(finding_id)
            if record is None or record["organization_id"] != organization_id:
                return []
            return deepcopy(self._feedback.get(finding_id, []))


def _finding_record_dict(record: FindingRecord) -> dict[str, Any]:
    return {
        "finding_id": record.finding_id,
        "organization_id": record.organization_id,
        "correlation_key": record.correlation_key,
        "status": record.status,
        "version": record.version,
        "category": record.category,
        "attack_family": record.attack_family,
        "event_type": record.event_type,
        "severity": record.severity,
        "severity_score": record.severity_score,
        "first_seen": record.first_seen,
        "last_seen": record.last_seen,
        "alert_count": record.alert_count,
        "representative_alert_id": record.representative_alert_id,
        "evidence_refs": deepcopy(record.evidence_refs),
        "finding": deepcopy(record.finding),
        "verdict": deepcopy(record.verdict),
        "enrichment": deepcopy(record.enrichment),
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


def _feedback_record_dict(record: FindingFeedbackRecord) -> dict[str, Any]:
    return {
        "feedback_id": record.feedback_id,
        "finding_id": record.finding_id,
        "organization_id": record.organization_id,
        "reviewer_user_id": record.reviewer_user_id,
        "disposition": record.disposition,
        "notes": record.notes,
        "created_at": record.created_at,
    }


class SQLAlchemyFindingRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def upsert(
        self,
        *,
        organization_id: str,
        finding: SecurityFinding,
        verdict: TriageVerdict,
        enrichment: list[EnrichmentResult],
    ) -> dict[str, Any]:
        finding_data = sanitize_for_storage(finding.model_dump(mode="json"))
        verdict_data = sanitize_for_storage(verdict.model_dump(mode="json"))
        enrichment_data = sanitize_for_storage(
            [item.model_dump(mode="json") for item in enrichment]
        )
        now = _utc_now()
        with self._session_factory.begin() as session:
            record = session.get(
                FindingRecord,
                finding.finding_id,
                with_for_update=True,
            )
            if record is None:
                record = FindingRecord(
                    finding_id=finding.finding_id,
                    organization_id=organization_id,
                    correlation_key=finding.finding_id,
                    status="open",
                    version=1,
                    category=finding.category,
                    attack_family=finding.attack_family,
                    event_type=finding.event_type,
                    severity=finding.severity,
                    severity_score=finding.severity_score,
                    first_seen=finding.first_seen,
                    last_seen=finding.last_seen,
                    alert_count=finding.alert_count,
                    representative_alert_id=finding.representative_alert_id,
                    evidence_refs=list(finding.evidence_refs),
                    finding=finding_data,
                    verdict=verdict_data,
                    verdict_label=verdict.verdict,
                    verdict_confidence=verdict.confidence,
                    enrichment=enrichment_data,
                    created_at=now,
                    updated_at=now,
                )
                session.add(record)
            else:
                if record.organization_id != organization_id:
                    raise FindingOwnershipError(
                        "Finding belongs to another organization."
                    )
                old_refs = list(record.evidence_refs)
                evidence_refs = _unique(
                    old_refs + list(finding.evidence_refs)
                )
                new_references = len(
                    set(finding.evidence_refs) - set(old_refs)
                )
                changed = bool(
                    new_references
                    or finding.last_seen > record.last_seen
                    or verdict_data != record.verdict
                    or enrichment_data != record.enrichment
                )
                first_seen = min(record.first_seen, finding.first_seen)
                last_seen = max(record.last_seen, finding.last_seen)
                alert_count = record.alert_count + new_references
                record.severity = finding.severity
                record.severity_score = finding.severity_score
                record.first_seen = first_seen
                record.last_seen = last_seen
                record.alert_count = alert_count
                record.evidence_refs = evidence_refs
                if changed:
                    record.version += 1
                record.finding = sanitize_for_storage(
                    _merge_finding_data(
                        record.finding,
                        finding_data,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        alert_count=alert_count,
                        evidence_refs=evidence_refs,
                    )
                )
                record.verdict = verdict_data
                record.verdict_label = verdict.verdict
                record.verdict_confidence = verdict.confidence
                record.enrichment = enrichment_data
                if changed:
                    record.updated_at = now
            session.flush()
            data = _finding_record_dict(record)
        data["feedback"] = self.list_feedback(
            finding.finding_id,
            organization_id=organization_id,
        )
        return data

    def get(self, finding_id: str, *, organization_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.get(FindingRecord, finding_id)
            if record is None or record.organization_id != organization_id:
                return None
            data = _finding_record_dict(record)
        data["feedback"] = self.list_feedback(finding_id, organization_id=organization_id)
        return data

    @staticmethod
    def _apply_filters(
        statement: Any,
        *,
        organization_id: str,
        severity: str | None = None,
        verdict: str | None = None,
        status: str | None = None,
        has_verdict: bool | None = None,
        finding_ids: set[str] | None = None,
        text: str | None = None,
        created_after: datetime | None = None,
        updated_after: datetime | None = None,
        created_on_or_before: datetime | None = None,
        changed_after: datetime | None = None,
    ) -> Any:
        statement = statement.where(FindingRecord.organization_id == organization_id)
        if severity:
            statement = statement.where(FindingRecord.severity == severity)
        if verdict:
            statement = statement.where(FindingRecord.verdict_label == verdict)
        if status:
            statement = statement.where(FindingRecord.status == status)
        if has_verdict is True:
            statement = statement.where(FindingRecord.verdict_label.is_not(None))
        elif has_verdict is False:
            statement = statement.where(FindingRecord.verdict_label.is_(None))
        if finding_ids is not None:
            statement = statement.where(FindingRecord.finding_id.in_(finding_ids))
        if text:
            pattern = f"%{text.strip()}%"
            statement = statement.where(
                or_(
                    FindingRecord.event_type.ilike(pattern),
                    cast(FindingRecord.finding, String).ilike(pattern),
                )
            )
        if created_after is not None:
            statement = statement.where(FindingRecord.created_at > created_after)
        if updated_after is not None:
            statement = statement.where(FindingRecord.updated_at > updated_after)
        if created_on_or_before is not None:
            statement = statement.where(FindingRecord.created_at <= created_on_or_before)
        if changed_after is not None:
            statement = statement.where(
                or_(
                    FindingRecord.created_at > changed_after,
                    FindingRecord.updated_at > changed_after,
                )
            )
        return statement

    def list(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
        severity: str | None = None,
        verdict: str | None = None,
        status: str | None = None,
        has_verdict: bool | None = None,
        finding_ids: set[str] | None = None,
        text: str | None = None,
        created_after: datetime | None = None,
        updated_after: datetime | None = None,
        created_on_or_before: datetime | None = None,
        changed_after: datetime | None = None,
    ) -> list[dict[str, Any]]:
        statement = self._apply_filters(
            select(FindingRecord),
            organization_id=organization_id,
            severity=severity,
            verdict=verdict,
            status=status,
            has_verdict=has_verdict,
            finding_ids=finding_ids,
            text=text,
            created_after=created_after,
            updated_after=updated_after,
            created_on_or_before=created_on_or_before,
            changed_after=changed_after,
        )
        statement = (
            statement
            .order_by(FindingRecord.updated_at.desc())
            .offset(offset)
            .limit(limit)
        )
        with self._session_factory() as session:
            return [_finding_record_dict(record) for record in session.scalars(statement).all()]

    def count(
        self,
        *,
        organization_id: str,
        severity: str | None = None,
        verdict: str | None = None,
        status: str | None = None,
        has_verdict: bool | None = None,
        finding_ids: set[str] | None = None,
        text: str | None = None,
        created_after: datetime | None = None,
        updated_after: datetime | None = None,
        created_on_or_before: datetime | None = None,
        changed_after: datetime | None = None,
    ) -> int:
        statement = self._apply_filters(
            select(func.count()).select_from(FindingRecord),
            organization_id=organization_id,
            severity=severity,
            verdict=verdict,
            status=status,
            has_verdict=has_verdict,
            finding_ids=finding_ids,
            text=text,
            created_after=created_after,
            updated_after=updated_after,
            created_on_or_before=created_on_or_before,
            changed_after=changed_after,
        )
        with self._session_factory() as session:
            return int(session.scalar(statement) or 0)

    def add_feedback(
        self,
        *,
        finding_id: str,
        organization_id: str,
        reviewer_user_id: str,
        disposition: str,
        notes: str | None,
    ) -> dict[str, Any]:
        with self._session_factory.begin() as session:
            finding_record = session.get(FindingRecord, finding_id)
            if finding_record is None or finding_record.organization_id != organization_id:
                raise LookupError(f"Finding {finding_id} not found.")
            record = FindingFeedbackRecord(
                feedback_id=_feedback_id(),
                finding_id=finding_id,
                organization_id=organization_id,
                reviewer_user_id=reviewer_user_id,
                disposition=disposition,
                notes=notes,
                created_at=_utc_now(),
            )
            session.add(record)
            status = _status_for_disposition(disposition)
            if status and finding_record.status != status:
                finding_record.status = status
                finding_record.version += 1
                finding_record.updated_at = record.created_at
            session.flush()
            data = _feedback_record_dict(record)
        return data

    def list_feedback(
        self,
        finding_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        statement = (
            select(FindingFeedbackRecord)
            .where(
                FindingFeedbackRecord.finding_id == finding_id,
                FindingFeedbackRecord.organization_id == organization_id,
            )
            .order_by(FindingFeedbackRecord.created_at.asc())
        )
        with self._session_factory() as session:
            return [_feedback_record_dict(record) for record in session.scalars(statement).all()]


@lru_cache(maxsize=1)
def get_finding_repository() -> FindingRepository:
    if not database_url():
        if settings.DATABASE_REQUIRED:
            raise DatabaseNotConfiguredError(
                "DATABASE_REQUIRED is true but DATABASE_URL is empty."
            )
        return InMemoryFindingRepository()
    if settings.DATABASE_AUTO_CREATE:
        init_database()
    return SQLAlchemyFindingRepository(get_session_factory())


def close_finding_repository() -> None:
    get_finding_repository.cache_clear()
