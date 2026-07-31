"""Persistence boundary for SOC investigations and immutable history."""

import hashlib
import json
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from threading import RLock
from typing import Any, Protocol

from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.db.models.investigation import (
    AgentRunRecord,
    ApprovalRecord,
    AuditEventRecord,
    EvidenceRecord,
    InvestigationRecord,
    InvestigationResourceLeaseRecord,
    InvestigationReportRecord,
    ResponseActionRecord,
    TierReportRecord,
    ToolExecutionRecord,
)
from app.db.models.alert_memory import InvestigationStepRecord
from app.db.models.alert_memory import WazuhAlertRecord
from app.orchestration.reporting import build_tier_report
from app.orchestration.schemas import AgentTier
from app.db.sanitization import bounded_excerpt, sanitize_for_storage
from app.db.session import (
    DatabaseNotConfiguredError,
    database_url,
    get_session_factory,
    init_database,
)


TERMINAL_STATUSES = {"completed", "failed", "rejected", "escalated"}

# Worker pickup order. Ready verifications come first because their observation
# window has already elapsed and every further delay widens it; within a class,
# a critical incident should not wait behind a batch of low-severity ones.
_WORKER_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


def worker_candidate_priority(snapshot: dict[str, Any]) -> tuple[int, int, str]:
    status = str(snapshot.get("status") or "")
    severity = str(snapshot.get("severity") or "").lower()
    return (
        0 if status == "waiting_verification" else 1,
        _WORKER_SEVERITY_RANK.get(severity, 3),
        str(snapshot.get("updated_at") or ""),
    )
ROLLBACK_ELIGIBLE_STATUSES = {
    "accepted",
    "applied",
    "executed",
    "outcome_unknown",
    "rollback_failed_retryable",
}
ROLLBACK_RESULT_STATUSES = {
    "rolled_back",
    "rollback_failed_retryable",
    "rollback_failed_terminal",
}


class ResponseExecutionConflictError(RuntimeError):
    pass


class InvestigationStateConflictError(RuntimeError):
    pass


class ResourceLeaseConflictError(RuntimeError):
    pass


def _json_value(value: Any) -> Any:
    return sanitize_for_storage(value)


def _parse_datetime(value: Any, default: datetime | None = None) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = default or datetime.now(UTC)
    else:
        parsed = default or datetime.now(UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = json.dumps(parts, sort_keys=True, default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:40]
    return f"{prefix}-{digest}"


def _rollback_idempotency_key(record: dict[str, Any]) -> str:
    return _stable_id(
        "RBK-IDEM",
        record.get("organization_id"),
        record.get("action_id"),
        record.get("rollback_action_id"),
    )


def _rollback_record_is_eligible(
    record: dict[str, Any],
    *,
    now: datetime,
    stale_before: datetime,
    max_retries: int,
) -> bool:
    expires_at = record.get("expires_at")
    if (
        not expires_at
        or not record.get("rollback_action_id")
        or int(record.get("rollback_retry_count") or 0) > max_retries
        or _parse_datetime(expires_at) > now
    ):
        return False
    status = str(record.get("status") or "")
    if status in ROLLBACK_ELIGIBLE_STATUSES:
        return True
    last_attempt = record.get("last_rollback_attempt")
    return bool(
        status == "rollback_running"
        and last_attempt
        and _parse_datetime(last_attempt) <= stale_before
    )


def _response_action_payload(
    record: ResponseActionRecord,
) -> dict[str, Any]:
    return {
        "action_id": record.action_id,
        "investigation_id": record.investigation_id,
        "organization_id": record.organization_id,
        "action_type": record.action_type,
        "target": record.target,
        "risk_level": record.risk_level,
        "status": record.status,
        "plan_id": record.plan_id,
        "plan_hash": record.plan_hash,
        "evidence_version": record.evidence_version,
        "approval_id": record.approval_id,
        "approved_by": record.approved_by,
        "approved_by_user_id": record.approved_by_user_id,
        "execution_id": record.execution_id,
        "executor_user_id": record.executor_user_id,
        "claimed_at": record.claimed_at,
        "executed_at": record.executed_at,
        "rollback_action_id": record.rollback_action_id,
        "expires_at": record.expires_at,
        "retry_count": record.retry_count,
        "rollback_claim_id": record.rollback_claim_id,
        "rollback_retry_count": record.rollback_retry_count,
        "last_rollback_attempt": record.last_rollback_attempt,
        "rollback_completed_at": record.rollback_completed_at,
        "details": deepcopy(record.details),
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


def _overdue_response_action_statement(
    *,
    organization_id: str,
    now: datetime,
    claim_timeout_seconds: int,
    max_retries: int,
) -> Select:
    stale_before = now - timedelta(
        seconds=max(1, claim_timeout_seconds)
    )
    return (
        select(ResponseActionRecord)
        .where(
            ResponseActionRecord.organization_id == organization_id,
            ResponseActionRecord.expires_at.is_not(None),
            ResponseActionRecord.expires_at <= now,
            ResponseActionRecord.rollback_action_id.is_not(None),
            ResponseActionRecord.rollback_retry_count
            <= max(0, max_retries),
            or_(
                ResponseActionRecord.status.in_(
                    tuple(sorted(ROLLBACK_ELIGIBLE_STATUSES))
                ),
                and_(
                    ResponseActionRecord.status == "rollback_running",
                    ResponseActionRecord.last_rollback_attempt.is_not(None),
                    ResponseActionRecord.last_rollback_attempt <= stale_before,
                ),
            ),
        )
        .order_by(
            ResponseActionRecord.expires_at,
            ResponseActionRecord.action_id,
        )
    )


def _expected_state_version(
    snapshot: dict[str, Any],
    expected_version: int | None,
) -> int | None:
    value = (
        expected_version
        if expected_version is not None
        else snapshot.get("state_version")
    )
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("state_version must be a non-negative integer.")
    try:
        version = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "state_version must be a non-negative integer."
        ) from exc
    if version < 0:
        raise ValueError("state_version must be a non-negative integer.")
    return version


def _lease_now(value: datetime | None = None) -> datetime:
    return _parse_datetime(value, default=datetime.now(UTC))


def _lease_key(
    *,
    organization_id: str,
    resource_type: str,
    resource_id: str,
) -> tuple[str, str, str, str]:
    organization_id = organization_id.strip()
    resource_type = resource_type.strip().lower()
    resource_id = resource_id.strip()
    if not organization_id:
        raise ValueError("organization_id is required.")
    if not resource_type:
        raise ValueError("resource_type is required.")
    if not resource_id:
        raise ValueError("resource_id is required.")
    return (
        _stable_id(
            "lock",
            organization_id,
            resource_type,
            resource_id,
        ),
        organization_id,
        resource_type,
        resource_id,
    )


def _lease_expiry(now: datetime, lease_seconds: int) -> datetime:
    if (
        isinstance(lease_seconds, bool)
        or not isinstance(lease_seconds, int)
        or not 1 <= lease_seconds <= 86_400
    ):
        raise ValueError("lease_seconds must be between 1 and 86400.")
    return now + timedelta(seconds=lease_seconds)


def _lease_payload(
    *,
    lock_key: str,
    organization_id: str,
    resource_type: str,
    resource_id: str,
    lease_token: str,
    owner_id: str,
    acquired_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    return {
        "lock_key": lock_key,
        "organization_id": organization_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "lease_token": lease_token,
        "owner_id": owner_id,
        "acquired_at": acquired_at,
        "expires_at": expires_at,
    }


def _event_time(
    snapshot: dict[str, Any],
    *,
    stage: str,
    event: str,
) -> datetime | None:
    for item in snapshot.get("audit_events", []):
        if item.get("stage") == stage and item.get("event") == event:
            return _parse_datetime(item.get("timestamp"))
    return None


class InvestigationRepository(Protocol):
    durable: bool

    def save_snapshot(
        self,
        snapshot: dict[str, Any],
        *,
        expected_version: int | None = None,
    ) -> int: ...

    def get_snapshot(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None: ...

    def list_snapshots(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict[str, Any]]: ...

    def count_snapshots(
        self,
        *,
        organization_id: str,
        status: str | None = None,
    ) -> int: ...

    def list_worker_candidates(
        self,
        *,
        statuses: tuple[str, ...],
        limit: int,
    ) -> list[dict[str, Any]]: ...

    def get_active_for_alert(
        self,
        alert_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None: ...

    def get_report(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None: ...

    def save_tier_report(
        self,
        snapshot: dict[str, Any],
        *,
        tier: AgentTier,
    ) -> dict[str, Any]: ...

    def list_tier_reports(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]: ...

    def list_agent_runs(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]: ...

    def list_audit_events(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]: ...

    def append_audit_events(
        self,
        investigation_id: str,
        *,
        organization_id: str,
        events: list[dict[str, Any]],
    ) -> None: ...

    def list_approvals(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]: ...

    def list_response_actions(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]: ...

    def list_response_action_organizations(self) -> list[str]: ...

    def claim_response_actions(
        self,
        investigation_id: str,
        *,
        organization_id: str,
        approval_id: str,
        executor_user_id: str,
        executor_roles: list[str],
        expected_action_ids: list[str],
        expected_plan_hash: str,
        expected_evidence_version: str,
    ) -> dict[str, Any]: ...

    def mark_execution_failed(
        self,
        execution_id: str,
        *,
        organization_id: str,
    ) -> None: ...

    def begin_response_action(
        self,
        action_id: str,
        *,
        organization_id: str,
        execution_id: str,
        before_state: dict[str, Any],
        intended_expires_at: datetime | None,
        idempotency_key: str,
    ) -> bool: ...

    def complete_response_action(
        self,
        action_id: str,
        *,
        organization_id: str,
        execution_id: str,
        status: str,
        details: dict[str, Any],
        expires_at: datetime | None = None,
    ) -> None: ...

    def list_overdue_response_actions(
        self,
        *,
        organization_id: str,
        now: datetime,
        limit: int = 100,
        claim_timeout_seconds: int = 300,
        max_retries: int = 1,
    ) -> list[dict[str, Any]]: ...

    def claim_overdue_response_actions(
        self,
        *,
        organization_id: str,
        now: datetime,
        limit: int = 100,
        claim_timeout_seconds: int = 300,
        max_retries: int = 1,
    ) -> list[dict[str, Any]]: ...

    def complete_response_action_rollback(
        self,
        action_id: str,
        *,
        organization_id: str,
        rollback_claim_id: str,
        success: bool,
        retryable: bool,
        details: dict[str, Any],
        completed_at: datetime,
        max_retries: int = 1,
    ) -> str: ...

    def acquire_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        owner_id: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> dict[str, Any]: ...

    def renew_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        lease_token: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> dict[str, Any]: ...

    def release_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        lease_token: str,
    ) -> bool: ...


class InMemoryInvestigationRepository:
    durable = False

    def __init__(self) -> None:
        self._snapshots: dict[tuple[str, str], dict[str, Any]] = {}
        self._claims: dict[tuple[str, str], dict[str, Any]] = {}
        self._response_actions: dict[
            tuple[str, str], dict[str, Any]
        ] = {}
        self._tier_reports: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._resource_leases: dict[
            tuple[str, str, str],
            dict[str, Any],
        ] = {}
        self._lock = RLock()

    def _sync_response_actions(self, snapshot: dict[str, Any]) -> None:
        organization_id = str(snapshot["organization_id"])
        investigation_id = str(snapshot["investigation_id"])
        decision = snapshot.get("approval_decision") or {}
        request = snapshot.get("approval_request") or {}
        plan = snapshot.get("remediation_plan") or {}
        executed_by_id = {
            item.get("action_id"): item
            for item in snapshot.get("executed_actions", [])
            if isinstance(item, dict) and item.get("action_id")
        }
        executed_by_target = {
            (item.get("action_type"), item.get("target")): item
            for item in snapshot.get("executed_actions", [])
            if isinstance(item, dict)
        }
        rollback_by_action = {
            str(item.get("parameters", {}).get("reverts_action_id")): item
            for item in plan.get("rollback_actions", [])
            if isinstance(item, dict)
            and item.get("parameters", {}).get("reverts_action_id")
        }
        now = datetime.now(UTC)
        protected_statuses = {
            "claimed",
            "running",
            "accepted",
            "applied",
            "executed",
            "outcome_unknown",
            "no_op",
            "rollback_running",
            "rollback_failed_retryable",
            "rollback_failed_terminal",
            "rolled_back",
        }
        for index, action in enumerate(snapshot.get("proposed_actions", [])):
            if not isinstance(action, dict):
                continue
            action_id = str(action.get("action_id") or _stable_id(
                "ACT",
                investigation_id,
                index,
                action.get("action_type"),
                action.get("target"),
            ))
            execution = (
                executed_by_id.get(action_id)
                or executed_by_target.get(
                    (action.get("action_type"), action.get("target"))
                )
            )
            if execution:
                snapshot_status = str(execution.get("status") or "executed")
            elif decision.get("decision") == "reject":
                snapshot_status = "rejected"
            elif decision.get("decision") == "approve":
                snapshot_status = "approved"
            else:
                snapshot_status = "proposed"
            rollback_action = rollback_by_action.get(action_id)
            result = (
                execution.get("result")
                if execution and isinstance(execution.get("result"), dict)
                else {}
            )
            expires_at = (
                _parse_datetime(result["expires_at"])
                if result.get("expires_at")
                else None
            )
            key = (organization_id, action_id)
            record = self._response_actions.get(key)
            details = deepcopy({**action, **(execution or {})})
            if record is None:
                self._response_actions[key] = {
                    "action_id": action_id,
                    "investigation_id": investigation_id,
                    "organization_id": organization_id,
                    "action_type": str(
                        action.get("action_type") or "unknown"
                    ),
                    "target": str(action.get("target") or ""),
                    "risk_level": action.get("risk_level"),
                    "status": snapshot_status,
                    "plan_id": request.get("plan_id"),
                    "plan_hash": request.get("plan_hash"),
                    "evidence_version": request.get("evidence_version"),
                    "approval_id": decision.get("approval_id"),
                    "approved_by": decision.get("actor_user_id"),
                    "approved_by_user_id": decision.get("actor_user_id"),
                    "execution_id": (
                        execution.get("execution_id") if execution else None
                    ),
                    "executor_user_id": (
                        execution.get("executed_by") if execution else None
                    ),
                    "claimed_at": None,
                    "executed_at": now if execution else None,
                    "rollback_action_id": (
                        str(rollback_action.get("action_id"))
                        if rollback_action
                        else None
                    ),
                    "expires_at": expires_at,
                    "retry_count": 0,
                    "rollback_claim_id": None,
                    "rollback_retry_count": 0,
                    "last_rollback_attempt": None,
                    "rollback_completed_at": None,
                    "details": details,
                    "created_at": now,
                    "updated_at": now,
                }
                continue
            if record.get("status") not in protected_statuses:
                record["status"] = snapshot_status
                record["details"] = details
            record.update({
                "plan_id": request.get("plan_id"),
                "plan_hash": request.get("plan_hash"),
                "evidence_version": request.get("evidence_version"),
                "approval_id": decision.get("approval_id"),
                "approved_by": decision.get("actor_user_id"),
                "approved_by_user_id": (
                    decision.get("actor_user_id")
                    or record.get("approved_by_user_id")
                ),
                "rollback_action_id": (
                    str(rollback_action.get("action_id"))
                    if rollback_action
                    else record.get("rollback_action_id")
                ),
                "expires_at": expires_at or record.get("expires_at"),
                "updated_at": now,
            })
            if execution:
                record["execution_id"] = (
                    execution.get("execution_id")
                    or record.get("execution_id")
                )
                record["executor_user_id"] = (
                    execution.get("executed_by")
                    or record.get("executor_user_id")
                )
                record["executed_at"] = record.get("executed_at") or now

    def save_snapshot(
        self,
        snapshot: dict[str, Any],
        *,
        expected_version: int | None = None,
    ) -> int:
        organization_id = str(snapshot.get("organization_id") or "").strip()
        if not organization_id:
            raise ValueError("organization_id is required.")
        requested_version = _expected_state_version(
            snapshot,
            expected_version,
        )
        with self._lock:
            key = (organization_id, snapshot["investigation_id"])
            current = self._snapshots.get(key)
            if current is None:
                if requested_version not in (None, 0):
                    raise InvestigationStateConflictError(
                        "Investigation does not exist at the expected version."
                    )
                next_version = 1
            else:
                current_version = int(current.get("state_version") or 1)
                if (
                    requested_version is not None
                    and requested_version != current_version
                ):
                    raise InvestigationStateConflictError(
                        "Investigation snapshot is stale."
                    )
                next_version = current_version + 1
            stored = deepcopy(snapshot)
            stored["state_version"] = next_version
            self._snapshots[key] = stored
            self._sync_response_actions(stored)
            for tier in ("l1", "l2", "l3"):
                if isinstance(snapshot.get(f"{tier}_result"), dict):
                    report = build_tier_report(snapshot, tier)
                    self._tier_reports.setdefault(
                        (
                            organization_id,
                            snapshot["investigation_id"],
                            tier,
                        ),
                        report,
                    )
            return next_version

    def get_snapshot(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            value = self._snapshots.get((organization_id, investigation_id))
            return deepcopy(value) if value is not None else None

    def list_snapshots(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            values = [
                item
                for (org_id, _), item in self._snapshots.items()
                if org_id == organization_id
            ]
        if status:
            values = [item for item in values if item.get("status") == status]
        values.reverse()
        return deepcopy(values[offset:offset + limit])

    def list_worker_candidates(
        self,
        *,
        statuses: tuple[str, ...],
        limit: int,
    ) -> list[dict[str, Any]]:
        wanted = set(statuses)
        with self._lock:
            values = [
                item
                for item in self._snapshots.values()
                if item.get("status") in wanted
            ]
        values.reverse()
        values.sort(key=worker_candidate_priority)
        return deepcopy(values[:limit])

    def get_active_for_alert(
        self,
        alert_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        active = {
            "created",
            "queued",
            "running",
            "awaiting_approval",
            "waiting_approval",
            "waiting_verification",
            "approved",
        }
        with self._lock:
            matches = [
                item
                for (org_id, _), item in self._snapshots.items()
                if org_id == organization_id
                and item.get("alert_id") == alert_id
                and item.get("status") in active
            ]
        return deepcopy(matches[-1]) if matches else None

    def get_report(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        snapshot = self.get_snapshot(
            investigation_id,
            organization_id=organization_id,
        )
        if snapshot is None:
            return None
        report = snapshot.get("final_report")
        return deepcopy(report) if isinstance(report, dict) else None

    def save_tier_report(
        self,
        snapshot: dict[str, Any],
        *,
        tier: AgentTier,
    ) -> dict[str, Any]:
        organization_id = str(snapshot.get("organization_id") or "").strip()
        investigation_id = str(snapshot.get("investigation_id") or "").strip()
        if not organization_id or not investigation_id:
            raise ValueError(
                "organization_id and investigation_id are required."
            )
        report = build_tier_report(snapshot, tier)
        with self._lock:
            if (
                organization_id,
                investigation_id,
            ) not in self._snapshots:
                raise ValueError("Investigation must be persisted first.")
            self._tier_reports[
                (organization_id, investigation_id, tier)
            ] = deepcopy(report)
        return report

    def list_tier_reports(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(
                [
                    report
                    for (org_id, case_id, _), report
                    in self._tier_reports.items()
                    if org_id == organization_id
                    and case_id == investigation_id
                ]
            )

    def count_snapshots(
        self,
        *,
        organization_id: str,
        status: str | None = None,
    ) -> int:
        with self._lock:
            return sum(
                org_id == organization_id
                and (status is None or item.get("status") == status)
                for (org_id, _), item in self._snapshots.items()
            )

    def list_agent_runs(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        snapshot = self.get_snapshot(
            investigation_id,
            organization_id=organization_id,
        )
        if snapshot is None:
            return []
        specialist_runs = snapshot.get("specialist_runs")
        if isinstance(specialist_runs, list):
            return deepcopy(specialist_runs)
        explicit_runs = snapshot.get("agent_runs")
        if isinstance(explicit_runs, list):
            return deepcopy(explicit_runs)
        result: list[dict[str, Any]] = []
        for tier in ("l1", "l2", "l3"):
            tier_result = snapshot.get(f"{tier}_result")
            if not isinstance(tier_result, dict):
                continue
            result.append({
                "investigation_id": investigation_id,
                "organization_id": organization_id,
                "tier": tier,
                "role": "supervisor",
                "attempt": 1,
                "status": "completed",
                "result": deepcopy(tier_result),
            })
        return result

    def list_audit_events(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        snapshot = self.get_snapshot(
            investigation_id,
            organization_id=organization_id,
        )
        return deepcopy(snapshot.get("audit_events", [])) if snapshot else []

    def append_audit_events(
        self,
        investigation_id: str,
        *,
        organization_id: str,
        events: list[dict[str, Any]],
    ) -> None:
        with self._lock:
            snapshot = self._snapshots.get(
                (organization_id, investigation_id)
            )
            if snapshot is None:
                raise ValueError("Investigation must be persisted first.")
            existing = snapshot.setdefault("audit_events", [])
            fingerprints = {
                json.dumps(item, sort_keys=True, default=str)
                for item in existing
                if isinstance(item, dict)
            }
            for event in events:
                fingerprint = json.dumps(
                    event,
                    sort_keys=True,
                    default=str,
                )
                if fingerprint not in fingerprints:
                    existing.append(deepcopy(event))
                    fingerprints.add(fingerprint)

    def list_response_actions(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        with self._lock:
            records = [
                item
                for (org_id, _), item in self._response_actions.items()
                if org_id == organization_id
                and item.get("investigation_id") == investigation_id
            ]
        records.sort(
            key=lambda item: (
                item.get("created_at") or datetime.min.replace(tzinfo=UTC),
                item.get("action_id") or "",
            )
        )
        return deepcopy(records)

    def list_response_action_organizations(self) -> list[str]:
        with self._lock:
            return sorted(
                {organization_id for organization_id, _ in self._response_actions}
            )

    def list_approvals(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        snapshot = self.get_snapshot(
            investigation_id,
            organization_id=organization_id,
        )
        if snapshot is None:
            return []
        request = snapshot.get("approval_request")
        if not isinstance(request, dict):
            return []
        decision = snapshot.get("approval_decision")
        return [{
            **deepcopy(request),
            "organization_id": organization_id,
            "decision": (
                deepcopy(decision)
                if isinstance(decision, dict)
                else None
            ),
        }]

    def claim_response_actions(
        self,
        investigation_id: str,
        *,
        organization_id: str,
        approval_id: str,
        executor_user_id: str,
        executor_roles: list[str],
        expected_action_ids: list[str],
        expected_plan_hash: str,
        expected_evidence_version: str,
    ) -> dict[str, Any]:
        with self._lock:
            key = (organization_id, investigation_id)
            snapshot = self._snapshots.get(key)
            if snapshot is None:
                raise ResponseExecutionConflictError(
                    "Investigation is not persisted."
                )
            decision = snapshot.get("approval_decision") or {}
            if (
                decision.get("decision") != "approve"
                or decision.get("approval_id") != approval_id
                or decision.get("plan_hash") != expected_plan_hash
                or decision.get("evidence_version") != expected_evidence_version
            ):
                raise ResponseExecutionConflictError(
                    "Actions are not approved."
                )
            if key in self._claims:
                raise ResponseExecutionConflictError(
                    "Response actions were already claimed."
                )
            request = snapshot.get("approval_request") or {}
            action_ids = list(request.get("action_ids") or [])
            if action_ids != expected_action_ids or len(action_ids) != len(
                set(action_ids)
            ):
                raise ResponseExecutionConflictError(
                    "Approved action IDs do not exactly match the current plan."
                )
            execution_id = f"EXE-{uuid.uuid4().hex}"
            claim = {
                "execution_id": execution_id,
                "action_ids": action_ids,
                "actor_user_id": executor_user_id,
                "actor_roles": list(executor_roles),
            }
            self._claims[key] = claim
            claim_time = datetime.now(UTC)
            for action_id in action_ids:
                record = self._response_actions.get(
                    (organization_id, action_id)
                )
                if record is not None:
                    record.update({
                        "status": "claimed",
                        "execution_id": execution_id,
                        "executor_user_id": executor_user_id,
                        "claimed_at": claim_time,
                        "updated_at": claim_time,
                    })
            return deepcopy(claim)

    def mark_execution_failed(
        self,
        execution_id: str,
        *,
        organization_id: str,
    ) -> None:
        with self._lock:
            for key, claim in self._claims.items():
                if (
                    key[0] == organization_id
                    and claim["execution_id"] == execution_id
                ):
                    claim["status"] = "failed"
                    failed_at = datetime.now(UTC)
                    for action_id in claim.get("action_ids", []):
                        record = self._response_actions.get(
                            (organization_id, action_id)
                        )
                        if record is not None and record.get("status") in {
                            "claimed",
                            "running",
                        }:
                            record.update({
                                "status": "failed_terminal",
                                "executed_at": failed_at,
                                "updated_at": failed_at,
                            })
                    return

    def begin_response_action(
        self,
        action_id: str,
        *,
        organization_id: str,
        execution_id: str,
        before_state: dict[str, Any],
        intended_expires_at: datetime | None,
        idempotency_key: str,
    ) -> bool:
        with self._lock:
            claim = next(
                (
                    item
                    for (org_id, _), item in self._claims.items()
                    if org_id == organization_id
                    and item.get("execution_id") == execution_id
                    and action_id in item.get("action_ids", [])
                ),
                None,
            )
            if claim is None:
                raise ResponseExecutionConflictError(
                    "The action has no durable execution claim."
                )
            statuses = claim.setdefault("action_statuses", {})
            if statuses.get(action_id) in {
                "running",
                "accepted",
                "applied",
                "executed",
                "outcome_unknown",
                "no_op",
            }:
                return False
            statuses[action_id] = "running"
            record = self._response_actions.get((organization_id, action_id))
            if record is not None:
                record.update({
                    "status": "running",
                    "details": deepcopy({
                        **(record.get("details") or {}),
                        "execution_preflight": {
                            "before_state": before_state,
                            "intended_expires_at": (
                                intended_expires_at.isoformat()
                                if intended_expires_at
                                else None
                            ),
                            "idempotency_key": idempotency_key,
                        },
                    }),
                    "expires_at": intended_expires_at,
                    "updated_at": datetime.now(UTC),
                })
            return True

    def complete_response_action(
        self,
        action_id: str,
        *,
        organization_id: str,
        execution_id: str,
        status: str,
        details: dict[str, Any],
        expires_at: datetime | None = None,
    ) -> None:
        with self._lock:
            for (org_id, _), claim in self._claims.items():
                if (
                    org_id == organization_id
                    and claim.get("execution_id") == execution_id
                    and action_id in claim.get("action_ids", [])
                ):
                    claim.setdefault("action_statuses", {})[action_id] = status
                    claim.setdefault("action_details", {})[action_id] = deepcopy(
                        details
                    )
                    completed_at = datetime.now(UTC)
                    record = self._response_actions.get(
                        (organization_id, action_id)
                    )
                    if record is not None:
                        record.update({
                            "status": status,
                            "details": deepcopy({
                                **(record.get("details") or {}),
                                "execution_result": details,
                            }),
                            "expires_at": expires_at,
                            "executed_at": completed_at,
                            "updated_at": completed_at,
                        })
                    return
        raise ResponseExecutionConflictError(
            "The action has no durable execution claim."
        )

    def list_overdue_response_actions(
        self,
        *,
        organization_id: str,
        now: datetime,
        limit: int = 100,
        claim_timeout_seconds: int = 300,
        max_retries: int = 1,
    ) -> list[dict[str, Any]]:
        observed_at = _parse_datetime(now)
        stale_before = observed_at - timedelta(
            seconds=max(1, claim_timeout_seconds)
        )
        retry_limit = max(0, max_retries)
        with self._lock:
            records = [
                deepcopy(record)
                for (org_id, _), record in self._response_actions.items()
                if org_id == organization_id
                and _rollback_record_is_eligible(
                    record,
                    now=observed_at,
                    stale_before=stale_before,
                    max_retries=retry_limit,
                )
            ]
        records.sort(key=lambda item: (
            _parse_datetime(item["expires_at"]),
            str(item["action_id"]),
        ))
        return records[:max(0, limit)]

    def claim_overdue_response_actions(
        self,
        *,
        organization_id: str,
        now: datetime,
        limit: int = 100,
        claim_timeout_seconds: int = 300,
        max_retries: int = 1,
    ) -> list[dict[str, Any]]:
        observed_at = _parse_datetime(now)
        stale_before = observed_at - timedelta(
            seconds=max(1, claim_timeout_seconds)
        )
        retry_limit = max(0, max_retries)
        with self._lock:
            records = [
                record
                for (org_id, _), record in self._response_actions.items()
                if org_id == organization_id
                and _rollback_record_is_eligible(
                    record,
                    now=observed_at,
                    stale_before=stale_before,
                    max_retries=retry_limit,
                )
            ]
            records.sort(key=lambda item: (
                _parse_datetime(item["expires_at"]),
                str(item["action_id"]),
            ))
            claimed: list[dict[str, Any]] = []
            for record in records[:max(0, limit)]:
                claim_id = f"RBK-{uuid.uuid4().hex}"
                attempt = int(record.get("rollback_retry_count") or 0) + 1
                rollback = {
                    **(
                        record.get("details", {}).get("rollback", {})
                        if isinstance(record.get("details"), dict)
                        and isinstance(
                            record.get("details", {}).get("rollback"),
                            dict,
                        )
                        else {}
                    ),
                    "claim_id": claim_id,
                    "status": "running",
                    "attempt": attempt,
                    "started_at": observed_at.isoformat(),
                }
                record.update({
                    "status": "rollback_running",
                    "rollback_claim_id": claim_id,
                    "last_rollback_attempt": observed_at,
                    "updated_at": observed_at,
                    "details": deepcopy({
                        **(record.get("details") or {}),
                        "rollback": rollback,
                    }),
                })
                claimed.append(deepcopy({
                    **record,
                    "rollback_attempt": attempt,
                    "rollback_idempotency_key": (
                        _rollback_idempotency_key(record)
                    ),
                }))
            return claimed

    def complete_response_action_rollback(
        self,
        action_id: str,
        *,
        organization_id: str,
        rollback_claim_id: str,
        success: bool,
        retryable: bool,
        details: dict[str, Any],
        completed_at: datetime,
        max_retries: int = 1,
    ) -> str:
        with self._lock:
            record = self._response_actions.get(
                (organization_id, action_id)
            )
            if record is None:
                raise ResponseExecutionConflictError(
                    "The rollback action claim is unavailable."
                )
            if (
                record.get("rollback_claim_id") == rollback_claim_id
                and record.get("status") in ROLLBACK_RESULT_STATUSES
            ):
                return str(record["status"])
            if (
                record.get("status") != "rollback_running"
                or record.get("rollback_claim_id") != rollback_claim_id
            ):
                raise ResponseExecutionConflictError(
                    "The rollback action claim is stale or unavailable."
                )
            finished_at = _parse_datetime(completed_at)
            retry_count = int(record.get("rollback_retry_count") or 0)
            if success:
                status = "rolled_back"
            else:
                retry_count += 1
                status = (
                    "rollback_failed_retryable"
                    if retryable and retry_count <= max(0, max_retries)
                    else "rollback_failed_terminal"
                )
            current_details = record.get("details") or {}
            current_rollback = (
                current_details.get("rollback", {})
                if isinstance(current_details, dict)
                and isinstance(current_details.get("rollback"), dict)
                else {}
            )
            history = list(current_rollback.get("history") or [])[-9:]
            history.append({
                "claim_id": rollback_claim_id,
                "attempt": retry_count if not success else (
                    int(record.get("rollback_retry_count") or 0) + 1
                ),
                "status": status,
                "completed_at": finished_at.isoformat(),
                "details": deepcopy(details),
            })
            record.update({
                "status": status,
                "rollback_retry_count": retry_count,
                "rollback_completed_at": (
                    finished_at
                    if status in {
                        "rolled_back",
                        "rollback_failed_terminal",
                    }
                    else None
                ),
                "updated_at": finished_at,
                "details": deepcopy({
                    **current_details,
                    "rollback": {
                        **current_rollback,
                        "status": status,
                        "completed_at": finished_at.isoformat(),
                        "result": details,
                        "history": history,
                    },
                }),
            })
            return status

    def acquire_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        owner_id: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        lock_key, organization_id, resource_type, resource_id = _lease_key(
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        owner_id = owner_id.strip()
        if not owner_id:
            raise ValueError("owner_id is required.")
        acquired_at = _lease_now(now)
        expires_at = _lease_expiry(acquired_at, lease_seconds)
        key = (organization_id, resource_type, resource_id)
        with self._lock:
            current = self._resource_leases.get(key)
            if (
                current is not None
                and _parse_datetime(current["expires_at"]) > acquired_at
            ):
                raise ResourceLeaseConflictError(
                    "The resource already has an active lease."
                )
            lease = _lease_payload(
                lock_key=lock_key,
                organization_id=organization_id,
                resource_type=resource_type,
                resource_id=resource_id,
                lease_token=f"LEASE-{uuid.uuid4().hex}",
                owner_id=owner_id,
                acquired_at=acquired_at,
                expires_at=expires_at,
            )
            self._resource_leases[key] = deepcopy(lease)
            return deepcopy(lease)

    def renew_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        lease_token: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        _, organization_id, resource_type, resource_id = _lease_key(
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        renewed_at = _lease_now(now)
        expires_at = _lease_expiry(renewed_at, lease_seconds)
        key = (organization_id, resource_type, resource_id)
        with self._lock:
            current = self._resource_leases.get(key)
            if (
                current is None
                or current.get("lease_token") != lease_token
                or _parse_datetime(current["expires_at"]) <= renewed_at
            ):
                raise ResourceLeaseConflictError(
                    "The resource lease is unavailable or expired."
                )
            current["expires_at"] = expires_at
            return deepcopy(current)

    def release_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        lease_token: str,
    ) -> bool:
        _, organization_id, resource_type, resource_id = _lease_key(
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        key = (organization_id, resource_type, resource_id)
        with self._lock:
            current = self._resource_leases.get(key)
            if current is None:
                return False
            if current.get("lease_token") != lease_token:
                raise ResourceLeaseConflictError(
                    "The lease token does not own this resource."
                )
            del self._resource_leases[key]
            return True


class SQLAlchemyInvestigationRepository:
    durable = True

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    @staticmethod
    def _record_snapshot(
        record: InvestigationRecord,
    ) -> dict[str, Any]:
        snapshot = deepcopy(record.snapshot)
        snapshot["state_version"] = int(record.state_version or 1)
        return snapshot

    def save_snapshot(
        self,
        snapshot: dict[str, Any],
        *,
        expected_version: int | None = None,
    ) -> int:
        data = _json_value(snapshot)
        requested_version = _expected_state_version(
            data,
            expected_version,
        )
        investigation_id = str(data["investigation_id"])
        organization_id = str(data.get("organization_id") or "").strip()
        if not organization_id:
            raise ValueError("organization_id is required.")
        now = datetime.now(UTC)
        errors = [
            item
            for item in data.get("errors", [])
            if isinstance(item, dict)
        ]
        last_error = errors[-1] if errors else {}
        successful_stages = [
            str(item.get("stage"))
            for item in data.get("audit_events", [])
            if isinstance(item, dict)
            and str(item.get("event") or "").endswith(
                ("completed", "succeeded")
            )
        ]

        with self._session_factory.begin() as session:
            record = session.get(
                InvestigationRecord,
                investigation_id,
                with_for_update=True,
            )
            if record is None:
                if requested_version not in (None, 0):
                    raise InvestigationStateConflictError(
                        "Investigation does not exist at the expected version."
                    )
                next_version = 1
                data["state_version"] = next_version
                alert_record = session.scalar(
                    select(WazuhAlertRecord)
                    .where(
                        WazuhAlertRecord.wazuh_document_id
                        == str(data["alert_id"])
                    )
                    .order_by(WazuhAlertRecord.event_timestamp.desc())
                    .limit(1)
                )
                record = InvestigationRecord(
                    investigation_id=investigation_id,
                    organization_id=organization_id,
                    owner_user_id=data.get("owner_user_id"),
                    alert_id=str(data["alert_id"]),
                    primary_alert_id=(
                        alert_record.id if alert_record is not None else None
                    ),
                    finding_id=data.get("finding_id"),
                    agent_id=data.get("agent_id"),
                    status=str(data["status"]),
                    current_stage=str(data["current_stage"]),
                    severity=data.get("severity"),
                    confidence=data.get("confidence"),
                    initiated_by=data.get("initiated_by"),
                    initiated_by_user_id=data.get(
                        "initiated_by_user_id",
                        data.get("owner_user_id"),
                    ),
                    initiation_reason=data.get("initiation_reason"),
                    failure_code=last_error.get("code"),
                    failure_reason=(
                        last_error.get("message")
                        or last_error.get("error")
                    ),
                    last_successful_stage=(
                        successful_stages[-1] if successful_stages else None
                    ),
                    state_version=next_version,
                    snapshot=data,
                    created_at=now,
                    updated_at=now,
                )
                session.add(record)
            else:
                if record.organization_id != organization_id:
                    raise PermissionError(
                        "Investigation belongs to another organization."
                    )
                current_version = int(record.state_version or 1)
                if (
                    requested_version is not None
                    and requested_version != current_version
                ):
                    raise InvestigationStateConflictError(
                        "Investigation snapshot is stale."
                    )
                next_version = current_version + 1
                data["state_version"] = next_version
                record.owner_user_id = (
                    data.get("owner_user_id") or record.owner_user_id
                )
                record.finding_id = (
                    data.get("finding_id") or record.finding_id
                )
                record.agent_id = data.get("agent_id")
                record.status = str(data["status"])
                record.current_stage = str(data["current_stage"])
                record.severity = data.get("severity")
                record.confidence = data.get("confidence")
                record.initiated_by_user_id = (
                    data.get("initiated_by_user_id")
                    or record.initiated_by_user_id
                )
                record.failure_code = last_error.get("code")
                record.failure_reason = (
                    last_error.get("message") or last_error.get("error")
                )
                record.last_successful_stage = (
                    successful_stages[-1]
                    if successful_stages
                    else record.last_successful_stage
                )
                record.state_version = next_version
                record.snapshot = data
                record.updated_at = now
            if data["status"] in TERMINAL_STATUSES:
                record.completed_at = record.completed_at or now

            # SQLAlchemy cannot infer the insert dependency without ORM
            # relationships, so make the parent visible before child rows.
            session.flush()
            self._save_agent_runs(session, data)
            session.flush()
            self._save_tool_executions(session, data)
            self._save_evidence(session, data)
            self._save_report(session, data)
            self._save_tier_reports(session, data)
            self._save_audit_events(session, data)
            self._save_approval(session, data)
            self._save_actions(session, data)
            self._save_steps(session, data)
        return next_version

    def get_active_for_alert(
        self,
        alert_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        active = (
            "created",
            "queued",
            "running",
            "awaiting_approval",
            "waiting_approval",
            "waiting_verification",
            "approved",
        )
        statement = (
            select(InvestigationRecord)
            .where(
                InvestigationRecord.organization_id == organization_id,
                InvestigationRecord.alert_id == alert_id,
                InvestigationRecord.status.in_(active),
            )
            .order_by(InvestigationRecord.updated_at.desc())
            .limit(1)
        )
        with self._session_factory() as session:
            record = session.scalar(statement)
            return self._record_snapshot(record) if record else None

    @staticmethod
    def _save_steps(
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        investigation_id = snapshot["investigation_id"]
        existing = {
            (record.stage, record.started_at.isoformat())
            for record in session.scalars(
                select(InvestigationStepRecord).where(
                    InvestigationStepRecord.investigation_id
                    == investigation_id
                )
            ).all()
        }
        errors_by_stage = {
            str(item.get("stage") or snapshot.get("current_stage")): item
            for item in snapshot.get("errors", [])
            if isinstance(item, dict)
        }
        for event in snapshot.get("audit_events", []):
            if not isinstance(event, dict) or not event.get("timestamp"):
                continue
            stage = str(event.get("stage") or "unknown")
            started_at = _parse_datetime(event["timestamp"])
            key = (stage, started_at.isoformat())
            if key in existing:
                continue
            name = str(event.get("event") or "")
            status = (
                "failed"
                if "failed" in name
                else "completed"
                if name.endswith(("completed", "succeeded"))
                else "started"
            )
            error = errors_by_stage.get(stage, {})
            session.add(
                InvestigationStepRecord(
                    investigation_id=investigation_id,
                    stage=stage,
                    status=status,
                    input_data={},
                    output_data=_json_value(event),
                    error_code=error.get("code"),
                    error_message=(
                        error.get("message") or error.get("error")
                    ),
                    started_at=started_at,
                    completed_at=(
                        started_at if status in {"completed", "failed"} else None
                    ),
                )
            )

    def _save_agent_runs(
        self,
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        investigation_id = snapshot["investigation_id"]
        organization_id = snapshot["organization_id"]
        runs: list[dict[str, Any]] = []
        for key in ("specialist_runs", "agent_runs"):
            explicit_runs = snapshot.get(key)
            if isinstance(explicit_runs, list):
                runs.extend(
                    run
                    for run in explicit_runs
                    if isinstance(run, dict)
                )

        for tier in ("l1", "l2", "l3"):
            result = snapshot.get(f"{tier}_result")
            if not isinstance(result, dict):
                continue
            has_supervisor = any(
                run.get("tier") == tier
                and run.get("role", "supervisor") == "supervisor"
                for run in runs
            )
            if not has_supervisor:
                runs.append({
                    "run_id": _stable_id(
                        "RUN",
                        investigation_id,
                        tier,
                        "supervisor",
                        1,
                    ),
                    "tier": tier,
                    "role": "supervisor",
                    "attempt": 1,
                    "status": "completed",
                    "result": result,
                    "completed_at": _event_time(
                        snapshot,
                        stage=tier,
                        event="analysis_completed",
                    ) or datetime.now(UTC),
                })

        # Parent supervisor rows must exist before specialist rows reference
        # them through the self-referential foreign key.
        runs.sort(
            key=lambda run: (
                0 if run.get("role", "supervisor") == "supervisor" else 1,
                str(run.get("tier") or ""),
                str(run.get("role") or ""),
            )
        )

        for run in runs:
            tier = str(run.get("tier") or "").lower()
            role = str(run.get("role") or "supervisor")
            if tier not in {"l1", "l2", "l3"}:
                continue
            attempt = max(int(run.get("attempt") or 1), 1)
            run_id = str(run.get("run_id") or _stable_id(
                "RUN",
                investigation_id,
                tier,
                role,
                attempt,
            ))
            statement = select(AgentRunRecord).where(
                AgentRunRecord.run_id == run_id,
            )
            record = session.scalar(statement)
            if record is None and role == "supervisor":
                record = session.scalar(
                    select(AgentRunRecord).where(
                        AgentRunRecord.investigation_id == investigation_id,
                        AgentRunRecord.organization_id == organization_id,
                        AgentRunRecord.tier == tier,
                        AgentRunRecord.role == role,
                        AgentRunRecord.parent_run_id.is_(None),
                    ).order_by(AgentRunRecord.id).limit(1)
                )
            run_result = run.get("result")
            if not isinstance(run_result, dict):
                run_result = {
                    "input_summary": run.get("input_summary") or {},
                    "result_summary": run.get("result_summary") or {},
                }
            values = {
                "parent_run_id": run.get("parent_run_id"),
                "status": str(run.get("status") or "completed"),
                "provider": run.get("provider"),
                "model_name": run.get("model_name") or run.get("model"),
                "duration_ms": run.get("duration_ms"),
                "tool_activity": _json_value(
                    run.get("tool_activity") or []
                ),
                "error_code": run.get("error_code"),
                "error_summary": (
                    bounded_excerpt(run["error_summary"], max_length=2000)
                    if run.get("error_summary")
                    else None
                ),
                "result": _json_value(run_result),
                "started_at": (
                    _parse_datetime(run["started_at"])
                    if run.get("started_at")
                    else None
                ),
                "completed_at": (
                    _parse_datetime(run["completed_at"])
                    if run.get("completed_at")
                    else None
                ),
            }
            if record is None:
                session.add(AgentRunRecord(
                    run_id=run_id,
                    parent_run_id=values["parent_run_id"],
                    investigation_id=investigation_id,
                    organization_id=organization_id,
                    tier=tier,
                    role=role,
                    attempt=attempt,
                    **{key: value for key, value in values.items()
                       if key != "parent_run_id"},
                ))
            else:
                if record.organization_id != organization_id:
                    raise PermissionError(
                        "Agent run belongs to another organization."
                    )
                record.run_id = run_id
                record.parent_run_id = values["parent_run_id"]
                record.attempt = attempt
                for key, value in values.items():
                    if key != "parent_run_id":
                        setattr(record, key, value)

    @staticmethod
    def _save_tool_executions(
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        investigation_id = snapshot["investigation_id"]
        organization_id = snapshot["organization_id"]
        runs: list[dict[str, Any]] = []
        for key in ("specialist_runs", "agent_runs"):
            explicit_runs = snapshot.get(key)
            if isinstance(explicit_runs, list):
                runs.extend(
                    run
                    for run in explicit_runs
                    if isinstance(run, dict)
                )
        for run in runs:
            if not isinstance(run, dict):
                continue
            run_id = run.get("run_id")
            executions = run.get("tool_executions")
            if not isinstance(executions, list):
                executions = []
            if not executions and isinstance(run.get("tool_activity"), list):
                executions = [
                    {
                        "execution_id": _stable_id(
                            "TOOL",
                            run_id,
                            index,
                            activity.get("name"),
                            activity.get("arguments_hash"),
                        ),
                        "tool_name": activity.get("name"),
                        "status": activity.get("status"),
                        "input_summary": {
                            "arguments_hash": activity.get(
                                "arguments_hash"
                            ),
                        },
                        "output_summary": {
                            "status": activity.get("status"),
                        },
                        "started_at": run.get("started_at"),
                        "completed_at": run.get("completed_at"),
                    }
                    for index, activity in enumerate(run["tool_activity"])
                    if isinstance(activity, dict)
                ]
            if not run_id:
                continue
            for index, execution in enumerate(executions):
                if not isinstance(execution, dict):
                    continue
                tool_name = str(execution.get("tool_name") or "unknown")
                execution_id = str(
                    execution.get("execution_id")
                    or _stable_id(
                        "TOOL",
                        run_id,
                        index,
                        tool_name,
                        execution.get("started_at"),
                    )
                )
                record = session.get(ToolExecutionRecord, execution_id)
                values = {
                    "status": str(execution.get("status") or "completed"),
                    "attempt": max(int(execution.get("attempt") or 1), 1),
                    "input_summary": _json_value(
                        execution.get("input_summary") or {}
                    ),
                    "output_summary": _json_value(
                        execution.get("output_summary") or {}
                    ),
                    "error_code": execution.get("error_code"),
                    "duration_ms": execution.get("duration_ms"),
                    "started_at": (
                        _parse_datetime(execution["started_at"])
                        if execution.get("started_at")
                        else None
                    ),
                    "completed_at": (
                        _parse_datetime(execution["completed_at"])
                        if execution.get("completed_at")
                        else None
                    ),
                }
                if record is None:
                    session.add(ToolExecutionRecord(
                        execution_id=execution_id,
                        run_id=str(run_id),
                        investigation_id=investigation_id,
                        organization_id=organization_id,
                        tool_name=tool_name,
                        **values,
                    ))
                else:
                    if record.organization_id != organization_id:
                        raise PermissionError(
                            "Tool execution belongs to another organization."
                        )
                    for key, value in values.items():
                        setattr(record, key, value)

    @staticmethod
    def _save_evidence(
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        investigation_id = snapshot["investigation_id"]
        organization_id = snapshot["organization_id"]
        candidates: list[dict[str, Any]] = []
        if isinstance(snapshot.get("evidence_records"), list):
            candidates.extend(snapshot["evidence_records"])
        for tier in ("l1", "l2", "l3"):
            result = snapshot.get(f"{tier}_result")
            if isinstance(result, dict) and isinstance(
                result.get("evidence"),
                list,
            ):
                candidates.extend(result["evidence"])

        for item in candidates:
            if not isinstance(item, dict):
                continue
            safe_item = _json_value(item)
            source_ref = str(
                safe_item.get("source_ref")
                or safe_item.get("alert_id")
                or safe_item.get("event_id")
                or safe_item.get("_id")
                or "unknown"
            )
            source_type = str(
                safe_item.get("source_type") or "wazuh_alert"
            )
            canonical = json.dumps(safe_item, sort_keys=True, default=str)
            content_hash = str(
                safe_item.get("normalized_document_hash")
                or safe_item.get("content_hash")
                or hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            )
            evidence_id = str(
                safe_item.get("evidence_id")
                or _stable_id(
                    "EVD",
                    investigation_id,
                    content_hash,
                )
            )
            observed_value = (
                safe_item.get("observed_at")
                or safe_item.get("timestamp")
            )
            excerpt_value = (
                safe_item.get("excerpt")
                or safe_item.get("description")
                or safe_item.get("summary")
            )
            record = session.get(EvidenceRecord, evidence_id)
            if record is None:
                session.add(EvidenceRecord(
                    evidence_id=evidence_id,
                    investigation_id=investigation_id,
                    organization_id=organization_id,
                    source_type=source_type,
                    source_ref=source_ref[:512],
                    content_hash=content_hash,
                    excerpt=(
                        bounded_excerpt(excerpt_value, max_length=2000)
                        if excerpt_value is not None
                        else None
                    ),
                    evidence_metadata=safe_item,
                    observed_at=(
                        _parse_datetime(observed_value)
                        if observed_value
                        else None
                    ),
                ))

    @staticmethod
    def _save_report(
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        report = snapshot.get("final_report")
        if not isinstance(report, dict):
            return
        investigation_id = snapshot["investigation_id"]
        record = session.get(InvestigationReportRecord, investigation_id)
        generated_at = _event_time(
            snapshot,
            stage="final_report",
            event="investigation_completed",
        ) or datetime.now(UTC)
        if record is None:
            session.add(InvestigationReportRecord(
                investigation_id=investigation_id,
                organization_id=snapshot["organization_id"],
                report=report,
                generated_at=generated_at,
            ))
        else:
            record.report = report
            record.generated_at = generated_at

    @staticmethod
    def _upsert_tier_report(
        session: Session,
        snapshot: dict[str, Any],
        tier: AgentTier,
        *,
        overwrite: bool = True,
    ) -> dict[str, Any]:
        report = build_tier_report(snapshot, tier)
        report_id = str(report["report_id"])
        record = session.get(TierReportRecord, report_id)
        generated_at = _parse_datetime(report.get("generated_at"))
        if record is None:
            session.add(
                TierReportRecord(
                    report_id=report_id,
                    investigation_id=snapshot["investigation_id"],
                    organization_id=snapshot["organization_id"],
                    tier=tier,
                    report=report,
                    generated_at=generated_at,
                    updated_at=datetime.now(UTC),
                )
            )
        elif overwrite:
            record.report = report
            record.generated_at = generated_at
            record.updated_at = datetime.now(UTC)
        return deepcopy(record.report) if record is not None else report

    @classmethod
    def _save_tier_reports(
        cls,
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        for tier in ("l1", "l2", "l3"):
            if isinstance(snapshot.get(f"{tier}_result"), dict):
                cls._upsert_tier_report(
                    session,
                    snapshot,
                    tier,
                    overwrite=False,
                )

    def save_tier_report(
        self,
        snapshot: dict[str, Any],
        *,
        tier: AgentTier,
    ) -> dict[str, Any]:
        organization_id = str(snapshot.get("organization_id") or "").strip()
        investigation_id = str(snapshot.get("investigation_id") or "").strip()
        if not organization_id or not investigation_id:
            raise ValueError(
                "organization_id and investigation_id are required."
            )
        data = _json_value(snapshot)
        with self._session_factory.begin() as session:
            investigation = session.scalar(
                select(InvestigationRecord).where(
                    InvestigationRecord.investigation_id
                    == investigation_id,
                    InvestigationRecord.organization_id
                    == organization_id,
                )
            )
            if investigation is None:
                raise ValueError("Investigation must be persisted first.")
            return self._upsert_tier_report(
                session,
                data,
                tier,
                overwrite=True,
            )

    @staticmethod
    def _save_audit_events(
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        investigation_id = snapshot["investigation_id"]
        previous_hash = session.scalar(
            select(AuditEventRecord.event_hash)
            .where(
                AuditEventRecord.investigation_id == investigation_id,
                AuditEventRecord.event_hash.is_not(None),
            )
            .order_by(
                AuditEventRecord.occurred_at.desc(),
                AuditEventRecord.event_id.desc(),
            )
            .limit(1)
        )
        for event in snapshot.get("audit_events", []):
            if not isinstance(event, dict):
                continue
            event_id = _stable_id(
                "AUD",
                investigation_id,
                event.get("stage"),
                event.get("event"),
                event.get("timestamp"),
                event,
            )
            if session.get(AuditEventRecord, event_id) is not None:
                continue
            payload = _json_value(event)
            actor_id = (
                event.get("actor_id")
                or event.get("actor_user_id")
                or snapshot.get("owner_user_id")
            )
            actor_type = str(
                event.get("actor_type")
                or ("user" if actor_id else "system")
            )
            metadata = {
                key: value
                for key, value in payload.items()
                if key not in {
                    "event",
                    "stage",
                    "timestamp",
                    "investigation_id",
                    "organization_id",
                    "actor_type",
                    "actor_id",
                    "actor_user_id",
                    "request_id",
                    "trace_id",
                    "conversation_id",
                    "target_type",
                    "target_id",
                    "outcome",
                    "reason_code",
                }
            }
            hash_material = {
                "event_id": event_id,
                "investigation_id": investigation_id,
                "organization_id": snapshot["organization_id"],
                "event": str(event.get("event") or "unknown"),
                "stage": str(event.get("stage") or "unknown"),
                "occurred_at": _parse_datetime(
                    event.get("timestamp")
                ).isoformat(),
                "actor_type": actor_type,
                "actor_id": actor_id,
                "request_id": event.get("request_id"),
                "trace_id": event.get("trace_id"),
                "conversation_id": event.get("conversation_id"),
                "target_type": event.get("target_type"),
                "target_id": event.get("target_id"),
                "outcome": event.get("outcome"),
                "reason_code": event.get("reason_code"),
                "metadata": metadata,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(
                json.dumps(
                    hash_material,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
            session.add(AuditEventRecord(
                event_id=event_id,
                investigation_id=investigation_id,
                organization_id=snapshot["organization_id"],
                actor_user_id=actor_id,
                actor_type=actor_type,
                actor_id=actor_id,
                request_id=event.get("request_id"),
                trace_id=event.get("trace_id"),
                conversation_id=event.get("conversation_id"),
                target_type=event.get("target_type"),
                target_id=event.get("target_id"),
                outcome=event.get("outcome"),
                reason_code=event.get("reason_code"),
                stage=str(event.get("stage") or "unknown"),
                event=str(event.get("event") or "unknown"),
                occurred_at=_parse_datetime(event.get("timestamp")),
                metadata_json=metadata,
                previous_hash=previous_hash,
                event_hash=event_hash,
                payload=payload,
            ))
            previous_hash = event_hash

    @staticmethod
    def _save_approval(
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        request = snapshot.get("approval_request")
        if not isinstance(request, dict) or not request.get("approval_id"):
            return
        decision = snapshot.get("approval_decision")
        if not isinstance(decision, dict):
            decision = None
        approval_id = str(request["approval_id"])
        record = session.get(ApprovalRecord, approval_id)
        status = (
            str(decision.get("decision"))
            if decision
            else "waiting_approval"
        )
        decided_by = (
            (
                decision.get("actor_user_id")
                or decision.get("approved_by_user_id")
                or decision.get("approved_by")
            )
            if decision
            else None
        )
        proposed_actions = [
            item
            for item in (
                (snapshot.get("remediation_plan") or {}).get("actions", [])
            )
            if isinstance(item, dict)
        ]
        invalidated = (
            snapshot.get("error", {}).get("code") == "APPROVAL_STALE"
            if isinstance(snapshot.get("error"), dict)
            else False
        )
        invalidation_reason = (
            str(
                (snapshot.get("error") or {}).get("message")
                or "stale_or_expired"
            )[:128]
            if invalidated
            else None
        )
        values = {
            "incident_id": str(request.get("incident_id") or ""),
            "plan_id": str(request.get("plan_id") or ""),
            "plan_version": int(request.get("plan_version") or 1),
            "plan_hash": str(request.get("plan_hash") or ""),
            "evidence_version": str(request.get("evidence_version") or ""),
            "policy_version": str(request.get("policy_version") or ""),
            "action_catalogue_version": str(
                request.get("action_catalogue_version") or ""
            ),
            "required_role": str(request.get("required_role") or ""),
            "status": status,
            "proposed_actions": _json_value(proposed_actions),
            "decision": _json_value(decision) if decision else None,
            "decided_by_user_id": decided_by,
            "expires_at": (
                _parse_datetime(request["expires_at"])
                if request.get("expires_at")
                else None
            ),
            "decided_at": (
                _parse_datetime(decision.get("decided_at"))
                if decision
                else None
            ),
            "invalidated_at": datetime.now(UTC) if invalidated else None,
            "invalidation_reason": invalidation_reason,
        }
        if record is None:
            session.add(ApprovalRecord(
                approval_id=approval_id,
                investigation_id=snapshot["investigation_id"],
                organization_id=snapshot["organization_id"],
                **values,
            ))
            return
        if record.organization_id != snapshot["organization_id"]:
            raise PermissionError("Approval belongs to another organization.")
        for key, value in values.items():
            setattr(record, key, value)

    @staticmethod
    def _save_actions(
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        investigation_id = snapshot["investigation_id"]
        decision = snapshot.get("approval_decision") or {}
        request = snapshot.get("approval_request") or {}
        plan = snapshot.get("remediation_plan") or {}
        executed_by_id = {
            item.get("action_id"): item
            for item in snapshot.get("executed_actions", [])
            if isinstance(item, dict) and item.get("action_id")
        }
        executed_by_target = {
            (item.get("action_type"), item.get("target")): item
            for item in snapshot.get("executed_actions", [])
            if isinstance(item, dict)
        }
        for index, action in enumerate(snapshot.get("proposed_actions", [])):
            if not isinstance(action, dict):
                continue
            action_id = str(action.get("action_id") or _stable_id(
                "ACT",
                investigation_id,
                index,
                action.get("action_type"),
                action.get("target"),
            ))
            execution = executed_by_id.get(action_id) or executed_by_target.get(
                (action.get("action_type"), action.get("target"))
            )
            if execution:
                status = str(execution.get("status") or "executed")
            elif decision.get("decision") == "reject":
                status = "rejected"
            elif decision.get("decision") == "approve":
                status = "approved"
            else:
                status = "proposed"
            record = session.get(ResponseActionRecord, action_id)
            details = {**action, **(execution or {})}
            result = (
                execution.get("result")
                if execution and isinstance(execution.get("result"), dict)
                else {}
            )
            expires_at = (
                _parse_datetime(result["expires_at"])
                if result.get("expires_at")
                else None
            )
            rollback_action = next(
                (
                    item
                    for item in plan.get("rollback_actions", [])
                    if isinstance(item, dict)
                    and item.get("parameters", {}).get("reverts_action_id")
                    == action_id
                ),
                None,
            )
            rollback_action_id = (
                str(rollback_action.get("action_id"))
                if rollback_action
                else None
            )
            if record is None:
                session.add(ResponseActionRecord(
                    action_id=action_id,
                    investigation_id=investigation_id,
                    organization_id=snapshot["organization_id"],
                    action_type=str(action.get("action_type") or "unknown"),
                    target=str(action.get("target") or ""),
                    risk_level=action.get("risk_level"),
                    status=status,
                    plan_id=request.get("plan_id"),
                    plan_hash=request.get("plan_hash"),
                    evidence_version=request.get("evidence_version"),
                    approval_id=decision.get("approval_id"),
                    approved_by=decision.get("actor_user_id"),
                    approved_by_user_id=decision.get("actor_user_id"),
                    execution_id=(
                        execution.get("execution_id") if execution else None
                    ),
                    executor_user_id=(
                        execution.get("executed_by") if execution else None
                    ),
                    executed_at=(
                        datetime.now(UTC) if execution else None
                    ),
                    rollback_action_id=rollback_action_id,
                    expires_at=expires_at,
                    retry_count=0,
                    rollback_retry_count=0,
                    details=details,
                ))
            else:
                preserve_lifecycle = record.status in {
                    "claimed",
                    "running",
                    "accepted",
                    "applied",
                    "executed",
                    "outcome_unknown",
                    "no_op",
                    "rollback_running",
                    "rollback_failed_retryable",
                    "rollback_failed_terminal",
                    "rolled_back",
                }
                if not preserve_lifecycle and not (
                    record.status in {"claimed", "running"}
                    and status == "approved"
                ):
                    record.status = status
                record.approval_id = decision.get("approval_id")
                record.plan_id = request.get("plan_id")
                record.plan_hash = request.get("plan_hash")
                record.evidence_version = request.get("evidence_version")
                record.approved_by = decision.get("actor_user_id")
                record.approved_by_user_id = (
                    decision.get("actor_user_id")
                    or record.approved_by_user_id
                )
                record.rollback_action_id = (
                    rollback_action_id or record.rollback_action_id
                )
                if not preserve_lifecycle:
                    record.expires_at = expires_at or record.expires_at
                if execution and not preserve_lifecycle:
                    record.execution_id = execution.get(
                        "execution_id",
                        record.execution_id,
                    )
                    record.executor_user_id = execution.get(
                        "executed_by",
                        record.executor_user_id,
                    )
                    record.executed_at = record.executed_at or datetime.now(UTC)
                if not preserve_lifecycle:
                    record.details = details

    def claim_response_actions(
        self,
        investigation_id: str,
        *,
        organization_id: str,
        approval_id: str,
        executor_user_id: str,
        executor_roles: list[str],
        expected_action_ids: list[str],
        expected_plan_hash: str,
        expected_evidence_version: str,
    ) -> dict[str, Any]:
        execution_id = f"EXE-{uuid.uuid4().hex}"
        now = datetime.now(UTC)
        with self._session_factory.begin() as session:
            approval = session.get(
                ApprovalRecord,
                approval_id,
                with_for_update=True,
            )
            if (
                approval is None
                or approval.investigation_id != investigation_id
                or approval.organization_id != organization_id
                or approval.status != "approve"
                or approval.plan_hash != expected_plan_hash
                or approval.evidence_version != expected_evidence_version
                or approval.invalidated_at is not None
                or approval.expires_at is None
                or _parse_datetime(approval.expires_at) <= now
            ):
                raise ResponseExecutionConflictError(
                    "The approval is stale, expired, or does not match the plan."
                )
            queried = list(session.scalars(
                select(ResponseActionRecord)
                .where(
                    ResponseActionRecord.investigation_id == investigation_id,
                    ResponseActionRecord.organization_id == organization_id,
                    ResponseActionRecord.approval_id == approval_id,
                )
                .with_for_update()
            ).all())
            records_by_id = {record.action_id: record for record in queried}
            if (
                len(expected_action_ids) != len(set(expected_action_ids))
                or set(records_by_id) != set(expected_action_ids)
            ):
                raise ResponseExecutionConflictError(
                    "Approved action IDs do not exactly match the current plan."
                )
            records = [records_by_id[action_id] for action_id in expected_action_ids]
            if not records:
                raise ResponseExecutionConflictError(
                    "No approved response actions exist."
                )
            if any(record.status != "approved" for record in records):
                raise ResponseExecutionConflictError(
                    "Response actions are already claimed or completed."
                )
            for record in records:
                if (
                    record.plan_hash != expected_plan_hash
                    or record.evidence_version != expected_evidence_version
                ):
                    raise ResponseExecutionConflictError(
                        "A response action has stale plan or evidence binding."
                    )
                record.status = "claimed"
                record.execution_id = execution_id
                record.executor_user_id = executor_user_id
                record.claimed_at = now
            return {
                "execution_id": execution_id,
                "action_ids": [record.action_id for record in records],
                "actor_user_id": executor_user_id,
                "actor_roles": list(executor_roles),
            }

    def mark_execution_failed(
        self,
        execution_id: str,
        *,
        organization_id: str,
    ) -> None:
        with self._session_factory.begin() as session:
            records = list(session.scalars(
                select(ResponseActionRecord).where(
                    ResponseActionRecord.execution_id == execution_id,
                    ResponseActionRecord.organization_id == organization_id,
                    ResponseActionRecord.status.in_(("claimed", "running")),
                )
            ).all())
            for record in records:
                record.status = "failed_terminal"
                record.executed_at = datetime.now(UTC)

    def begin_response_action(
        self,
        action_id: str,
        *,
        organization_id: str,
        execution_id: str,
        before_state: dict[str, Any],
        intended_expires_at: datetime | None,
        idempotency_key: str,
    ) -> bool:
        with self._session_factory.begin() as session:
            record = session.get(
                ResponseActionRecord,
                action_id,
                with_for_update=True,
            )
            if (
                record is None
                or record.organization_id != organization_id
                or record.execution_id != execution_id
            ):
                raise ResponseExecutionConflictError(
                    "The action has no durable execution claim."
                )
            if record.status in {
                "running",
                "accepted",
                "applied",
                "executed",
                "outcome_unknown",
                "no_op",
                "rolled_back",
            }:
                return False
            if record.status not in {
                "claimed",
                "failed_retryable",
                "timed_out",
            }:
                raise ResponseExecutionConflictError(
                    f"Action cannot run from status {record.status!r}."
                )
            if (
                record.status in {"failed_retryable", "timed_out"}
                and record.retry_count >= settings.MAPEK_MAX_EXECUTION_RETRIES
            ):
                raise ResponseExecutionConflictError(
                    "The action retry budget is exhausted."
                )
            if record.status in {"failed_retryable", "timed_out"}:
                record.retry_count += 1
            record.status = "running"
            record.details = _json_value({
                **(record.details or {}),
                "execution_preflight": {
                    "before_state": before_state,
                    "intended_expires_at": (
                        intended_expires_at.isoformat()
                        if intended_expires_at
                        else None
                    ),
                    "idempotency_key": idempotency_key,
                },
            })
            record.expires_at = intended_expires_at
            return True

    def complete_response_action(
        self,
        action_id: str,
        *,
        organization_id: str,
        execution_id: str,
        status: str,
        details: dict[str, Any],
        expires_at: datetime | None = None,
    ) -> None:
        allowed = {
            "accepted",
            "applied",
            "executed",
            "failed_retryable",
            "failed_terminal",
            "timed_out",
            "outcome_unknown",
            "no_op",
            "cancelled",
        }
        if status not in allowed:
            raise ValueError("Unsupported durable response action status.")
        with self._session_factory.begin() as session:
            record = session.get(
                ResponseActionRecord,
                action_id,
                with_for_update=True,
            )
            if (
                record is None
                or record.organization_id != organization_id
                or record.execution_id != execution_id
                or record.status != "running"
            ):
                raise ResponseExecutionConflictError(
                    "The running response action claim is unavailable."
                )
            record.status = status
            record.details = _json_value(
                {**(record.details or {}), "execution_result": details}
            )
            record.expires_at = expires_at
            record.executed_at = datetime.now(UTC)

    def list_overdue_response_actions(
        self,
        *,
        organization_id: str,
        now: datetime,
        limit: int = 100,
        claim_timeout_seconds: int = 300,
        max_retries: int = 1,
    ) -> list[dict[str, Any]]:
        statement = _overdue_response_action_statement(
            organization_id=organization_id,
            now=_parse_datetime(now),
            claim_timeout_seconds=claim_timeout_seconds,
            max_retries=max_retries,
        ).limit(max(0, limit))
        with self._session_factory() as session:
            return [
                _response_action_payload(record)
                for record in session.scalars(statement).all()
            ]

    def claim_overdue_response_actions(
        self,
        *,
        organization_id: str,
        now: datetime,
        limit: int = 100,
        claim_timeout_seconds: int = 300,
        max_retries: int = 1,
    ) -> list[dict[str, Any]]:
        observed_at = _parse_datetime(now)
        statement = (
            _overdue_response_action_statement(
                organization_id=organization_id,
                now=observed_at,
                claim_timeout_seconds=claim_timeout_seconds,
                max_retries=max_retries,
            )
            .limit(max(0, limit))
            .with_for_update(skip_locked=True)
        )
        with self._session_factory.begin() as session:
            records = list(session.scalars(statement).all())
            claimed: list[dict[str, Any]] = []
            for record in records:
                claim_id = f"RBK-{uuid.uuid4().hex}"
                attempt = int(record.rollback_retry_count or 0) + 1
                current_details = record.details or {}
                current_rollback = (
                    current_details.get("rollback", {})
                    if isinstance(current_details, dict)
                    and isinstance(current_details.get("rollback"), dict)
                    else {}
                )
                record.status = "rollback_running"
                record.rollback_claim_id = claim_id
                record.last_rollback_attempt = observed_at
                record.details = _json_value({
                    **current_details,
                    "rollback": {
                        **current_rollback,
                        "claim_id": claim_id,
                        "status": "running",
                        "attempt": attempt,
                        "started_at": observed_at.isoformat(),
                    },
                })
                claimed.append({
                    **_response_action_payload(record),
                    "rollback_attempt": attempt,
                    "rollback_idempotency_key": _stable_id(
                        "RBK-IDEM",
                        record.organization_id,
                        record.action_id,
                        record.rollback_action_id,
                    ),
                })
            return claimed

    def complete_response_action_rollback(
        self,
        action_id: str,
        *,
        organization_id: str,
        rollback_claim_id: str,
        success: bool,
        retryable: bool,
        details: dict[str, Any],
        completed_at: datetime,
        max_retries: int = 1,
    ) -> str:
        with self._session_factory.begin() as session:
            record = session.get(
                ResponseActionRecord,
                action_id,
                with_for_update=True,
            )
            if (
                record is None
                or record.organization_id != organization_id
            ):
                raise ResponseExecutionConflictError(
                    "The rollback action claim is unavailable."
                )
            if (
                record.rollback_claim_id == rollback_claim_id
                and record.status in ROLLBACK_RESULT_STATUSES
            ):
                return record.status
            if (
                record.status != "rollback_running"
                or record.rollback_claim_id != rollback_claim_id
            ):
                raise ResponseExecutionConflictError(
                    "The rollback action claim is stale or unavailable."
                )
            finished_at = _parse_datetime(completed_at)
            retry_count = int(record.rollback_retry_count or 0)
            if success:
                status = "rolled_back"
            else:
                retry_count += 1
                status = (
                    "rollback_failed_retryable"
                    if retryable and retry_count <= max(0, max_retries)
                    else "rollback_failed_terminal"
                )
            current_details = record.details or {}
            current_rollback = (
                current_details.get("rollback", {})
                if isinstance(current_details, dict)
                and isinstance(current_details.get("rollback"), dict)
                else {}
            )
            history = list(current_rollback.get("history") or [])[-9:]
            history.append({
                "claim_id": rollback_claim_id,
                "attempt": (
                    retry_count
                    if not success
                    else int(record.rollback_retry_count or 0) + 1
                ),
                "status": status,
                "completed_at": finished_at.isoformat(),
                "details": details,
            })
            record.status = status
            record.rollback_retry_count = retry_count
            record.rollback_completed_at = (
                finished_at
                if status in {
                    "rolled_back",
                    "rollback_failed_terminal",
                }
                else None
            )
            record.details = _json_value({
                **current_details,
                "rollback": {
                    **current_rollback,
                    "status": status,
                    "completed_at": finished_at.isoformat(),
                    "result": details,
                    "history": history,
                },
            })
            return status

    def acquire_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        owner_id: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        lock_key, organization_id, resource_type, resource_id = _lease_key(
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        owner_id = owner_id.strip()
        if not owner_id:
            raise ValueError("owner_id is required.")
        acquired_at = _lease_now(now)
        expires_at = _lease_expiry(acquired_at, lease_seconds)
        lease_token = f"LEASE-{uuid.uuid4().hex}"
        try:
            with self._session_factory.begin() as session:
                record = session.get(
                    InvestigationResourceLeaseRecord,
                    lock_key,
                    with_for_update=True,
                )
                if record is None:
                    record = InvestigationResourceLeaseRecord(
                        lock_key=lock_key,
                        organization_id=organization_id,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        lease_token=lease_token,
                        owner_id=owner_id,
                        acquired_at=acquired_at,
                        expires_at=expires_at,
                        updated_at=acquired_at,
                    )
                    session.add(record)
                    session.flush()
                else:
                    if _parse_datetime(record.expires_at) > acquired_at:
                        raise ResourceLeaseConflictError(
                            "The resource already has an active lease."
                        )
                    record.lease_token = lease_token
                    record.owner_id = owner_id
                    record.acquired_at = acquired_at
                    record.expires_at = expires_at
                    record.updated_at = acquired_at
        except IntegrityError as exc:
            raise ResourceLeaseConflictError(
                "The resource already has an active lease."
            ) from exc
        return _lease_payload(
            lock_key=lock_key,
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
            lease_token=lease_token,
            owner_id=owner_id,
            acquired_at=acquired_at,
            expires_at=expires_at,
        )

    def renew_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        lease_token: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        lock_key, organization_id, resource_type, resource_id = _lease_key(
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        renewed_at = _lease_now(now)
        expires_at = _lease_expiry(renewed_at, lease_seconds)
        with self._session_factory.begin() as session:
            record = session.get(
                InvestigationResourceLeaseRecord,
                lock_key,
                with_for_update=True,
            )
            if (
                record is None
                or record.lease_token != lease_token
                or _parse_datetime(record.expires_at) <= renewed_at
            ):
                raise ResourceLeaseConflictError(
                    "The resource lease is unavailable or expired."
                )
            record.expires_at = expires_at
            record.updated_at = renewed_at
            return _lease_payload(
                lock_key=record.lock_key,
                organization_id=record.organization_id,
                resource_type=record.resource_type,
                resource_id=record.resource_id,
                lease_token=record.lease_token,
                owner_id=record.owner_id,
                acquired_at=_parse_datetime(record.acquired_at),
                expires_at=expires_at,
            )

    def release_resource_lease(
        self,
        *,
        organization_id: str,
        resource_type: str,
        resource_id: str,
        lease_token: str,
    ) -> bool:
        lock_key, _, _, _ = _lease_key(
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        with self._session_factory.begin() as session:
            record = session.get(
                InvestigationResourceLeaseRecord,
                lock_key,
                with_for_update=True,
            )
            if record is None:
                return False
            if record.lease_token != lease_token:
                raise ResourceLeaseConflictError(
                    "The lease token does not own this resource."
                )
            session.delete(record)
            return True

    def get_snapshot(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(InvestigationRecord).where(
                    InvestigationRecord.investigation_id == investigation_id,
                    InvestigationRecord.organization_id == organization_id,
                )
            )
            return self._record_snapshot(record) if record else None

    def list_snapshots(
        self,
        *,
        organization_id: str,
        limit: int,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        statement: Select = select(InvestigationRecord).where(
            InvestigationRecord.organization_id == organization_id
        )
        if status:
            statement = statement.where(InvestigationRecord.status == status)
        statement = (
            statement.order_by(InvestigationRecord.updated_at.desc())
            .offset(offset)
            .limit(limit)
        )
        with self._session_factory() as session:
            return [
                self._record_snapshot(record)
                for record in session.scalars(statement).all()
            ]

    def list_worker_candidates(
        self,
        *,
        statuses: tuple[str, ...],
        limit: int,
    ) -> list[dict[str, Any]]:
        if not statuses:
            return []
        # Ordering has to happen in SQL: sorting after LIMIT would drop a
        # critical incident that sits past the batch boundary.
        statement = (
            select(InvestigationRecord)
            .where(InvestigationRecord.status.in_(statuses))
            .order_by(
                case(
                    (InvestigationRecord.status == "waiting_verification", 0),
                    else_=1,
                ),
                case(
                    _WORKER_SEVERITY_RANK,
                    value=func.lower(InvestigationRecord.severity),
                    else_=3,
                ),
                InvestigationRecord.updated_at.asc(),
            )
            .limit(max(1, min(limit, 1000)))
        )
        with self._session_factory() as session:
            return [
                self._record_snapshot(record)
                for record in session.scalars(statement).all()
            ]

    def get_report(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(InvestigationReportRecord).where(
                    InvestigationReportRecord.investigation_id
                    == investigation_id,
                    InvestigationReportRecord.organization_id
                    == organization_id,
                )
            )
            return deepcopy(record.report) if record else None

    def list_tier_reports(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        statement = (
            select(TierReportRecord)
            .where(
                TierReportRecord.investigation_id == investigation_id,
                TierReportRecord.organization_id == organization_id,
            )
            .order_by(TierReportRecord.generated_at, TierReportRecord.tier)
        )
        with self._session_factory() as session:
            return [
                deepcopy(record.report)
                for record in session.scalars(statement).all()
            ]

    def count_snapshots(
        self,
        *,
        organization_id: str,
        status: str | None = None,
    ) -> int:
        statement = (
            select(func.count())
            .select_from(InvestigationRecord)
            .where(InvestigationRecord.organization_id == organization_id)
        )
        if status:
            statement = statement.where(InvestigationRecord.status == status)
        with self._session_factory() as session:
            return int(session.scalar(statement) or 0)

    def list_agent_runs(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        statement = (
            select(AgentRunRecord)
            .where(
                AgentRunRecord.investigation_id == investigation_id,
                AgentRunRecord.organization_id == organization_id,
            )
            .order_by(AgentRunRecord.id)
        )
        with self._session_factory() as session:
            return [
                {
                    "id": record.id,
                    "run_id": record.run_id,
                    "parent_run_id": record.parent_run_id,
                    "investigation_id": record.investigation_id,
                    "organization_id": record.organization_id,
                    "tier": record.tier,
                    "role": record.role,
                    "attempt": record.attempt,
                    "status": record.status,
                    "provider": record.provider,
                    "model_name": record.model_name,
                    "duration_ms": record.duration_ms,
                    "tool_activity": deepcopy(record.tool_activity),
                    "error_code": record.error_code,
                    "error_summary": record.error_summary,
                    "result": deepcopy(record.result),
                    "started_at": record.started_at,
                    "completed_at": record.completed_at,
                }
                for record in session.scalars(statement).all()
            ]

    def list_audit_events(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        statement = (
            select(AuditEventRecord)
            .where(
                AuditEventRecord.investigation_id == investigation_id,
                AuditEventRecord.organization_id == organization_id,
            )
            .order_by(AuditEventRecord.occurred_at, AuditEventRecord.event_id)
        )
        with self._session_factory() as session:
            return [
                {
                    "event_id": record.event_id,
                    **deepcopy(record.payload),
                }
                for record in session.scalars(statement).all()
            ]

    def append_audit_events(
        self,
        investigation_id: str,
        *,
        organization_id: str,
        events: list[dict[str, Any]],
    ) -> None:
        if not events:
            return
        with self._session_factory.begin() as session:
            investigation = session.scalar(
                select(InvestigationRecord).where(
                    InvestigationRecord.investigation_id == investigation_id,
                    InvestigationRecord.organization_id == organization_id,
                )
            )
            if investigation is None:
                raise ValueError("Investigation must be persisted first.")
            self._save_audit_events(
                session,
                {
                    "investigation_id": investigation_id,
                    "organization_id": organization_id,
                    "owner_user_id": investigation.owner_user_id,
                    "audit_events": events,
                },
            )

    def list_approvals(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        statement = (
            select(ApprovalRecord)
            .where(
                ApprovalRecord.investigation_id == investigation_id,
                ApprovalRecord.organization_id == organization_id,
            )
            .order_by(ApprovalRecord.created_at)
        )
        with self._session_factory() as session:
            return [
                {
                    "approval_id": record.approval_id,
                    "investigation_id": record.investigation_id,
                    "organization_id": record.organization_id,
                    "status": record.status,
                    "proposed_actions": deepcopy(
                        record.proposed_actions
                    ),
                    "decision": deepcopy(record.decision),
                    "decided_by_user_id": record.decided_by_user_id,
                    "created_at": record.created_at,
                    "expires_at": record.expires_at,
                    "decided_at": record.decided_at,
                }
                for record in session.scalars(statement).all()
            ]

    def list_response_actions(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> list[dict[str, Any]]:
        statement = (
            select(ResponseActionRecord)
            .where(
                ResponseActionRecord.investigation_id == investigation_id,
                ResponseActionRecord.organization_id == organization_id,
            )
            .order_by(ResponseActionRecord.created_at)
        )
        with self._session_factory() as session:
            return [
                _response_action_payload(record)
                for record in session.scalars(statement).all()
            ]

    def list_response_action_organizations(self) -> list[str]:
        statement = (
            select(ResponseActionRecord.organization_id)
            .distinct()
            .order_by(ResponseActionRecord.organization_id)
        )
        with self._session_factory() as session:
            return [str(value) for value in session.scalars(statement).all()]


@lru_cache(maxsize=1)
def get_investigation_repository() -> InvestigationRepository:
    if not database_url():
        if settings.DATABASE_REQUIRED:
            raise DatabaseNotConfiguredError(
                "DATABASE_REQUIRED is true but DATABASE_URL is empty."
            )
        return InMemoryInvestigationRepository()
    if settings.DATABASE_AUTO_CREATE:
        init_database()
    return SQLAlchemyInvestigationRepository(get_session_factory())


def close_investigation_repository() -> None:
    get_investigation_repository.cache_clear()
