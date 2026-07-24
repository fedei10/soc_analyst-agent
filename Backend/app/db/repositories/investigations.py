"""Persistence boundary for SOC investigations and immutable history."""

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from functools import lru_cache
from threading import RLock
from typing import Any, Protocol

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.db.models.investigation import (
    AgentRunRecord,
    ApprovalRecord,
    AuditEventRecord,
    EvidenceRecord,
    InvestigationRecord,
    InvestigationReportRecord,
    ResponseActionRecord,
    ToolExecutionRecord,
)
from app.db.sanitization import bounded_excerpt, sanitize_for_storage
from app.db.session import (
    DatabaseNotConfiguredError,
    database_url,
    get_session_factory,
    init_database,
)


TERMINAL_STATUSES = {"completed", "failed", "rejected"}


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

    def save_snapshot(self, snapshot: dict[str, Any]) -> None: ...

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

    def get_report(
        self,
        investigation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None: ...

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


class InMemoryInvestigationRepository:
    durable = False

    def __init__(self) -> None:
        self._snapshots: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = RLock()

    def save_snapshot(self, snapshot: dict[str, Any]) -> None:
        organization_id = str(snapshot.get("organization_id") or "").strip()
        if not organization_id:
            raise ValueError("organization_id is required.")
        with self._lock:
            key = (organization_id, snapshot["investigation_id"])
            self._snapshots[key] = deepcopy(snapshot)

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

    def list_response_actions(
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
        return deepcopy([
            *snapshot.get("proposed_actions", []),
            *snapshot.get("executed_actions", []),
        ])

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


class SQLAlchemyInvestigationRepository:
    durable = True

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save_snapshot(self, snapshot: dict[str, Any]) -> None:
        data = _json_value(snapshot)
        investigation_id = str(data["investigation_id"])
        organization_id = str(data.get("organization_id") or "").strip()
        if not organization_id:
            raise ValueError("organization_id is required.")
        now = datetime.now(UTC)

        with self._session_factory.begin() as session:
            record = session.get(InvestigationRecord, investigation_id)
            if record is None:
                record = InvestigationRecord(
                    investigation_id=investigation_id,
                    organization_id=organization_id,
                    owner_user_id=data.get("owner_user_id"),
                    alert_id=str(data["alert_id"]),
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
                record.owner_user_id = (
                    data.get("owner_user_id") or record.owner_user_id
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
            self._save_audit_events(session, data)
            self._save_approval(session, data)
            self._save_actions(session, data)

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
            content_hash = hashlib.sha256(
                canonical.encode("utf-8")
            ).hexdigest()
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
    def _save_audit_events(
        session: Session,
        snapshot: dict[str, Any],
    ) -> None:
        investigation_id = snapshot["investigation_id"]
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
            session.add(AuditEventRecord(
                event_id=event_id,
                investigation_id=investigation_id,
                organization_id=snapshot["organization_id"],
                actor_user_id=(
                    event.get("actor_user_id")
                    or snapshot.get("owner_user_id")
                ),
                stage=str(event.get("stage") or "unknown"),
                event=str(event.get("event") or "unknown"),
                occurred_at=_parse_datetime(event.get("timestamp")),
                payload=event,
            ))

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
            else "awaiting_approval"
        )
        decided_by = (
            decision.get("approved_by_user_id")
            or decision.get("approved_by")
            if decision
            else None
        )
        values = {
            "status": status,
            "proposed_actions": _json_value(
                request.get("proposed_actions") or []
            ),
            "decision": _json_value(decision) if decision else None,
            "decided_by_user_id": decided_by,
            "expires_at": (
                _parse_datetime(request["expires_at"])
                if request.get("expires_at")
                else None
            ),
            "decided_at": (
                _event_time(
                    snapshot,
                    stage="human_approval",
                    event="approval_decision_received",
                )
                if decision
                else None
            ),
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
        executed = {
            (item.get("action_type"), item.get("target")): item
            for item in snapshot.get("executed_actions", [])
            if isinstance(item, dict)
        }
        for index, action in enumerate(snapshot.get("proposed_actions", [])):
            if not isinstance(action, dict):
                continue
            key = (action.get("action_type"), action.get("target"))
            execution = executed.get(key)
            if execution:
                status = str(execution.get("status") or "executed")
            elif decision.get("decision") == "reject":
                status = "rejected"
            elif decision.get("decision") == "approve":
                status = "approved"
            else:
                status = "proposed"
            action_id = _stable_id(
                "ACT",
                investigation_id,
                index,
                action.get("action_type"),
                action.get("target"),
            )
            record = session.get(ResponseActionRecord, action_id)
            details = {**action, **(execution or {})}
            if record is None:
                session.add(ResponseActionRecord(
                    action_id=action_id,
                    investigation_id=investigation_id,
                    organization_id=snapshot["organization_id"],
                    action_type=str(action.get("action_type") or "unknown"),
                    target=str(action.get("target") or ""),
                    risk_level=action.get("risk_level"),
                    status=status,
                    approval_id=decision.get("approval_id"),
                    approved_by=decision.get("approved_by"),
                    approved_by_user_id=(
                        decision.get("approved_by_user_id")
                        or snapshot.get("owner_user_id")
                    ),
                    details=details,
                ))
            else:
                record.status = status
                record.approval_id = decision.get("approval_id")
                record.approved_by = decision.get("approved_by")
                record.approved_by_user_id = (
                    decision.get("approved_by_user_id")
                    or record.approved_by_user_id
                )
                record.details = details

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
            return deepcopy(record.snapshot) if record else None

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
                deepcopy(record.snapshot)
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
                {
                    "action_id": record.action_id,
                    "investigation_id": record.investigation_id,
                    "organization_id": record.organization_id,
                    "action_type": record.action_type,
                    "target": record.target,
                    "risk_level": record.risk_level,
                    "status": record.status,
                    "approval_id": record.approval_id,
                    "approved_by": record.approved_by,
                    "approved_by_user_id": record.approved_by_user_id,
                    "details": deepcopy(record.details),
                    "created_at": record.created_at,
                    "updated_at": record.updated_at,
                }
                for record in session.scalars(statement).all()
            ]


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
