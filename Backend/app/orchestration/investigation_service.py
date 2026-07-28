"""Reusable application service around the formal investigation graph."""

import uuid
from datetime import UTC, datetime
from enum import Enum
from functools import lru_cache
from threading import RLock
from typing import Any

from langgraph.types import Command
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.mape_k.graph import (
    create_mape_k_graph,
    investigation_config,
)
from app.mape_k.schemas import (
    TrustedApprovalSubmission,
    VerificationResumeAuthorization,
)
from app.mape_k.executor import RestrictedExecutor
from app.mape_k.utils import response_resource_namespace
from app.db.checkpointer import (
    CheckpointerHandle,
    create_investigation_checkpointer,
)
from app.db.repositories.investigations import (
    InvestigationRepository,
    ResourceLeaseConflictError,
    ResponseExecutionConflictError,
    get_investigation_repository,
)
from app.services.telegram.notifier import (
    format_approval_alert,
    format_escalation_alert,
    get_telegram_notifier,
)


class InvestigationNotFoundError(LookupError):
    pass


def _notify_investigation_transition(snapshot: dict[str, Any]) -> None:
    status = str(snapshot.get("status") or "")
    if status == "awaiting_approval" and not settings.TELEGRAM_NOTIFY_APPROVALS:
        return
    if status not in {"awaiting_approval", "escalated", "failed"}:
        return
    try:
        notifier = get_telegram_notifier()
        if not notifier.configured:
            return
        message = (
            format_approval_alert(snapshot)
            if status == "awaiting_approval"
            else format_escalation_alert(snapshot)
        )
        notifier.send(message)
    except Exception:
        pass


def _json_safe(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _worst_severity(findings: list[dict[str, Any]]) -> str | None:
    severities = [item.get("severity") for item in findings if item.get("severity")]
    if not severities:
        return None
    return max(severities, key=lambda value: _SEVERITY_RANK.get(value, -1))


class InvestigationService:
    def __init__(
        self,
        graph=None,
        *,
        repository: InvestigationRepository | None = None,
    ) -> None:
        self._checkpointer: CheckpointerHandle | None = None
        self.repository = repository or get_investigation_repository()
        if graph is None:
            self._checkpointer = create_investigation_checkpointer()
            graph = create_mape_k_graph(
                checkpointer=self._checkpointer.saver,
                executor=RestrictedExecutor(action_repository=self.repository),
            )
        self.graph = graph
        self._lock = RLock()

    @staticmethod
    def initial_state(
        investigation_id: str,
        *,
        alert_id: str,
        finding_id: str | None = None,
        agent_id: str | None = None,
        initiated_by: str | None = None,
        initiation_reason: str | None = None,
        organization_id: str = "local",
        owner_user_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "incident_id": f"INC-{investigation_id.removeprefix('INV-')}",
            "investigation_id": investigation_id,
            "status": "created",
            "stage": "monitor",
            "current_stage": "monitor",
            "alert_id": alert_id,
            "finding_id": finding_id,
            "agent_id": agent_id,
            "initiated_by": initiated_by,
            "initiation_reason": initiation_reason,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "normalized_alerts": [],
            "evidence": [],
            "evidence_records": [],
            "findings": [],
            "remediation_plan": None,
            "advisory_plan": None,
            "proposed_actions": [],
            "execution_results": [],
            "executed_actions": [],
            "audit_events": [],
            "llm_input_tokens": 0,
            "llm_output_tokens": 0,
            "estimated_input_tokens": 0,
            "estimated_output_tokens": 0,
            "actual_input_tokens": None,
            "actual_output_tokens": None,
            "cached_input_tokens": None,
            "model_calls": 0,
            "model_retries": 0,
            "model_provider": None,
            "model_name": None,
            "estimated_cost_usd": 0,
            "actual_cost_usd": None,
            "errors": [],
        }

    def start(
        self,
        *,
        alert_id: str,
        finding_id: str | None = None,
        agent_id: str | None = None,
        initiated_by: str = "api",
        initiation_reason: str | None = None,
        organization_id: str = "local",
        owner_user_id: str | None = None,
    ) -> dict[str, Any]:
        # Only claiming the alert needs mutual exclusion. Running the graph
        # does not: LangGraph isolates by thread_id and this investigation_id
        # is freshly minted, so no other caller can be inside it. Holding the
        # lock across the whole run pinned every other investigation in this
        # process behind one incident's Wazuh calls, LLM latency and
        # rate-limiter sleeps.
        with self._lock:
            existing = self.repository.get_active_for_alert(
                alert_id,
                organization_id=organization_id,
            )
            if existing is not None:
                return existing
            investigation_id = f"INV-{uuid.uuid4().hex[:12].upper()}"
            state = self.initial_state(
                investigation_id,
                alert_id=alert_id,
                finding_id=finding_id,
                agent_id=agent_id,
                initiated_by=initiated_by,
                initiation_reason=initiation_reason,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
            )
            try:
                self.repository.save_snapshot(
                    {
                        **state,
                        "pending_nodes": [],
                        "specialist_runs": [],
                        "final_report": None,
                    }
                )
            except IntegrityError:
                # Another worker claimed the same alert between our read and
                # our write; the unique constraint is the real arbiter.
                existing = self.repository.get_active_for_alert(
                    alert_id,
                    organization_id=organization_id,
                )
                if existing is not None:
                    return existing
                raise

        self.graph.invoke(
            state,
            config=investigation_config(investigation_id),
        )
        return self._sync_snapshot(investigation_id)

    def _checkpoint_view(
        self,
        investigation_id: str,
        *,
        organization_id: str | None = None,
    ) -> dict[str, Any] | None:
        snapshot = self.graph.get_state(investigation_config(investigation_id))
        if not snapshot.values:
            return None

        state = _json_safe(dict(snapshot.values))
        state_organization = str(state.get("organization_id") or "local")
        if (
            organization_id is not None
            and state_organization != organization_id
        ):
            raise InvestigationNotFoundError(investigation_id)
        plan = state.get("remediation_plan") or {}
        proposed_actions = state.get("proposed_actions") or [
            item
            for item in plan.get("actions", [])
            if isinstance(item, dict)
        ]
        execution_results = state.get("execution_results", [])
        authorization = state.get("execution_authorization") or {}
        approval_decision = state.get("approval_decision") or {}
        executed_actions = state.get("executed_actions") or [
            {
                **item,
                "execution_id": (
                    authorization.get("execution_id")
                    or item.get("execution_id")
                ),
                "executed_by": authorization.get("actor_user_id"),
                "approval_id": approval_decision.get("approval_id"),
            }
            for item in execution_results
            if isinstance(item, dict)
        ]
        result = {
            "incident_id": state["incident_id"],
            "investigation_id": state["investigation_id"],
            "alert_id": state["alert_id"],
            "finding_id": state.get("finding_id"),
            "agent_id": state.get("agent_id"),
            "initiated_by": state.get("initiated_by"),
            "initiation_reason": state.get("initiation_reason"),
            "organization_id": state_organization,
            "owner_user_id": state.get("owner_user_id"),
            "status": state["status"],
            "stage": state.get("stage"),
            "current_stage": state["current_stage"],
            "severity": _worst_severity(state.get("findings") or []),
            "confidence": (
                state.get("diagnosis", {}).get("confidence")
                if isinstance(state.get("diagnosis"), dict)
                else getattr(state.get("diagnosis"), "confidence", None)
            ),
            "normalized_alerts": state.get("normalized_alerts", []),
            "evidence": state.get("evidence", []),
            "evidence_records": state.get("evidence_records", []),
            "findings": state.get("findings", []),
            "incident_fingerprint": state.get("incident_fingerprint"),
            "evidence_version": state.get("evidence_version"),
            "diagnosis": state.get("diagnosis"),
            "remediation_plan": state.get("remediation_plan"),
            "advisory_plan": state.get("advisory_plan"),
            "policy_decision": state.get("policy_decision"),
            "proposed_actions": proposed_actions,
            "approval_request": state.get("approval_request"),
            "approval_decision": state.get("approval_decision"),
            "execution_results": execution_results,
            "executed_actions": executed_actions,
            "verification_not_before": state.get("verification_not_before"),
            "verification": state.get("verification"),
            "rollback": state.get("rollback"),
            "final_report": state.get("final_report"),
            "error": state.get("error"),
            "llm_input_tokens": state.get("llm_input_tokens", 0),
            "llm_output_tokens": state.get("llm_output_tokens", 0),
            "estimated_input_tokens": state.get(
                "estimated_input_tokens",
                0,
            ),
            "estimated_output_tokens": state.get(
                "estimated_output_tokens",
                0,
            ),
            "actual_input_tokens": state.get("actual_input_tokens"),
            "actual_output_tokens": state.get("actual_output_tokens"),
            "cached_input_tokens": state.get("cached_input_tokens"),
            "model_calls": state.get("model_calls", 0),
            "model_retries": state.get("model_retries", 0),
            "model_provider": state.get("model_provider"),
            "model_name": state.get("model_name"),
            "estimated_cost_usd": state.get("estimated_cost_usd", 0),
            "actual_cost_usd": state.get("actual_cost_usd"),
            "errors": state.get("errors", []),
            "failure_code": (
                (state.get("errors") or [{}])[-1].get("code")
                if state.get("errors")
                and isinstance((state.get("errors") or [{}])[-1], dict)
                else None
            ),
            "failure_reason": (
                (state.get("errors") or [{}])[-1].get("message")
                or (state.get("errors") or [{}])[-1].get("error")
                if state.get("errors")
                and isinstance((state.get("errors") or [{}])[-1], dict)
                else None
            ),
            "audit_events": state.get("audit_events", []),
            "specialist_runs": [],
            "pending_nodes": list(snapshot.next),
        }
        return result

    def snapshot(
        self,
        investigation_id: str,
        *,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        """Read-only public view; never writes.

        Persistence happens on workflow transitions via _sync_snapshot.
        """
        result = self._checkpoint_view(
            investigation_id,
            organization_id=organization_id,
        )
        if result is None:
            stored = self.repository.get_snapshot(
                investigation_id,
                organization_id=organization_id or "local",
            )
            if stored is None:
                raise InvestigationNotFoundError(investigation_id)
            return stored
        state_organization = str(result["organization_id"])
        persisted = self.repository.get_snapshot(
            investigation_id,
            organization_id=state_organization,
        )
        result["state_version"] = (
            int(persisted.get("state_version") or 0)
            if persisted is not None
            else 0
        )
        result["tier_reports"] = self.repository.list_tier_reports(
            investigation_id,
            organization_id=state_organization,
        )
        return result

    def _sync_snapshot(
        self,
        investigation_id: str,
        *,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        """Persist the checkpoint view after a graph transition."""
        result = self._checkpoint_view(
            investigation_id,
            organization_id=organization_id,
        )
        if result is None:
            return self.snapshot(
                investigation_id,
                organization_id=organization_id,
            )
        state_organization = str(result["organization_id"])
        with self._lock:
            persisted = self.repository.get_snapshot(
                investigation_id,
                organization_id=state_organization,
            )
            expected_version = (
                int(persisted.get("state_version") or 0)
                if persisted is not None
                else 0
            )
            result["state_version"] = self.repository.save_snapshot(
                result,
                expected_version=expected_version,
            )
            result["tier_reports"] = self.repository.list_tier_reports(
                investigation_id,
                organization_id=state_organization,
            )
        _notify_investigation_transition(result)
        return result

    def active_for_alert(
        self,
        alert_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        return self.repository.get_active_for_alert(
            alert_id,
            organization_id=organization_id,
        )

    def _resume_trusted(
        self,
        investigation_id: str,
        command_payload: dict,
        *,
        organization_id: str | None = None,
        resource_lock_held: bool = False,
    ) -> dict[str, Any]:
        stored = self.repository.get_snapshot(
            investigation_id,
            organization_id=organization_id or "local",
        )
        if stored is None:
            raise InvestigationNotFoundError(investigation_id)
        lock_namespace = response_resource_namespace(settings)
        lease: dict[str, Any] | None = None
        if not resource_lock_held:
            try:
                lease = self.repository.acquire_resource_lease(
                    organization_id=lock_namespace,
                    resource_type="incident",
                    resource_id=str(stored["incident_id"]),
                    owner_id=f"resume-{uuid.uuid4().hex}",
                    lease_seconds=int(
                        settings.MAPEK_EXECUTION_LOCK_TTL_SECONDS
                    ),
                )
            except ResourceLeaseConflictError as exc:
                raise ResponseExecutionConflictError(
                    "Another worker is updating this investigation."
                ) from exc
        try:
            with self._lock:
                self.graph.invoke(
                    Command(resume=command_payload),
                    config=investigation_config(investigation_id),
                )
                return self._sync_snapshot(
                    investigation_id,
                    organization_id=organization_id,
                )
        finally:
            if lease is not None:
                try:
                    self.repository.release_resource_lease(
                        organization_id=lock_namespace,
                        resource_type="incident",
                        resource_id=str(stored["incident_id"]),
                        lease_token=str(lease["lease_token"]),
                    )
                except ResourceLeaseConflictError:
                    pass

    def submit_approval(
        self,
        investigation_id: str,
        *,
        approval_id: str,
        decision: str,
        comment: str | None,
        actor_user_id: str,
        actor_roles: list[str] | tuple[str, ...],
        organization_id: str,
    ) -> dict[str, Any]:
        """Resume approval using identity derived from the authenticated server."""

        submission = TrustedApprovalSubmission(
            approval_id=approval_id,
            decision=decision,
            comment=comment,
            actor_user_id=actor_user_id,
            actor_roles=list(actor_roles),
        )
        return self._resume_trusted(
            investigation_id,
            submission.model_dump(mode="json", exclude_none=True),
            organization_id=organization_id,
        )

    def execute_approved(
        self,
        investigation_id: str,
        *,
        approval_id: str,
        executed_by: str,
        executor_roles: list[str] | tuple[str, ...],
        organization_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            before = self.snapshot(
                investigation_id,
                organization_id=organization_id,
            )
            if "execution_authorization" not in before["pending_nodes"]:
                raise ResponseExecutionConflictError(
                    "Investigation is not waiting for response execution."
                )
            request = before.get("approval_request") or {}
            if request.get("approval_id") != approval_id:
                raise ResponseExecutionConflictError(
                    "Approval ID does not match this investigation."
                )
            plan = before.get("remediation_plan") or {}
            decision = before.get("approval_decision") or {}
            expected_action_ids = [
                str(item.get("action_id"))
                for item in plan.get("actions", [])
                if isinstance(item, dict) and item.get("action_id")
            ]
            if (
                not expected_action_ids
                or request.get("action_ids") != expected_action_ids
                or decision.get("plan_hash") != plan.get("plan_hash")
                or decision.get("evidence_version")
                != before.get("evidence_version")
            ):
                raise ResponseExecutionConflictError(
                    "The approval is stale or no longer matches the plan."
                )
            owner_id = f"execution-{uuid.uuid4().hex}"
            incident_lease_seconds = min(
                3600,
                max(
                    int(settings.MAPEK_EXECUTION_LOCK_TTL_SECONDS),
                    max(
                        (
                            int(item.get("timeout_seconds") or 0)
                            for item in plan.get("actions", [])
                            if isinstance(item, dict)
                        ),
                        default=0,
                    )
                    + 60,
                ),
            )
            lock_namespace = response_resource_namespace(settings)
            resource_scopes = [
                (
                    "incident",
                    str(before["incident_id"]),
                    incident_lease_seconds,
                    False,
                ),
                *[
                    (
                        (
                            "ip"
                            if str(item.get("action_type"))
                            in {"block_ip", "unblock_ip"}
                            else str(item.get("action_type") or "resource")
                        ),
                        str(item.get("target") or ""),
                        min(
                            86_400,
                            max(
                                int(
                                    settings.MAPEK_EXECUTION_LOCK_TTL_SECONDS
                                ),
                                int(item.get("ttl_seconds") or 0),
                                int(item.get("timeout_seconds") or 0) + 60,
                            ),
                        ),
                        bool(item.get("ttl_seconds")),
                    )
                    for item in plan.get("actions", [])
                    if isinstance(item, dict) and item.get("target")
                ],
            ]
            acquired_leases: list[tuple[str, str, str, bool]] = []
            result: dict[str, Any] | None = None
            try:
                for resource_type, resource_id, ttl, retainable in dict.fromkeys(
                    resource_scopes
                ):
                    lease = self.repository.acquire_resource_lease(
                        organization_id=lock_namespace,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        owner_id=owner_id,
                        lease_seconds=ttl,
                    )
                    acquired_leases.append(
                        (
                            resource_type,
                            resource_id,
                            str(lease["lease_token"]),
                            retainable,
                        )
                    )
                claim = self.repository.claim_response_actions(
                    investigation_id,
                    organization_id=organization_id,
                    approval_id=approval_id,
                    executor_user_id=executed_by,
                    executor_roles=list(executor_roles),
                    expected_action_ids=expected_action_ids,
                    expected_plan_hash=str(plan.get("plan_hash") or ""),
                    expected_evidence_version=str(
                        before.get("evidence_version") or ""
                    ),
                )
                try:
                    self._resume_trusted(
                        investigation_id,
                        {
                            "approval_id": approval_id,
                            **claim,
                        },
                        organization_id=organization_id,
                        resource_lock_held=True,
                    )
                    result = self.snapshot(
                        investigation_id,
                        organization_id=organization_id,
                    )
                except Exception:
                    self.repository.mark_execution_failed(
                        claim["execution_id"],
                        organization_id=organization_id,
                    )
                    raise
                if (
                    result.get("status") == "failed"
                    or not result.get("execution_results")
                ):
                    self.repository.mark_execution_failed(
                        claim["execution_id"],
                        organization_id=organization_id,
                    )
                return result
            except ResourceLeaseConflictError as exc:
                raise ResponseExecutionConflictError(
                    "Another workflow holds the incident or target resource lock."
                ) from exc
            finally:
                retained_targets = {
                    ("ip", str(item.get("target") or ""))
                    for item in (result or {}).get("execution_results", [])
                    if isinstance(item, dict)
                    and item.get("status")
                    in {"accepted", "applied", "executed", "outcome_unknown"}
                }
                for (
                    resource_type,
                    resource_id,
                    lease_token,
                    retainable,
                ) in reversed(acquired_leases):
                    if (
                        retainable
                        and (resource_type, resource_id) in retained_targets
                    ):
                        continue
                    try:
                        self.repository.release_resource_lease(
                            organization_id=lock_namespace,
                            resource_type=resource_type,
                            resource_id=resource_id,
                            lease_token=lease_token,
                        )
                    except ResourceLeaseConflictError:
                        # An expired lease may already have been recovered.
                        pass

    def resume_verification(
        self,
        investigation_id: str,
        *,
        resumed_by: str,
        executor_roles: list[str] | tuple[str, ...],
        organization_id: str,
    ) -> dict[str, Any]:
        """Resume post-action verification using server-derived identity/time."""

        with self._lock:
            before = self.snapshot(
                investigation_id,
                organization_id=organization_id,
            )
            if "verification_wait" not in before["pending_nodes"]:
                raise ResponseExecutionConflictError(
                    "Investigation is not waiting for post-action verification."
                )
            ready_at_value = before.get("verification_not_before")
            ready_at = (
                datetime.fromisoformat(
                    str(ready_at_value).replace("Z", "+00:00")
                )
                if ready_at_value
                else None
            )
            if ready_at is None:
                raise ResponseExecutionConflictError(
                    "A successful execution timestamp is required before "
                    "verification."
                )
            if datetime.now(UTC) < ready_at:
                raise ResponseExecutionConflictError(
                    "The post-action observation window is not complete. "
                    f"Verification can resume at {ready_at.isoformat()}."
                )
            authorization = VerificationResumeAuthorization(
                investigation_id=investigation_id,
                actor_user_id=resumed_by,
                actor_roles=list(executor_roles),
            )
            return self._resume_trusted(
                investigation_id,
                authorization.model_dump(mode="json"),
                organization_id=organization_id,
            )

    def list_recent(
        self,
        *,
        limit: int = 10,
        organization_id: str = "local",
    ) -> list[dict[str, Any]]:
        return self.repository.list_snapshots(
            organization_id=organization_id,
            limit=limit,
        )

    def list_history(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
        organization_id: str = "local",
    ) -> list[dict[str, Any]]:
        return self.repository.list_snapshots(
            limit=limit,
            offset=offset,
            status=status,
            organization_id=organization_id,
        )

    def history_count(
        self,
        *,
        status: str | None = None,
        organization_id: str = "local",
    ) -> int:
        return self.repository.count_snapshots(
            status=status,
            organization_id=organization_id,
        )

    def report(
        self,
        investigation_id: str,
        *,
        organization_id: str = "local",
    ) -> dict[str, Any] | None:
        report = self.repository.get_report(
            investigation_id,
            organization_id=organization_id,
        )
        if report is not None:
            return report
        return self.snapshot(
            investigation_id,
            organization_id=organization_id,
        ).get("final_report")

    def tier_reports(
        self,
        investigation_id: str,
        *,
        organization_id: str = "local",
    ) -> list[dict[str, Any]]:
        self.snapshot(
            investigation_id,
            organization_id=organization_id,
        )
        return self.repository.list_tier_reports(
            investigation_id,
            organization_id=organization_id,
        )

    def agent_runs(
        self,
        investigation_id: str,
        *,
        organization_id: str = "local",
    ) -> list[dict[str, Any]]:
        self.snapshot(investigation_id, organization_id=organization_id)
        return self.repository.list_agent_runs(
            investigation_id,
            organization_id=organization_id,
        )

    def audit_history(
        self,
        investigation_id: str,
        *,
        organization_id: str = "local",
    ) -> list[dict[str, Any]]:
        self.snapshot(investigation_id, organization_id=organization_id)
        return self.repository.list_audit_events(
            investigation_id,
            organization_id=organization_id,
        )

    def response_actions(
        self,
        investigation_id: str,
        *,
        organization_id: str = "local",
    ) -> list[dict[str, Any]]:
        self.snapshot(investigation_id, organization_id=organization_id)
        return self.repository.list_response_actions(
            investigation_id,
            organization_id=organization_id,
        )

    def approval_history(
        self,
        investigation_id: str,
        *,
        organization_id: str = "local",
    ) -> list[dict[str, Any]]:
        self.snapshot(investigation_id, organization_id=organization_id)
        return self.repository.list_approvals(
            investigation_id,
            organization_id=organization_id,
        )

    def close(self) -> None:
        if self._checkpointer is not None:
            self._checkpointer.close()
            self._checkpointer = None


@lru_cache(maxsize=1)
def get_investigation_service() -> InvestigationService:
    return InvestigationService()


def close_investigation_service() -> None:
    if get_investigation_service.cache_info().currsize:
        get_investigation_service().close()
    get_investigation_service.cache_clear()
