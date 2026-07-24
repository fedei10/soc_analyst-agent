"""Reusable application service around the formal investigation graph."""

import uuid
from functools import lru_cache
from threading import RLock
from typing import Any

from langgraph.types import Command

from app.coreAgents.orchestration.graph import (
    create_investigation_graph,
    investigation_config,
)
from app.db.checkpointer import (
    CheckpointerHandle,
    create_investigation_checkpointer,
)
from app.db.repositories.investigations import (
    InvestigationRepository,
    ResponseExecutionConflictError,
    get_investigation_repository,
)


class InvestigationNotFoundError(LookupError):
    pass


class InvestigationService:
    def __init__(
        self,
        graph=None,
        *,
        repository: InvestigationRepository | None = None,
    ) -> None:
        self._checkpointer: CheckpointerHandle | None = None
        if graph is None:
            self._checkpointer = create_investigation_checkpointer()
            graph = create_investigation_graph(
                checkpointer=self._checkpointer.saver
            )
        self.graph = graph
        self.repository = repository or get_investigation_repository()
        self._lock = RLock()

    @staticmethod
    def initial_state(
        investigation_id: str,
        *,
        alert_id: str,
        agent_id: str | None = None,
        initiated_by: str | None = None,
        initiation_reason: str | None = None,
        organization_id: str = "local",
        owner_user_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "investigation_id": investigation_id,
            "status": "created",
            "current_stage": "created",
            "alert_id": alert_id,
            "agent_id": agent_id,
            "initiated_by": initiated_by,
            "initiation_reason": initiation_reason,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "evidence": [],
            "timeline": [],
            "affected_assets": [],
            "proposed_actions": [],
            "executed_actions": [],
            "audit_events": [],
            "errors": [],
        }

    def start(
        self,
        *,
        alert_id: str,
        agent_id: str | None = None,
        initiated_by: str = "api",
        initiation_reason: str | None = None,
        organization_id: str = "local",
        owner_user_id: str | None = None,
    ) -> dict[str, Any]:
        investigation_id = f"INV-{uuid.uuid4().hex[:12].upper()}"
        state = self.initial_state(
            investigation_id,
            alert_id=alert_id,
            agent_id=agent_id,
            initiated_by=initiated_by,
            initiation_reason=initiation_reason,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
        )
        self.graph.invoke(
            state,
            config=investigation_config(investigation_id),
        )
        return self.snapshot(investigation_id)

    def snapshot(
        self,
        investigation_id: str,
        *,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        snapshot = self.graph.get_state(investigation_config(investigation_id))
        if not snapshot.values:
            stored = self.repository.get_snapshot(
                investigation_id,
                organization_id=organization_id or "local",
            )
            if stored is None:
                raise InvestigationNotFoundError(investigation_id)
            return stored

        state = dict(snapshot.values)
        state_organization = str(state.get("organization_id") or "local")
        if (
            organization_id is not None
            and state_organization != organization_id
        ):
            raise InvestigationNotFoundError(investigation_id)
        result = {
            "investigation_id": state["investigation_id"],
            "alert_id": state["alert_id"],
            "agent_id": state.get("agent_id"),
            "initiated_by": state.get("initiated_by"),
            "initiation_reason": state.get("initiation_reason"),
            "organization_id": state_organization,
            "owner_user_id": state.get("owner_user_id"),
            "status": state["status"],
            "current_stage": state["current_stage"],
            "severity": state.get("severity"),
            "confidence": state.get("confidence"),
            "l1_result": state.get("l1_result"),
            "l2_result": state.get("l2_result"),
            "l3_result": state.get("l3_result"),
            "proposed_actions": state.get("proposed_actions", []),
            "approval_request": state.get("approval_request"),
            "approval_decision": state.get("approval_decision"),
            "executed_actions": state.get("executed_actions", []),
            "final_report": state.get("final_report"),
            "errors": state.get("errors", []),
            "audit_events": state.get("audit_events", []),
            "specialist_runs": state.get("specialist_runs", []),
            "pending_nodes": list(snapshot.next),
        }
        with self._lock:
            self.repository.save_snapshot(result)
        return result

    def resume(
        self,
        investigation_id: str,
        decision: dict,
        *,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self.snapshot(
                investigation_id,
                organization_id=organization_id,
            )
            self.graph.invoke(
                Command(resume=decision),
                config=investigation_config(investigation_id),
            )
            return self.snapshot(
                investigation_id,
                organization_id=organization_id,
            )

    def execute_approved(
        self,
        investigation_id: str,
        *,
        approval_id: str,
        executed_by: str,
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
            claim = self.repository.claim_response_actions(
                investigation_id,
                organization_id=organization_id,
                approval_id=approval_id,
                executed_by=executed_by,
            )
            try:
                self.graph.invoke(
                    Command(resume={
                        "approval_id": approval_id,
                        **claim,
                    }),
                    config=investigation_config(investigation_id),
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
            if result.get("status") == "failed":
                self.repository.mark_execution_failed(
                    claim["execution_id"],
                    organization_id=organization_id,
                )
            return result

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
