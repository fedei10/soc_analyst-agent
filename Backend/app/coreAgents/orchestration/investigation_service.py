"""Reusable application service around the formal investigation graph."""

import uuid
from collections import OrderedDict
from functools import lru_cache
from threading import RLock
from typing import Any

from langgraph.types import Command

from app.coreAgents.orchestration.graph import (
    create_investigation_graph,
    investigation_config,
)


class InvestigationNotFoundError(LookupError):
    pass


class InvestigationService:
    def __init__(self, graph=None) -> None:
        self.graph = graph or create_investigation_graph()
        self._known_ids: OrderedDict[str, None] = OrderedDict()
        self._lock = RLock()

    @staticmethod
    def initial_state(
        investigation_id: str,
        *,
        alert_id: str,
        agent_id: str | None = None,
        initiated_by: str | None = None,
        initiation_reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "investigation_id": investigation_id,
            "status": "created",
            "current_stage": "created",
            "alert_id": alert_id,
            "agent_id": agent_id,
            "initiated_by": initiated_by,
            "initiation_reason": initiation_reason,
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
    ) -> dict[str, Any]:
        investigation_id = f"INV-{uuid.uuid4().hex[:12].upper()}"
        state = self.initial_state(
            investigation_id,
            alert_id=alert_id,
            agent_id=agent_id,
            initiated_by=initiated_by,
            initiation_reason=initiation_reason,
        )
        with self._lock:
            self._known_ids[investigation_id] = None
        self.graph.invoke(
            state,
            config=investigation_config(investigation_id),
        )
        return self.snapshot(investigation_id)

    def snapshot(self, investigation_id: str) -> dict[str, Any]:
        snapshot = self.graph.get_state(investigation_config(investigation_id))
        if not snapshot.values:
            raise InvestigationNotFoundError(investigation_id)

        state = dict(snapshot.values)
        return {
            "investigation_id": state["investigation_id"],
            "alert_id": state["alert_id"],
            "agent_id": state.get("agent_id"),
            "initiated_by": state.get("initiated_by"),
            "initiation_reason": state.get("initiation_reason"),
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
            "pending_nodes": list(snapshot.next),
        }

    def resume(self, investigation_id: str, decision: dict) -> dict[str, Any]:
        self.graph.invoke(
            Command(resume=decision),
            config=investigation_config(investigation_id),
        )
        return self.snapshot(investigation_id)

    def list_recent(self, *, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            ids = list(self._known_ids.keys())[-limit:]
        results = []
        for investigation_id in reversed(ids):
            try:
                results.append(self.snapshot(investigation_id))
            except InvestigationNotFoundError:
                continue
        return results


@lru_cache(maxsize=1)
def get_investigation_service() -> InvestigationService:
    return InvestigationService()
