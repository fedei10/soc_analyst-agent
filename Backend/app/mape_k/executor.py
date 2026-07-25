"""Restricted response execution. No model-facing command surface exists here."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import settings
from app.mape_k.schemas import (
    ActionType,
    ExecutionResult,
    IncidentWorkflowState,
    RemediationAction,
)
from app.mape_k.utils import stable_id
from app.services.redis.ephemeral import EphemeralRedis


class RestrictedExecutor:
    def __init__(
        self,
        *,
        responder: Any | None = None,
        cache: EphemeralRedis | None = None,
        settings_obj: Any = settings,
    ) -> None:
        self.responder = responder
        self.cache = cache or EphemeralRedis()
        self.settings = settings_obj

    def _real_execution_enabled(self) -> bool:
        return bool(
            self.settings.MAPEK_REAL_EXECUTION_ENABLED
            and not self.settings.MAPEK_DRY_RUN
            and not self.settings.WAZUH_READ_ONLY
            and self.settings.WAZUH_ALLOW_DANGEROUS_TOOLS
        )

    def _execute_real(
        self,
        action: RemediationAction,
        state: IncidentWorkflowState,
    ) -> dict[str, Any]:
        if action.action_type not in {ActionType.BLOCK_IP, ActionType.UNBLOCK_IP}:
            raise ValueError("No restricted adapter is registered for this action.")
        if self.responder is None:
            from app.services.wazuh.dependencies import get_wazuh_responder

            self.responder = get_wazuh_responder()
        if not state.agent_id or not str(state.agent_id).isdigit():
            raise ValueError("A numeric Wazuh agent ID is required.")
        command = (
            "firewall-drop"
            if action.action_type == ActionType.BLOCK_IP
            else "firewall-drop-delete"
        )
        return self.responder.run_active_response(
            agent_id=str(state.agent_id),
            command=command,
            arguments=[action.target],
        )

    def run(self, state: IncidentWorkflowState) -> list[ExecutionResult]:
        if state.remediation_plan is None:
            raise ValueError("A validated remediation plan is required.")
        results: list[ExecutionResult] = []
        rollback_by_target = {
            item.target: item.action_id
            for item in state.remediation_plan.rollback_actions
        }
        for action in state.remediation_plan.actions:
            idempotency_key = stable_id(
                "IDEM",
                state.incident_id,
                action.action_id,
                state.evidence_version,
                length=40,
            )
            claim = self.cache.claim_idempotency(
                organization_id=state.organization_id,
                operation_key=idempotency_key,
                ttl_seconds=max(
                    action.ttl_seconds or 0,
                    settings.REDIS_IDEMPOTENCY_TTL_SECONDS,
                ),
            )
            now = datetime.now(UTC)
            execution_id = stable_id(
                "EXE", state.incident_id, action.action_id, length=32
            )
            if not claim.claimed:
                results.append(
                    ExecutionResult(
                        execution_id=execution_id,
                        action_id=action.action_id,
                        incident_id=state.incident_id,
                        idempotency_key=idempotency_key,
                        action_type=action.action_type,
                        target=action.target,
                        status="duplicate",
                        result={"reason": "idempotency_key_already_claimed"},
                        rollback_action_id=rollback_by_target.get(action.target),
                        started_at=now,
                        completed_at=datetime.now(UTC),
                    )
                )
                continue
            try:
                if self._real_execution_enabled():
                    provider_result = self._execute_real(action, state)
                    status = "executed"
                else:
                    provider_result = {
                        "simulated": True,
                        "real_execution_enabled": False,
                    }
                    status = "dry_run"
                if action.ttl_seconds:
                    expires_at = now + timedelta(seconds=action.ttl_seconds)
                    provider_result["expires_at"] = expires_at.isoformat()
                    self.cache.set_json(
                        namespace="mapek-expiring-actions",
                        organization_id=state.organization_id,
                        cache_key=action.action_id,
                        value={
                            "incident_id": state.incident_id,
                            "action_id": action.action_id,
                            "rollback_action_id": rollback_by_target.get(action.target),
                            "expires_at": expires_at.isoformat(),
                        },
                        ttl_seconds=action.ttl_seconds,
                    )
            except TimeoutError:
                status = "timed_out"
                provider_result = {"error": "executor_timeout"}
            except Exception as exc:
                status = "failed"
                provider_result = {"error": type(exc).__name__}
            results.append(
                ExecutionResult(
                    execution_id=execution_id,
                    action_id=action.action_id,
                    incident_id=state.incident_id,
                    idempotency_key=idempotency_key,
                    action_type=action.action_type,
                    target=action.target,
                    status=status,
                    before_state={
                        "target": action.target,
                        "action_absent": True,
                    },
                    result=provider_result,
                    rollback_action_id=rollback_by_target.get(action.target),
                    started_at=now,
                    completed_at=datetime.now(UTC),
                )
            )
        return results

    def rollback(self, state: IncidentWorkflowState) -> list[dict[str, Any]]:
        if state.remediation_plan is None:
            return []
        results = []
        for action in state.remediation_plan.rollback_actions:
            if self._real_execution_enabled():
                try:
                    provider_result = self._execute_real(action, state)
                    status = "executed"
                except Exception as exc:
                    provider_result = {"error": type(exc).__name__}
                    status = "failed"
            else:
                provider_result = {"simulated": True}
                status = "dry_run"
            results.append(
                {
                    "action_id": action.action_id,
                    "action_type": action.action_type,
                    "target": action.target,
                    "status": status,
                    "result": provider_result,
                }
            )
        return results

