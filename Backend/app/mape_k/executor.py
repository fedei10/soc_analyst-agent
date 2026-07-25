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
from app.services.wazuh.exceptions import WazuhAPIError, WazuhTimeoutError


class RestrictedExecutor:
    def __init__(
        self,
        *,
        responder: Any | None = None,
        cache: EphemeralRedis | None = None,
        before_state_provider: Any | None = None,
        action_repository: Any | None = None,
        settings_obj: Any = settings,
    ) -> None:
        self.responder = responder
        self.cache = cache or EphemeralRedis()
        self.before_state_provider = before_state_provider
        self.action_repository = action_repository
        self.settings = settings_obj

    def _real_execution_enabled(self) -> bool:
        return bool(
            str(
                getattr(
                    self.settings,
                    "MAPEK_EXECUTION_MODE",
                    "disabled",
                )
            ).lower()
            == "enabled"
            and self.settings.MAPEK_REAL_EXECUTION_ENABLED
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
            timeout_seconds=action.timeout_seconds,
        )

    def _collect_before_state(
        self,
        action: RemediationAction,
        state: IncidentWorkflowState,
    ) -> dict[str, Any]:
        if not self._real_execution_enabled():
            return {
                "target": action.target,
                "snapshot_status": "simulated",
            }
        if self.before_state_provider is None:
            raise RuntimeError(
                "Real execution requires an approved before-state provider."
            )
        snapshot = self.before_state_provider(action=action, state=state)
        if not isinstance(snapshot, dict):
            raise RuntimeError("The before-state provider returned no snapshot.")
        required = {
            "target",
            "action_present",
            "wazuh_agent_status",
            "management_connectivity",
        }
        missing = sorted(required - set(snapshot))
        if missing:
            raise RuntimeError(
                "The before-state snapshot is incomplete: " + ", ".join(missing)
            )
        if str(snapshot["target"]) != action.target:
            raise RuntimeError(
                "The before-state snapshot target does not match the action."
            )
        if not isinstance(snapshot["action_present"], bool):
            raise RuntimeError(
                "The before-state action_present value must be boolean."
            )
        return snapshot

    @staticmethod
    def _no_op_reason(
        action: RemediationAction,
        before_state: dict[str, Any],
    ) -> str | None:
        action_present = before_state.get("action_present")
        if action.action_type == ActionType.BLOCK_IP and action_present is True:
            return "block_already_present"
        if (
            action.action_type == ActionType.UNBLOCK_IP
            and action_present is False
        ):
            return "block_already_absent"
        return None

    def run(self, state: IncidentWorkflowState) -> list[ExecutionResult]:
        if state.remediation_plan is None:
            raise ValueError("A validated remediation plan is required.")
        if state.execution_authorization is not None:
            expected = [
                action.action_id for action in state.remediation_plan.actions
            ]
            if state.execution_authorization.action_ids != expected:
                raise ValueError(
                    "Execution authorization does not match the approved plan."
                )
        results: list[ExecutionResult] = []
        rollback_by_action = {
            str(item.parameters.get("reverts_action_id")): item.action_id
            for item in state.remediation_plan.rollback_actions
            if item.parameters.get("reverts_action_id")
        }
        for action in state.remediation_plan.actions:
            idempotency_key = stable_id(
                "IDEM",
                state.incident_id,
                action.action_id,
                state.evidence_version,
                length=40,
            )
            now = datetime.now(UTC)
            execution_id = stable_id(
                "EXE", state.incident_id, action.action_id, length=32
            )
            durable_execution_id = (
                state.execution_authorization.execution_id
                if state.execution_authorization
                else execution_id
            )
            before_state: dict[str, Any] = {}
            intended_expires_at: datetime | None = None
            no_op_reason: str | None = None
            if self._real_execution_enabled():
                if (
                    self.action_repository is None
                    or not getattr(self.action_repository, "durable", False)
                ):
                    results.append(
                        ExecutionResult(
                            execution_id=execution_id,
                            action_id=action.action_id,
                            incident_id=state.incident_id,
                            idempotency_key=idempotency_key,
                            action_type=action.action_type,
                            target=action.target,
                            status="failed_terminal",
                            result={
                                "error": "durable_execution_store_required"
                            },
                            rollback_action_id=rollback_by_action.get(
                                action.action_id
                            ),
                            started_at=now,
                            completed_at=datetime.now(UTC),
                        )
                    )
                    continue
                try:
                    before_state = self._collect_before_state(action, state)
                    no_op_reason = self._no_op_reason(action, before_state)
                    if action.ttl_seconds and no_op_reason is None:
                        intended_expires_at = now + timedelta(
                            seconds=action.ttl_seconds
                        )
                    claimed = self.action_repository.begin_response_action(
                        action.action_id,
                        organization_id=state.organization_id,
                        execution_id=durable_execution_id,
                        before_state=before_state,
                        intended_expires_at=intended_expires_at,
                        idempotency_key=idempotency_key,
                    )
                except Exception as exc:
                    results.append(
                        ExecutionResult(
                            execution_id=execution_id,
                            action_id=action.action_id,
                            incident_id=state.incident_id,
                            idempotency_key=idempotency_key,
                            action_type=action.action_type,
                            target=action.target,
                            status="failed_terminal",
                            result={"error": type(exc).__name__},
                            rollback_action_id=rollback_by_action.get(
                                action.action_id
                            ),
                            started_at=now,
                            completed_at=datetime.now(UTC),
                        )
                    )
                    continue
            else:
                advisory_claim = self.cache.claim_idempotency(
                    organization_id=state.organization_id,
                    operation_key=idempotency_key,
                    ttl_seconds=max(
                        action.ttl_seconds or 0,
                        settings.REDIS_IDEMPOTENCY_TTL_SECONDS,
                    ),
                )
                claimed = advisory_claim.claimed
            if not claimed:
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
                        rollback_action_id=rollback_by_action.get(action.action_id),
                        started_at=now,
                        completed_at=datetime.now(UTC),
                    )
                )
                continue
            try:
                if self._real_execution_enabled():
                    if no_op_reason is not None:
                        provider_result = {
                            "reason": no_op_reason,
                            "provider_called": False,
                            "desired_state_already_satisfied": True,
                        }
                        status = "no_op"
                    else:
                        provider_result = self._execute_real(action, state)
                        # Wazuh acknowledges/queues Active Response. Verification
                        # determines whether the mutation was actually applied.
                        provider_result = {
                            **provider_result,
                            "provider_called": True,
                            "verification_required": True,
                        }
                        status = "accepted"
                else:
                    before_state = self._collect_before_state(action, state)
                    provider_result = {
                        "simulated": True,
                        "real_execution_enabled": False,
                    }
                    status = "dry_run"
                if action.ttl_seconds:
                    expires_at = (
                        intended_expires_at
                        if self._real_execution_enabled()
                        else now + timedelta(seconds=action.ttl_seconds)
                    )
                    if expires_at is not None:
                        provider_result["expires_at"] = expires_at.isoformat()
                        self.cache.set_json(
                            namespace="mapek-expiring-actions",
                            organization_id=state.organization_id,
                            cache_key=action.action_id,
                            value={
                                "incident_id": state.incident_id,
                                "action_id": action.action_id,
                                "rollback_action_id": rollback_by_action.get(
                                    action.action_id
                                ),
                                "expires_at": expires_at.isoformat(),
                            },
                            ttl_seconds=action.ttl_seconds,
                        )
            except (TimeoutError, WazuhTimeoutError):
                status = "outcome_unknown"
                provider_result = {
                    "error": "executor_timeout",
                    "provider_called": True,
                    "outcome": "unknown",
                }
            except WazuhAPIError as exc:
                ambiguous = exc.status_code is None or exc.status_code >= 500
                status = (
                    "outcome_unknown" if ambiguous else "failed_terminal"
                )
                provider_result = {
                    "error": type(exc).__name__,
                    "status_code": exc.status_code,
                    "provider_called": True,
                    "outcome": "unknown" if ambiguous else "rejected",
                }
            except Exception as exc:
                status = "outcome_unknown"
                provider_result = {
                    "error": type(exc).__name__,
                    "provider_called": True,
                    "outcome": "unknown",
                }
            expires_at_value = (
                intended_expires_at
                if status in {"accepted", "applied", "executed", "outcome_unknown"}
                else None
            )
            if self._real_execution_enabled() and self.action_repository is not None:
                self.action_repository.complete_response_action(
                    action.action_id,
                    organization_id=state.organization_id,
                    execution_id=durable_execution_id,
                    status=status,
                    details=provider_result,
                    expires_at=expires_at_value,
                )
            results.append(
                ExecutionResult(
                    execution_id=execution_id,
                    action_id=action.action_id,
                    incident_id=state.incident_id,
                    idempotency_key=idempotency_key,
                    action_type=action.action_type,
                    target=action.target,
                    status=status,
                    before_state=before_state,
                    result=provider_result,
                    rollback_action_id=rollback_by_action.get(action.action_id),
                    started_at=now,
                    completed_at=datetime.now(UTC),
                )
            )
        return results

    def rollback(self, state: IncidentWorkflowState) -> list[dict[str, Any]]:
        if state.remediation_plan is None:
            return []
        results = []
        forward_results = {
            result.action_id: result for result in state.execution_results
        }
        prior_rollback = {
            str(item.get("action_id")): item
            for item in (
                state.rollback.results
                if state.rollback is not None
                else []
            )
            if isinstance(item, dict)
        }
        for action in state.remediation_plan.rollback_actions:
            forward_action_id = str(
                action.parameters.get("reverts_action_id") or ""
            )
            forward = forward_results.get(forward_action_id)
            if action.action_id in prior_rollback and prior_rollback[
                action.action_id
            ].get("status") in {"executed", "rolled_back"}:
                results.append(
                    {
                        "action_id": action.action_id,
                        "action_type": action.action_type,
                        "target": action.target,
                        "status": "duplicate",
                        "result": {"reason": "rollback_already_completed"},
                    }
                )
                continue
            if forward is None or forward.status not in {
                "accepted",
                "applied",
                "executed",
                "outcome_unknown",
            }:
                results.append(
                    {
                        "action_id": action.action_id,
                        "action_type": action.action_type,
                        "target": action.target,
                        "status": "not_required",
                        "result": {
                            "reason": "forward_action_did_not_mutate",
                            "forward_action_id": forward_action_id,
                        },
                    }
                )
                continue
            if self._real_execution_enabled():
                try:
                    before_state = self._collect_before_state(action, state)
                    no_op_reason = self._no_op_reason(action, before_state)
                    if no_op_reason is not None:
                        provider_result = {
                            "reason": no_op_reason,
                            "provider_called": False,
                            "desired_state_already_satisfied": True,
                        }
                        status = "no_op"
                    else:
                        provider_result = {
                            **self._execute_real(action, state),
                            "provider_called": True,
                            "verification_required": True,
                        }
                        status = "accepted"
                except (TimeoutError, WazuhTimeoutError):
                    provider_result = {
                        "error": "executor_timeout",
                        "provider_called": True,
                        "outcome": "unknown",
                    }
                    status = "outcome_unknown"
                except WazuhAPIError as exc:
                    ambiguous = (
                        exc.status_code is None or exc.status_code >= 500
                    )
                    provider_result = {
                        "error": type(exc).__name__,
                        "status_code": exc.status_code,
                        "provider_called": True,
                        "outcome": "unknown" if ambiguous else "rejected",
                    }
                    status = (
                        "outcome_unknown" if ambiguous else "failed_terminal"
                    )
                except Exception as exc:
                    provider_result = {
                        "error": type(exc).__name__,
                        "provider_called": True,
                        "outcome": "unknown",
                    }
                    status = "outcome_unknown"
            else:
                provider_result = {"simulated": True, "mutation_applied": False}
                status = "not_required"
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
