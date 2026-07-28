"""Durable recovery boundary for expired temporary response actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from app.config import settings
from app.db.repositories.investigations import (
    InvestigationRepository,
    ResourceLeaseConflictError,
    ResponseExecutionConflictError,
)
from app.mape_k.registries import ACTION_REGISTRY
from app.mape_k.schemas import ActionType
from app.mape_k.utils import response_resource_namespace
from app.services.wazuh.exceptions import WazuhAPIError, WazuhTimeoutError


@dataclass(frozen=True)
class TemporaryActionRollbackTask:
    action_id: str
    investigation_id: str
    organization_id: str
    action_type: ActionType
    target: str
    rollback_action_id: str
    rollback_action_type: ActionType
    rollback_claim_id: str
    rollback_idempotency_key: str
    attempt: int

    @classmethod
    def from_record(
        cls,
        record: dict[str, Any],
    ) -> "TemporaryActionRollbackTask":
        action_type = ActionType(str(record.get("action_type") or ""))
        registration = ACTION_REGISTRY.require(action_type)
        if registration.rollback_action_type is None:
            raise ValueError("The temporary action has no registered rollback.")
        required = (
            "action_id",
            "investigation_id",
            "organization_id",
            "target",
            "rollback_action_id",
            "rollback_claim_id",
            "rollback_idempotency_key",
        )
        missing = [name for name in required if not record.get(name)]
        if missing:
            raise ValueError(
                "The rollback claim is incomplete: " + ", ".join(missing)
            )
        return cls(
            action_id=str(record["action_id"]),
            investigation_id=str(record["investigation_id"]),
            organization_id=str(record["organization_id"]),
            action_type=action_type,
            target=str(record["target"]),
            rollback_action_id=str(record["rollback_action_id"]),
            rollback_action_type=registration.rollback_action_type,
            rollback_claim_id=str(record["rollback_claim_id"]),
            rollback_idempotency_key=str(
                record["rollback_idempotency_key"]
            ),
            attempt=int(record.get("rollback_attempt") or 1),
        )


@dataclass(frozen=True)
class RollbackAttemptResult:
    success: bool
    verified: bool = False
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)


class TemporaryActionRollbackAdapter(Protocol):
    """A narrow adapter that must deduplicate and verify the rollback."""

    def rollback(
        self,
        task: TemporaryActionRollbackTask,
    ) -> RollbackAttemptResult: ...


def _real_recovery_enabled(settings_obj: Any) -> bool:
    return bool(
        str(
            getattr(settings_obj, "MAPEK_EXECUTION_MODE", "disabled")
        ).lower()
        == "enabled"
        and getattr(settings_obj, "MAPEK_REAL_EXECUTION_ENABLED", False)
        and not getattr(settings_obj, "MAPEK_DRY_RUN", True)
        and not getattr(settings_obj, "WAZUH_READ_ONLY", True)
        and getattr(settings_obj, "WAZUH_ALLOW_DANGEROUS_TOOLS", False)
    )


def recover_expired_temporary_actions(
    *,
    repository: InvestigationRepository,
    organization_id: str,
    adapter: TemporaryActionRollbackAdapter | None = None,
    settings_obj: Any = settings,
    now: datetime | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Claim and roll back expired actions for the orchestration worker."""

    if not _real_recovery_enabled(settings_obj):
        return {
            "status": "disabled",
            "reason": "real_response_execution_is_disabled",
            "claimed": 0,
            "results": [],
        }
    if not getattr(repository, "durable", False):
        return {
            "status": "disabled",
            "reason": "durable_action_repository_required",
            "claimed": 0,
            "results": [],
        }
    if adapter is None:
        return {
            "status": "disabled",
            "reason": "rollback_adapter_required",
            "claimed": 0,
            "results": [],
        }

    observed_at = now or datetime.now(UTC)
    max_retries = max(
        0,
        int(getattr(settings_obj, "MAPEK_MAX_EXECUTION_RETRIES", 1)),
    )
    lease_seconds = max(
        1,
        int(
            getattr(
                settings_obj,
                "MAPEK_EXECUTION_LOCK_TTL_SECONDS",
                300,
            )
        ),
    )
    claimed = repository.claim_overdue_response_actions(
        organization_id=organization_id,
        now=observed_at,
        limit=max(1, min(limit, 1000)),
        claim_timeout_seconds=lease_seconds,
        max_retries=max_retries,
    )
    results: list[dict[str, Any]] = []
    for record in claimed:
        lease: dict[str, Any] | None = None
        lock_namespace = response_resource_namespace(settings_obj)
        try:
            task = TemporaryActionRollbackTask.from_record(record)
            resource_type = (
                "ip"
                if task.action_type
                in {ActionType.BLOCK_IP, ActionType.UNBLOCK_IP}
                else task.action_type.value
            )
            lease = repository.acquire_resource_lease(
                organization_id=lock_namespace,
                resource_type=resource_type,
                resource_id=task.target,
                owner_id=task.rollback_claim_id,
                lease_seconds=lease_seconds,
                now=observed_at,
            )
            attempt_result = adapter.rollback(task)
            if not isinstance(attempt_result, RollbackAttemptResult):
                raise TypeError(
                    "Rollback adapters must return RollbackAttemptResult."
                )
            if attempt_result.success and not attempt_result.verified:
                attempt_result = RollbackAttemptResult(
                    success=False,
                    retryable=False,
                    details={
                        **attempt_result.details,
                        "error": "rollback_success_was_not_verified",
                    },
                )
        except (TimeoutError, WazuhTimeoutError) as exc:
            attempt_result = RollbackAttemptResult(
                success=False,
                retryable=True,
                details={"error": type(exc).__name__},
            )
        except WazuhAPIError as exc:
            attempt_result = RollbackAttemptResult(
                success=False,
                retryable=(
                    exc.status_code is None or exc.status_code >= 500
                ),
                details={
                    "error": type(exc).__name__,
                    "status_code": exc.status_code,
                },
            )
        except ResourceLeaseConflictError:
            attempt_result = RollbackAttemptResult(
                success=False,
                retryable=True,
                details={"error": "resource_lock_unavailable"},
            )
        except Exception as exc:
            attempt_result = RollbackAttemptResult(
                success=False,
                retryable=False,
                details={"error": type(exc).__name__},
            )

        try:
            durable_status = repository.complete_response_action_rollback(
                str(record["action_id"]),
                organization_id=organization_id,
                rollback_claim_id=str(record["rollback_claim_id"]),
                success=attempt_result.success,
                retryable=attempt_result.retryable,
                details=attempt_result.details,
                completed_at=datetime.now(UTC) if now is None else now,
                max_retries=max_retries,
            )
        except ResponseExecutionConflictError:
            durable_status = "claim_lost"
        finally:
            if lease is not None:
                try:
                    repository.release_resource_lease(
                        organization_id=lock_namespace,
                        resource_type=resource_type,
                        resource_id=task.target,
                        lease_token=str(lease["lease_token"]),
                    )
                except ResourceLeaseConflictError:
                    pass
        results.append({
            "action_id": record["action_id"],
            "rollback_action_id": record["rollback_action_id"],
            "rollback_claim_id": record["rollback_claim_id"],
            "status": durable_status,
        })
    return {
        "status": "completed",
        "claimed": len(claimed),
        "results": results,
    }
