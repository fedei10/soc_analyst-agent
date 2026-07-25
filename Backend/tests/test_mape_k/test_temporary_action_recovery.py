from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.repositories.investigations import (
    InMemoryInvestigationRepository,
    ResponseExecutionConflictError,
    SQLAlchemyInvestigationRepository,
)
from app.mape_k.temporary_actions import (
    RollbackAttemptResult,
    recover_expired_temporary_actions,
)
from app.mape_k.utils import response_resource_namespace


def _sql_repository() -> SQLAlchemyInvestigationRepository:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return SQLAlchemyInvestigationRepository(
        sessionmaker(bind=engine, expire_on_commit=False)
    )


def _snapshot(
    now: datetime,
    *,
    status: str = "accepted",
) -> dict:
    plan_hash = "a" * 64
    evidence_version = "b" * 64
    return {
        "investigation_id": "INV-EXPIRY-001",
        "incident_id": "INC-EXPIRY-001",
        "organization_id": "org-test",
        "owner_user_id": "user-1",
        "alert_id": "alert-1",
        "agent_id": "001",
        "initiated_by": "api",
        "status": "completed",
        "current_stage": "verification",
        "severity": "high",
        "confidence": 0.9,
        "proposed_actions": [{
            "action_id": "ACT-BLOCK-001",
            "action_type": "block_ip",
            "target": "192.0.2.10",
            "risk_level": "medium",
        }],
        "remediation_plan": {
            "plan_id": "PLAN-001",
            "plan_version": 1,
            "plan_hash": plan_hash,
            "actions": [{
                "action_id": "ACT-BLOCK-001",
                "action_type": "block_ip",
                "target": "192.0.2.10",
                "risk_level": "medium",
            }],
            "rollback_actions": [{
                "action_id": "ACT-UNBLOCK-001",
                "action_type": "unblock_ip",
                "target": "192.0.2.10",
                "risk_level": "medium",
                "parameters": {
                    "reverts_action_id": "ACT-BLOCK-001",
                },
            }],
        },
        "evidence_version": evidence_version,
        "approval_decision": {
            "decision": "approve",
            "approval_id": "APR-001",
            "actor_user_id": "analyst",
            "plan_hash": plan_hash,
            "evidence_version": evidence_version,
        },
        "approval_request": {
            "investigation_id": "INV-EXPIRY-001",
            "incident_id": "INC-EXPIRY-001",
            "approval_id": "APR-001",
            "plan_id": "PLAN-001",
            "plan_version": 1,
            "plan_hash": plan_hash,
            "evidence_version": evidence_version,
            "policy_version": "1.0",
            "action_catalogue_version": "1.0",
            "required_role": "soc_l2",
            "action_ids": ["ACT-BLOCK-001"],
            "requested_at": (now - timedelta(hours=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
        "executed_actions": [{
            "action_id": "ACT-BLOCK-001",
            "action_type": "block_ip",
            "target": "192.0.2.10",
            "status": status,
            "result": {
                "expires_at": (now - timedelta(minutes=1)).isoformat(),
            },
        }],
        "errors": [],
        "audit_events": [],
        "pending_nodes": [],
    }


@pytest.fixture(params=("memory", "sql"))
def action_repository(request):
    if request.param == "memory":
        return InMemoryInvestigationRepository()
    return _sql_repository()


@pytest.mark.parametrize(
    "status",
    ("accepted", "applied", "executed", "outcome_unknown"),
)
def test_overdue_temporary_action_statuses_are_claimable(
    action_repository,
    status,
):
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    action_repository.save_snapshot(_snapshot(now, status=status))

    assert action_repository.list_overdue_response_actions(
        organization_id="org-other",
        now=now,
    ) == []
    overdue = action_repository.list_overdue_response_actions(
        organization_id="org-test",
        now=now,
    )
    assert [item["action_id"] for item in overdue] == ["ACT-BLOCK-001"]

    claimed = action_repository.claim_overdue_response_actions(
        organization_id="org-test",
        now=now,
    )
    assert claimed[0]["status"] == "rollback_running"
    assert claimed[0]["rollback_action_id"] == "ACT-UNBLOCK-001"
    assert claimed[0]["rollback_attempt"] == 1
    assert action_repository.claim_overdue_response_actions(
        organization_id="org-test",
        now=now + timedelta(seconds=1),
    ) == []


def test_rollback_retry_budget_and_completion_are_idempotent(
    action_repository,
):
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    stale_snapshot = _snapshot(now)
    action_repository.save_snapshot(stale_snapshot)
    first = action_repository.claim_overdue_response_actions(
        organization_id="org-test",
        now=now,
        max_retries=1,
    )[0]

    first_status = action_repository.complete_response_action_rollback(
        first["action_id"],
        organization_id="org-test",
        rollback_claim_id=first["rollback_claim_id"],
        success=False,
        retryable=True,
        details={"error": "temporary"},
        completed_at=now,
        max_retries=1,
    )
    assert first_status == "rollback_failed_retryable"

    second = action_repository.claim_overdue_response_actions(
        organization_id="org-test",
        now=now + timedelta(seconds=1),
        max_retries=1,
    )[0]
    assert second["rollback_claim_id"] != first["rollback_claim_id"]
    assert (
        second["rollback_idempotency_key"]
        == first["rollback_idempotency_key"]
    )
    assert second["rollback_attempt"] == 2

    second_status = action_repository.complete_response_action_rollback(
        second["action_id"],
        organization_id="org-test",
        rollback_claim_id=second["rollback_claim_id"],
        success=True,
        retryable=False,
        details={"provider_status": "accepted"},
        completed_at=now + timedelta(seconds=1),
        max_retries=1,
    )
    assert second_status == "rolled_back"
    assert action_repository.complete_response_action_rollback(
        second["action_id"],
        organization_id="org-test",
        rollback_claim_id=second["rollback_claim_id"],
        success=True,
        retryable=False,
        details={"provider_status": "accepted"},
        completed_at=now + timedelta(seconds=1),
        max_retries=1,
    ) == "rolled_back"
    assert action_repository.list_overdue_response_actions(
        organization_id="org-test",
        now=now + timedelta(minutes=1),
    ) == []

    action_repository.save_snapshot(stale_snapshot)
    assert action_repository.list_response_actions(
        "INV-EXPIRY-001",
        organization_id="org-test",
    )[0]["status"] == "rolled_back"


def test_retry_exhaustion_becomes_terminal(action_repository):
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    action_repository.save_snapshot(_snapshot(now))
    first = action_repository.claim_overdue_response_actions(
        organization_id="org-test",
        now=now,
        max_retries=1,
    )[0]
    action_repository.complete_response_action_rollback(
        first["action_id"],
        organization_id="org-test",
        rollback_claim_id=first["rollback_claim_id"],
        success=False,
        retryable=True,
        details={},
        completed_at=now,
        max_retries=1,
    )
    second = action_repository.claim_overdue_response_actions(
        organization_id="org-test",
        now=now + timedelta(seconds=1),
        max_retries=1,
    )[0]

    status = action_repository.complete_response_action_rollback(
        second["action_id"],
        organization_id="org-test",
        rollback_claim_id=second["rollback_claim_id"],
        success=False,
        retryable=True,
        details={},
        completed_at=now + timedelta(seconds=1),
        max_retries=1,
    )

    assert status == "rollback_failed_terminal"
    assert action_repository.claim_overdue_response_actions(
        organization_id="org-test",
        now=now + timedelta(minutes=1),
        max_retries=1,
    ) == []


def test_stale_rollback_claim_is_recovered_after_repository_restart():
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    repository = _sql_repository()
    repository.save_snapshot(_snapshot(now))
    first = repository.claim_overdue_response_actions(
        organization_id="org-test",
        now=now,
        claim_timeout_seconds=60,
    )[0]
    restarted = SQLAlchemyInvestigationRepository(
        repository._session_factory
    )

    assert restarted.list_overdue_response_actions(
        organization_id="org-test",
        now=now + timedelta(seconds=59),
        claim_timeout_seconds=60,
    ) == []
    second = restarted.claim_overdue_response_actions(
        organization_id="org-test",
        now=now + timedelta(seconds=61),
        claim_timeout_seconds=60,
    )[0]
    assert second["rollback_claim_id"] != first["rollback_claim_id"]
    assert (
        second["rollback_idempotency_key"]
        == first["rollback_idempotency_key"]
    )

    with pytest.raises(ResponseExecutionConflictError):
        repository.complete_response_action_rollback(
            first["action_id"],
            organization_id="org-test",
            rollback_claim_id=first["rollback_claim_id"],
            success=True,
            retryable=False,
            details={},
            completed_at=now + timedelta(seconds=62),
        )


class _RecordingAdapter:
    def __init__(self) -> None:
        self.tasks = []

    def rollback(self, task):
        self.tasks.append(task)
        return RollbackAttemptResult(
            success=True,
            verified=True,
            details={"provider_status": "verified"},
        )


class _UnverifiedAdapter:
    def rollback(self, _task):
        return RollbackAttemptResult(
            success=True,
            details={"provider_status": "accepted"},
        )


def _settings(*, enabled: bool) -> SimpleNamespace:
    return SimpleNamespace(
        MAPEK_EXECUTION_MODE="enabled" if enabled else "disabled",
        MAPEK_REAL_EXECUTION_ENABLED=enabled,
        MAPEK_DRY_RUN=not enabled,
        WAZUH_READ_ONLY=not enabled,
        WAZUH_ALLOW_DANGEROUS_TOOLS=enabled,
        MAPEK_MAX_EXECUTION_RETRIES=1,
        MAPEK_EXECUTION_LOCK_TTL_SECONDS=60,
    )


def test_recovery_service_is_disabled_before_claiming():
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    repository = _sql_repository()
    repository.save_snapshot(_snapshot(now))
    adapter = _RecordingAdapter()

    result = recover_expired_temporary_actions(
        repository=repository,
        organization_id="org-test",
        adapter=adapter,
        settings_obj=_settings(enabled=False),
        now=now,
    )

    assert result["status"] == "disabled"
    assert adapter.tasks == []
    assert len(repository.list_overdue_response_actions(
        organization_id="org-test",
        now=now,
    )) == 1


def test_recovery_service_uses_typed_adapter_and_durable_completion():
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    repository = _sql_repository()
    repository.save_snapshot(_snapshot(now))
    adapter = _RecordingAdapter()

    result = recover_expired_temporary_actions(
        repository=repository,
        organization_id="org-test",
        adapter=adapter,
        settings_obj=_settings(enabled=True),
        now=now,
    )

    assert result["claimed"] == 1
    assert result["results"][0]["status"] == "rolled_back"
    assert adapter.tasks[0].rollback_action_type.value == "unblock_ip"
    assert repository.list_response_actions(
        "INV-EXPIRY-001",
        organization_id="org-test",
    )[0]["status"] == "rolled_back"


def test_provider_acknowledgement_cannot_mark_action_rolled_back():
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    repository = _sql_repository()
    repository.save_snapshot(_snapshot(now))

    result = recover_expired_temporary_actions(
        repository=repository,
        organization_id="org-test",
        adapter=_UnverifiedAdapter(),
        settings_obj=_settings(enabled=True),
        now=now,
    )

    assert result["results"][0]["status"] == "rollback_failed_terminal"
    action = repository.list_response_actions(
        "INV-EXPIRY-001",
        organization_id="org-test",
    )[0]
    assert action["status"] == "rollback_failed_terminal"
    assert (
        action["details"]["rollback"]["result"]["error"]
        == "rollback_success_was_not_verified"
    )


def test_recovery_requires_the_shared_wazuh_resource_lock():
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    repository = _sql_repository()
    repository.save_snapshot(_snapshot(now))
    settings_obj = _settings(enabled=True)
    repository.acquire_resource_lease(
        organization_id=response_resource_namespace(settings_obj),
        resource_type="ip",
        resource_id="192.0.2.10",
        owner_id="other-response",
        lease_seconds=60,
        now=now,
    )
    adapter = _RecordingAdapter()

    result = recover_expired_temporary_actions(
        repository=repository,
        organization_id="org-test",
        adapter=adapter,
        settings_obj=settings_obj,
        now=now,
    )

    assert adapter.tasks == []
    assert result["results"][0]["status"] == "rollback_failed_retryable"
    action = repository.list_response_actions(
        "INV-EXPIRY-001",
        organization_id="org-test",
    )[0]
    assert (
        action["details"]["rollback"]["result"]["error"]
        == "resource_lock_unavailable"
    )
