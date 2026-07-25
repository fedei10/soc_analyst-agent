from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.repositories.investigations import (
    InMemoryInvestigationRepository,
    InvestigationStateConflictError,
    ResourceLeaseConflictError,
    SQLAlchemyInvestigationRepository,
)


@pytest.fixture(params=("memory", "sql"))
def repository(request):
    if request.param == "memory":
        return InMemoryInvestigationRepository()

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


def investigation_snapshot() -> dict:
    return {
        "incident_id": "INC-CAS-001",
        "investigation_id": "INV-CAS-001",
        "organization_id": "org-test",
        "owner_user_id": "user-1",
        "alert_id": "alert-cas-1",
        "agent_id": "001",
        "initiated_by": "test",
        "initiation_reason": "CAS verification",
        "status": "created",
        "stage": "monitor",
        "current_stage": "monitor",
        "severity": None,
        "confidence": None,
        "normalized_alerts": [],
        "evidence": [],
        "evidence_records": [],
        "findings": [],
        "proposed_actions": [],
        "executed_actions": [],
        "audit_events": [],
        "errors": [],
        "specialist_runs": [],
        "pending_nodes": [],
        "final_report": None,
    }


def test_stale_snapshot_compare_and_swap_is_rejected(repository):
    assert repository.save_snapshot(investigation_snapshot()) == 1
    first_writer = repository.get_snapshot(
        "INV-CAS-001",
        organization_id="org-test",
    )
    stale_writer = repository.get_snapshot(
        "INV-CAS-001",
        organization_id="org-test",
    )
    assert first_writer["state_version"] == 1
    assert stale_writer["state_version"] == 1

    first_writer["status"] = "running"
    first_writer["current_stage"] = "analyze"
    assert repository.save_snapshot(
        first_writer,
        expected_version=1,
    ) == 2

    stale_writer["status"] = "failed"
    with pytest.raises(
        InvestigationStateConflictError,
        match="stale",
    ):
        repository.save_snapshot(
            stale_writer,
            expected_version=1,
        )

    persisted = repository.get_snapshot(
        "INV-CAS-001",
        organization_id="org-test",
    )
    assert persisted["state_version"] == 2
    assert persisted["status"] == "running"


def test_active_resource_lease_conflicts(repository):
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    lease = repository.acquire_resource_lease(
        organization_id="org-test",
        resource_type="incident",
        resource_id="INC-LOCK-001",
        owner_id="worker-1",
        lease_seconds=60,
        now=now,
    )
    assert lease["owner_id"] == "worker-1"

    with pytest.raises(
        ResourceLeaseConflictError,
        match="active lease",
    ):
        repository.acquire_resource_lease(
            organization_id="org-test",
            resource_type="incident",
            resource_id="INC-LOCK-001",
            owner_id="worker-2",
            lease_seconds=60,
            now=now + timedelta(seconds=30),
        )


def test_stale_resource_lease_can_be_recovered_and_released(repository):
    now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    stale = repository.acquire_resource_lease(
        organization_id="org-test",
        resource_type="agent",
        resource_id="001",
        owner_id="worker-stale",
        lease_seconds=10,
        now=now,
    )
    recovered = repository.acquire_resource_lease(
        organization_id="org-test",
        resource_type="agent",
        resource_id="001",
        owner_id="worker-recovery",
        lease_seconds=60,
        now=now + timedelta(seconds=11),
    )
    assert recovered["lease_token"] != stale["lease_token"]
    renewed = repository.renew_resource_lease(
        organization_id="org-test",
        resource_type="agent",
        resource_id="001",
        lease_token=recovered["lease_token"],
        lease_seconds=90,
        now=now + timedelta(seconds=20),
    )
    assert renewed["expires_at"] > recovered["expires_at"]

    with pytest.raises(ResourceLeaseConflictError, match="does not own"):
        repository.release_resource_lease(
            organization_id="org-test",
            resource_type="agent",
            resource_id="001",
            lease_token=stale["lease_token"],
        )

    assert repository.release_resource_lease(
        organization_id="org-test",
        resource_type="agent",
        resource_id="001",
        lease_token=renewed["lease_token"],
    )
    next_lease = repository.acquire_resource_lease(
        organization_id="org-test",
        resource_type="agent",
        resource_id="001",
        owner_id="worker-next",
        lease_seconds=60,
        now=now + timedelta(seconds=12),
    )
    assert next_lease["owner_id"] == "worker-next"
