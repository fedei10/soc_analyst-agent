from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.repositories.investigations import (
    ResponseExecutionConflictError,
    SQLAlchemyInvestigationRepository,
)
from app.db.models.investigation import AuditEventRecord
import pytest


def repository():
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


def snapshot():
    timestamp = datetime(2026, 7, 23, 10, 0, tzinfo=UTC).isoformat()
    requested_at = datetime.now(UTC)
    expires_at = (requested_at + timedelta(hours=1)).isoformat()
    plan_hash = "a" * 64
    evidence_version = "b" * 64
    return {
        "investigation_id": "INV-PERSIST-001",
        "incident_id": "INC-PERSIST-001",
        "organization_id": "org-test",
        "owner_user_id": "user-1",
        "alert_id": "alert-1",
        "agent_id": "001",
        "initiated_by": "api",
        "initiation_reason": "High severity",
        "status": "completed",
        "current_stage": "final_report",
        "severity": "high",
        "confidence": 0.9,
        "l1_result": {"summary": "L1", "severity": "high"},
        "l2_result": {"summary": "L2", "severity": "high"},
        "l3_result": {"summary": "L3"},
        "proposed_actions": [
            {
                "action_id": "ACT-001",
                "action_type": "block_ip",
                "target": "192.0.2.10",
                "risk_level": "medium",
            }
        ],
        "remediation_plan": {
            "plan_id": "PLAN-001",
            "plan_version": 1,
            "plan_hash": plan_hash,
            "actions": [
                {
                    "action_id": "ACT-001",
                    "action_type": "block_ip",
                    "target": "192.0.2.10",
                    "risk_level": "medium",
                }
            ],
            "rollback_actions": [],
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
            "investigation_id": "INV-PERSIST-001",
            "incident_id": "INC-PERSIST-001",
            "approval_id": "APR-001",
            "plan_id": "PLAN-001",
            "plan_version": 1,
            "plan_hash": plan_hash,
            "evidence_version": evidence_version,
            "policy_version": "1.0",
            "action_catalogue_version": "1.0",
            "required_role": "soc_l2",
            "action_ids": ["ACT-001"],
            "requested_at": requested_at.isoformat(),
            "expires_at": expires_at,
        },
        "executed_actions": [
            {
                "action_id": "ACT-001",
                "action_type": "block_ip",
                "target": "192.0.2.10",
                "status": "queued",
            }
        ],
        "final_report": {"summary": "Final report"},
        "errors": [],
        "audit_events": [
            {
                "investigation_id": "INV-PERSIST-001",
                "stage": "l1",
                "event": "analysis_completed",
                "timestamp": timestamp,
            },
            {
                "investigation_id": "INV-PERSIST-001",
                "stage": "l2",
                "event": "analysis_completed",
                "timestamp": timestamp,
            },
            {
                "investigation_id": "INV-PERSIST-001",
                "stage": "l3",
                "event": "analysis_completed",
                "timestamp": timestamp,
            },
            {
                "investigation_id": "INV-PERSIST-001",
                "stage": "final_report",
                "event": "investigation_completed",
                "timestamp": timestamp,
            },
        ],
        "pending_nodes": [],
    }


def test_repository_persists_runs_report_actions_and_audit_history():
    store = repository()
    value = snapshot()

    store.save_snapshot(value)

    assert store.get_snapshot(
        "INV-PERSIST-001",
        organization_id="org-test",
    )["status"] == "completed"
    assert store.count_snapshots(
        organization_id="org-test",
        status="completed",
    ) == 1
    assert len(store.list_agent_runs(
        "INV-PERSIST-001",
        organization_id="org-test",
    )) == 3
    assert store.get_report(
        "INV-PERSIST-001",
        organization_id="org-test",
    )["summary"] == "Final report"
    assert store.list_response_actions(
        "INV-PERSIST-001",
        organization_id="org-test",
    )[0]["status"] == (
        "queued"
    )
    assert len(store.list_audit_events(
        "INV-PERSIST-001",
        organization_id="org-test",
    )) == 4
    tier_reports = store.list_tier_reports(
        "INV-PERSIST-001",
        organization_id="org-test",
    )
    assert [item["tier"] for item in tier_reports] == ["l1", "l2", "l3"]
    assert tier_reports[0]["triage"]["severity"] == "high"
    approvals = store.list_approvals(
        "INV-PERSIST-001",
        organization_id="org-test",
    )
    assert approvals[0]["approval_id"] == "APR-001"
    assert approvals[0]["decided_by_user_id"] == "analyst"


def test_audit_events_are_append_only_and_idempotent():
    store = repository()
    value = snapshot()

    store.save_snapshot(value)
    store.save_snapshot(value)

    events = store.list_audit_events(
        "INV-PERSIST-001",
        organization_id="org-test",
    )
    assert len(events) == 4
    assert len({item["event_id"] for item in events}) == 4

    with store._session_factory() as session:
        records = (
            session.query(AuditEventRecord)
            .order_by(AuditEventRecord.id if hasattr(AuditEventRecord, "id") else AuditEventRecord.occurred_at)
            .all()
        )
    hashes = [record.event_hash for record in records]
    assert all(hashes)
    assert len(set(hashes)) == 4
    assert sum(record.previous_hash is None for record in records) == 1


def test_repository_isolates_organization_queries():
    store = repository()
    store.save_snapshot(snapshot())

    assert store.get_snapshot(
        "INV-PERSIST-001",
        organization_id="org-other",
    ) is None
    assert store.count_snapshots(organization_id="org-other") == 0
    assert store.list_agent_runs(
        "INV-PERSIST-001",
        organization_id="org-other",
    ) == []


def test_response_action_claim_is_atomic_and_cannot_repeat():
    store = repository()
    value = snapshot()
    value["status"] = "approved"
    value["current_stage"] = "response_approved"
    value["executed_actions"] = []
    store.save_snapshot(value)

    claim = store.claim_response_actions(
        "INV-PERSIST-001",
        organization_id="org-test",
        approval_id="APR-001",
        executor_user_id="user-responder",
        executor_roles=["soc_l3"],
        expected_action_ids=["ACT-001"],
        expected_plan_hash=value["approval_request"]["plan_hash"],
        expected_evidence_version=value["evidence_version"],
    )

    assert claim["action_ids"]
    actions = store.list_response_actions(
        "INV-PERSIST-001",
        organization_id="org-test",
    )
    assert actions[0]["status"] == "claimed"
    assert actions[0]["execution_id"] == claim["execution_id"]
    assert actions[0]["executor_user_id"] == "user-responder"
    assert claim["actor_user_id"] == "user-responder"
    assert claim["actor_roles"] == ["soc_l3"]

    with pytest.raises(ResponseExecutionConflictError):
        store.claim_response_actions(
            "INV-PERSIST-001",
            organization_id="org-test",
            approval_id="APR-001",
            executor_user_id="user-responder",
            executor_roles=["soc_l3"],
            expected_action_ids=["ACT-001"],
            expected_plan_hash=value["approval_request"]["plan_hash"],
            expected_evidence_version=value["evidence_version"],
        )


def test_response_action_preflight_is_durable_before_completion():
    store = repository()
    value = snapshot()
    value["status"] = "approved"
    value["current_stage"] = "response_approved"
    value["executed_actions"] = []
    store.save_snapshot(value)
    claim = store.claim_response_actions(
        "INV-PERSIST-001",
        organization_id="org-test",
        approval_id="APR-001",
        executor_user_id="user-responder",
        executor_roles=["soc_l3"],
        expected_action_ids=["ACT-001"],
        expected_plan_hash=value["approval_request"]["plan_hash"],
        expected_evidence_version=value["evidence_version"],
    )
    intended_expires_at = datetime.now(UTC) + timedelta(minutes=15)
    before_state = {
        "target": "192.0.2.10",
        "action_present": False,
        "wazuh_agent_status": "active",
        "management_connectivity": True,
    }

    assert store.begin_response_action(
        "ACT-001",
        organization_id="org-test",
        execution_id=claim["execution_id"],
        before_state=before_state,
        intended_expires_at=intended_expires_at,
        idempotency_key="IDEM-PERSIST-001",
    )

    action = store.list_response_actions(
        "INV-PERSIST-001",
        organization_id="org-test",
    )[0]
    preflight = action["details"]["execution_preflight"]
    assert action["status"] == "running"
    persisted_expiry = action["expires_at"]
    if persisted_expiry.tzinfo is None:
        persisted_expiry = persisted_expiry.replace(tzinfo=UTC)
    assert persisted_expiry == intended_expires_at
    assert preflight["before_state"] == before_state
    assert preflight["intended_expires_at"] == intended_expires_at.isoformat()
    assert preflight["idempotency_key"] == "IDEM-PERSIST-001"


def test_repository_persists_multiple_specialist_runs_and_sanitizes_tools():
    store = repository()
    value = snapshot()
    value["specialist_runs"] = [
        {
            "run_id": "RUN-L1-CONTEXT",
            "tier": "l1",
            "role": "alert_context",
            "attempt": 1,
            "status": "completed",
            "provider": "cerebras",
            "model": "test-model",
            "tool_activity": [
                {"tool": "get_alert", "authorization": "must-not-persist"}
            ],
            "input_summary": {
                "alert_id": "alert-1",
                "api_key": "must-not-persist",
            },
            "result_summary": {"summary": "context"},
        },
        {
            "run_id": "RUN-L1-SUPERVISOR",
            "parent_run_id": None,
            "tier": "l1",
            "role": "supervisor",
            "attempt": 1,
            "status": "completed",
            "input_summary": {},
            "result_summary": {"summary": "L1"},
        },
    ]

    store.save_snapshot(value)
    runs = store.list_agent_runs(
        "INV-PERSIST-001",
        organization_id="org-test",
    )

    assert len(runs) == 4
    specialist = next(run for run in runs if run["role"] == "alert_context")
    assert specialist["provider"] == "cerebras"
    assert "authorization" not in specialist["tool_activity"][0]
