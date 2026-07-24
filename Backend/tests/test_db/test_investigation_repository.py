from datetime import UTC, datetime

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.repositories.investigations import (
    SQLAlchemyInvestigationRepository,
)


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
    return {
        "investigation_id": "INV-PERSIST-001",
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
                "action_type": "block_ip",
                "target": "192.0.2.10",
                "risk_level": "medium",
            }
        ],
        "approval_decision": {
            "decision": "approve",
            "approval_id": "APR-001",
            "approved_by": "analyst",
        },
        "approval_request": {
            "investigation_id": "INV-PERSIST-001",
            "approval_id": "APR-001",
            "status": "awaiting_approval",
            "expires_at": timestamp,
            "proposed_actions": [
                {
                    "action_type": "block_ip",
                    "target": "192.0.2.10",
                }
            ],
        },
        "executed_actions": [
            {
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
