from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.coreAgents.orchestration.executor import execute_response


class FakeResponder:
    def __init__(self, error: Exception | None = None):
        self.error = error
        self.calls = []

    def run_active_response(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {"data": {"affected_items": ["001"]}}

    def restart_agent(self, agent_id):
        self.calls.append({"restart_agent": agent_id})
        if self.error is not None:
            raise self.error
        return {"data": {"affected_items": [agent_id]}}


class FakeSystemExecutor:
    def __init__(self):
        self.validated = []
        self.restarted = []

    def validate_service(self, service_name):
        self.validated.append(service_name)

    def restart_service(self, service_name):
        self.restarted.append(service_name)
        return {"status": "completed"}


def settings(*, enabled=True):
    return SimpleNamespace(
        WAZUH_READ_ONLY=not enabled,
        WAZUH_ALLOW_DANGEROUS_TOOLS=enabled,
    )


def approved_state(*, action_type="block_ip", target="192.0.2.10"):
    action = {
        "action_type": action_type,
        "target": target,
        "reason": "Confirmed malicious authentication",
        "risk_level": "medium",
        "operational_impact": "May block a legitimate administrator",
        "requires_approval": True,
    }
    return {
        "investigation_id": "INV-2026-0001",
        "status": "approved",
        "current_stage": "response_approved",
        "alert_id": "alert-1",
        "agent_id": "001",
        "source_alert": {"alert_id": "alert-1"},
        "proposed_actions": [action],
        "approval_request": {
            "investigation_id": "INV-2026-0001",
            "approval_id": "APR-001",
            "expires_at": (
                datetime.now(UTC) + timedelta(minutes=15)
            ).isoformat(),
            "status": "awaiting_approval",
            "proposed_actions": [deepcopy(action)],
            "allowed_decisions": ["approve", "reject", "modify"],
        },
        "approval_decision": {
            "decision": "approve",
            "approved_by": "analyst@example.com",
            "approval_id": "APR-001",
            "modified_actions": None,
        },
        "execution_authorization": {
            "approval_id": "APR-001",
            "execution_id": "EXE-001",
            "executed_by": "responder@example.com",
            "action_ids": ["ACT-001"],
        },
        "executed_actions": [],
        "audit_events": [],
        "errors": [],
    }


def test_disabled_response_flags_fail_before_responder_call():
    responder = FakeResponder()

    update = execute_response(
        approved_state(),
        responder=responder,
        settings_obj=settings(enabled=False),
    )

    assert update["errors"][0]["code"] == "RESPONSE_ACTIONS_DISABLED"
    assert responder.calls == []


def test_investigation_id_mismatch_fails_closed():
    state = approved_state()
    state["approval_request"]["investigation_id"] = "INV-WRONG"

    update = execute_response(
        state,
        responder=FakeResponder(),
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "INVESTIGATION_ID_MISMATCH"


def test_expired_approval_fails_closed():
    state = approved_state()
    state["approval_request"]["expires_at"] = (
        datetime.now(UTC) - timedelta(seconds=1)
    ).isoformat()

    update = execute_response(
        state,
        responder=FakeResponder(),
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "APPROVAL_EXPIRED"


def test_approval_id_mismatch_fails_closed():
    state = approved_state()
    state["approval_decision"]["approval_id"] = "APR-WRONG"

    update = execute_response(
        state,
        responder=FakeResponder(),
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "APPROVAL_ID_MISMATCH"


def test_missing_approver_fails_closed():
    state = approved_state()
    state["approval_decision"]["approved_by"] = ""

    update = execute_response(
        state,
        responder=FakeResponder(),
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "VALID_APPROVAL_MISSING"


def test_changed_action_does_not_match_approval():
    state = approved_state()
    state["proposed_actions"][0]["target"] = "192.0.2.20"

    update = execute_response(
        state,
        responder=FakeResponder(),
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "APPROVED_ACTION_MISMATCH"


def test_action_outside_policy_catalog_fails_before_execution():
    state = approved_state(action_type="isolate_agent", target="agent-001")

    update = execute_response(
        state,
        responder=FakeResponder(),
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "APPROVED_ACTION_MISMATCH"


def test_invalid_ip_target_fails_closed():
    state = approved_state(target="not-an-ip")

    update = execute_response(
        state,
        responder=FakeResponder(),
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "INVALID_RESPONSE_TARGET"


def test_missing_ip_target_fails_closed():
    state = approved_state(target=None)

    update = execute_response(
        state,
        responder=FakeResponder(),
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "INVALID_RESPONSE_TARGET"


def test_approved_block_ip_uses_allowlisted_responder_command():
    responder = FakeResponder()

    update = execute_response(
        approved_state(),
        responder=responder,
        settings_obj=settings(),
    )

    assert update["status"] == "running"
    assert update["executed_actions"][0]["status"] == "executed"
    assert update["executed_actions"][0]["provider_status"] == "queued"
    assert responder.calls == [
        {
            "agent_id": "001",
            "command": "firewall-drop",
            "arguments": ["192.0.2.10"],
            "alert": {"alert_id": "alert-1"},
        }
    ]


def test_approved_agent_restart_uses_wazuh_responder():
    responder = FakeResponder()

    update = execute_response(
        approved_state(action_type="restart_agent", target="001"),
        responder=responder,
        settings_obj=settings(),
    )

    assert update["executed_actions"][0]["status"] == "executed"
    assert responder.calls == [{"restart_agent": "001"}]


def test_approved_service_restart_uses_allowlisted_system_executor():
    executor = FakeSystemExecutor()

    update = execute_response(
        approved_state(
            action_type="restart_service",
            target="wazuh-agent.service",
        ),
        system_executor=executor,
        settings_obj=settings(),
    )

    assert executor.validated == ["wazuh-agent.service"]
    assert executor.restarted == ["wazuh-agent.service"]
    assert update["executed_actions"][0]["status"] == "executed"


def test_responder_failure_does_not_leak_details():
    responder = FakeResponder(RuntimeError("secret responder detail"))

    update = execute_response(
        approved_state(),
        responder=responder,
        settings_obj=settings(),
    )

    assert update["errors"][0]["code"] == "RESPONSE_EXECUTION_FAILED"
    assert "secret responder detail" not in str(update)
