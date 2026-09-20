"""Unit tests for the Wazuh state-capture and rollback adapters.

These adapters run after the approval gate, so the tests pin the safety
properties: a numeric agent is mandatory, an unverified rollback stays
retryable, and an unregistered inverse action never reaches the responder.
"""

from types import SimpleNamespace

import pytest

from app.mape_k.executor import ACTIVE_RESPONSE_COMMANDS
from app.mape_k.registries import ACTION_REGISTRY
from app.mape_k.schemas import ActionType, IncidentWorkflowState, RemediationAction
from app.mape_k.temporary_actions import TemporaryActionRollbackTask
from app.mape_k.wazuh_response import (
    WazuhBeforeStateProvider,
    WazuhTemporaryActionRollbackAdapter,
)


EVIDENCE_ID = "EV-ABCDEF123456"


class FakeRepository:
    def __init__(self, *, actions=None, snapshot=None):
        self._actions = actions or []
        self._snapshot = snapshot

    def list_response_actions(self, investigation_id, *, organization_id):
        return self._actions

    def get_snapshot(self, investigation_id, *, organization_id):
        return self._snapshot


class FakeGateway:
    def __init__(self, agent):
        self._agent = agent
        self.calls = []

    def get_agent_summary(self, agent_id):
        self.calls.append(agent_id)
        return self._agent


class RecordingResponder:
    def __init__(self, response=None):
        self.calls = []
        # Kept verbatim: a non-dict reply means the manager did not accept.
        self._response = response

    def run_active_response(self, *, agent_id, command, arguments):
        self.calls.append(
            {"agent_id": agent_id, "command": command, "arguments": arguments}
        )
        return self._response


def _state(agent_id: str = "004") -> IncidentWorkflowState:
    return IncidentWorkflowState(
        incident_id="INC-WZ",
        investigation_id="INV-WZ",
        alert_id="alert-1",
        agent_id=agent_id,
        organization_id="org-1",
    )


def _action(action_type=ActionType.BLOCK_IP, target="10.0.0.9") -> RemediationAction:
    return RemediationAction(
        action_id="ACT-1",
        action_type=action_type,
        target=target,
        risk_level=2,
        evidence_refs=[EVIDENCE_ID],
        # Only a temporary IP block carries a TTL; the schema rejects it as None.
        ttl_seconds=3600 if action_type == ActionType.BLOCK_IP else None,
    )


def _task(
    *,
    rollback_action_type=ActionType.UNBLOCK_IP,
    target="10.0.0.9",
) -> TemporaryActionRollbackTask:
    return TemporaryActionRollbackTask(
        action_id="ACT-1",
        investigation_id="INV-WZ",
        organization_id="org-1",
        action_type=ActionType.BLOCK_IP,
        target=target,
        rollback_action_id="ACT-1-RB",
        rollback_action_type=rollback_action_type,
        rollback_claim_id="claim-1",
        rollback_idempotency_key="idem-1",
        attempt=1,
    )


# --- before-state capture -------------------------------------------------


@pytest.mark.parametrize("agent_id", ["", "agent-004", "00a", None])
def test_state_capture_requires_a_numeric_agent_id(agent_id):
    provider = WazuhBeforeStateProvider(
        repository=FakeRepository(),
        gateway=FakeGateway(SimpleNamespace(status="active")),
    )

    with pytest.raises(RuntimeError, match="numeric Wazuh agent ID"):
        provider(action=_action(), state=_state(agent_id))


def test_state_capture_rejects_a_missing_agent():
    provider = WazuhBeforeStateProvider(
        repository=FakeRepository(),
        gateway=FakeGateway(None),
    )

    with pytest.raises(RuntimeError, match="agent is unavailable"):
        provider(action=_action(), state=_state())


def test_state_capture_reports_the_matching_active_action_as_present():
    repository = FakeRepository(
        actions=[
            {"action_type": "block_ip", "target": "10.0.0.9", "status": "applied"},
        ]
    )
    provider = WazuhBeforeStateProvider(
        repository=repository,
        gateway=FakeGateway(SimpleNamespace(status="Active")),
    )

    snapshot = provider(action=_action(), state=_state())

    assert snapshot == {
        "target": "10.0.0.9",
        "action_present": True,
        "wazuh_agent_status": "active",
        "management_connectivity": True,
        "snapshot_source": "wazuh_agent_and_tsage_action_ledger",
    }


@pytest.mark.parametrize(
    "record",
    [
        {"action_type": "block_ip", "target": "10.0.0.9", "status": "rolled_back"},
        {"action_type": "block_ip", "target": "10.0.0.8", "status": "applied"},
        {"action_type": "disable_user", "target": "10.0.0.9", "status": "applied"},
    ],
    ids=["inactive_status", "other_target", "other_action_type"],
)
def test_state_capture_ignores_non_matching_ledger_records(record):
    provider = WazuhBeforeStateProvider(
        repository=FakeRepository(actions=[record]),
        gateway=FakeGateway(SimpleNamespace(status="active")),
    )

    assert provider(action=_action(), state=_state())["action_present"] is False


def test_state_capture_of_an_inverse_action_looks_up_the_forward_effect():
    """unblock_ip has no inverse of its own, so presence means the block exists."""
    provider = WazuhBeforeStateProvider(
        repository=FakeRepository(
            actions=[
                {"action_type": "block_ip", "target": "10.0.0.9", "status": "executed"},
            ]
        ),
        gateway=FakeGateway(SimpleNamespace(status="active")),
    )

    snapshot = provider(action=_action(ActionType.UNBLOCK_IP), state=_state())

    assert snapshot["action_present"] is True


def test_disconnected_agent_still_captures_state_without_connectivity():
    provider = WazuhBeforeStateProvider(
        repository=FakeRepository(),
        gateway=FakeGateway(SimpleNamespace(status="disconnected")),
    )

    snapshot = provider(action=_action(), state=_state())

    assert snapshot["wazuh_agent_status"] == "disconnected"
    assert snapshot["management_connectivity"] is False


def test_unknown_agent_status_is_normalised():
    provider = WazuhBeforeStateProvider(
        repository=FakeRepository(),
        gateway=FakeGateway(SimpleNamespace(status=None)),
    )

    assert provider(action=_action(), state=_state())["wazuh_agent_status"] == "unknown"


# --- rollback -------------------------------------------------------------


def test_rollback_refuses_a_snapshot_without_a_numeric_agent():
    responder = RecordingResponder()
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=FakeRepository(snapshot={"agent_id": "not-numeric"}),
        gateway=FakeGateway(SimpleNamespace(status="active")),
        responder=responder,
    )

    result = adapter.rollback(_task())

    assert result.success is False
    assert result.retryable is False
    assert result.details == {"error": "numeric_wazuh_agent_id_required"}
    assert responder.calls == [], "no command may be sent without a resolved agent"


def test_rollback_refuses_a_missing_snapshot():
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=FakeRepository(snapshot=None),
        gateway=FakeGateway(SimpleNamespace(status="active")),
        responder=RecordingResponder(),
    )

    result = adapter.rollback(_task())

    assert (result.success, result.retryable) == (False, False)
    assert result.details["error"] == "numeric_wazuh_agent_id_required"


def test_rollback_without_a_registered_adapter_is_not_retryable(monkeypatch):
    """A registered action whose executor adapter is missing must not be sent.

    Every action currently in ACTION_REGISTRY has an active-response command,
    so this guard is only reachable if the two catalogues drift apart. Dropping
    the command simulates that drift.
    """
    monkeypatch.delitem(
        ACTIVE_RESPONSE_COMMANDS,
        "wazuh_active_response.firewall_drop_delete",
    )
    responder = RecordingResponder()
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=FakeRepository(snapshot={"agent_id": "004"}),
        gateway=FakeGateway(SimpleNamespace(status="active")),
        responder=responder,
    )

    result = adapter.rollback(_task())

    assert result.success is False
    assert result.retryable is False
    assert result.details == {"error": "rollback_adapter_not_registered"}
    assert responder.calls == []


def test_every_registered_rollback_action_has_an_active_response_command():
    """Guards the drift that the previous test simulates."""
    for action_type in (ActionType.UNBLOCK_IP, ActionType.ENABLE_USER):
        registration = ACTION_REGISTRY.require(action_type)
        assert registration.executor_key in ACTIVE_RESPONSE_COMMANDS


def test_successful_rollback_sends_the_inverse_command_and_verifies():
    responder = RecordingResponder(response={"error": 0})
    gateway = FakeGateway(SimpleNamespace(status="active"))
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=FakeRepository(snapshot={"agent_id": "004"}),
        gateway=gateway,
        responder=responder,
    )

    result = adapter.rollback(_task())

    assert responder.calls == [
        {
            "agent_id": "004",
            "command": "firewall-drop-delete",
            "arguments": ["10.0.0.9"],
        }
    ]
    assert result.success is True
    assert result.verified is True
    assert result.retryable is False
    assert result.details == {
        "manager_accepted": True,
        "wazuh_agent_status": "active",
        "verification_scope": "manager_acceptance_and_agent_connectivity",
        "rollback_idempotency_key": "idem-1",
    }


def test_rollback_of_a_disabled_account_uses_its_own_command():
    responder = RecordingResponder(response={"error": 0})
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=FakeRepository(snapshot={"agent_id": "004"}),
        gateway=FakeGateway(SimpleNamespace(status="active")),
        responder=responder,
    )

    adapter.rollback(_task(rollback_action_type=ActionType.ENABLE_USER, target="alice"))

    assert responder.calls[0]["command"] == "disable-account-delete"
    assert responder.calls[0]["arguments"] == ["alice"]


def test_rollback_stays_retryable_when_the_agent_is_disconnected():
    """The command was accepted, but connectivity could not confirm delivery."""
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=FakeRepository(snapshot={"agent_id": "004"}),
        gateway=FakeGateway(SimpleNamespace(status="disconnected")),
        responder=RecordingResponder(response={"error": 0}),
    )

    result = adapter.rollback(_task())

    assert result.success is False
    assert result.verified is False
    assert result.retryable is True
    assert result.details["manager_accepted"] is True
    assert result.details["wazuh_agent_status"] == "disconnected"


def test_rollback_stays_retryable_when_the_manager_rejects_the_command():
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=FakeRepository(snapshot={"agent_id": "004"}),
        gateway=FakeGateway(SimpleNamespace(status="active")),
        responder=RecordingResponder(response=None),
    )

    result = adapter.rollback(_task())

    assert result.success is False
    assert result.retryable is True
    assert result.details["manager_accepted"] is False


def test_rollback_handles_a_missing_agent_summary():
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=FakeRepository(snapshot={"agent_id": "004"}),
        gateway=FakeGateway(None),
        responder=RecordingResponder(response={"error": 0}),
    )

    result = adapter.rollback(_task())

    assert result.success is False
    assert result.retryable is True
    assert result.details["wazuh_agent_status"] == "unknown"
