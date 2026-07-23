import pytest

from app.coreAgents.orchestration.nodes import (
    mark_awaiting_approval,
    prepare_actions,
)
from app.coreAgents.orchestration.routing import (
    requires_approval,
    route_after_action_policy,
)
from app.coreAgents.orchestration.schemas import WRITE_ACTIONS


def base_state(actions):
    return {
        "investigation_id": "INV-2026-0001",
        "status": "running",
        "current_stage": "l3_completed",
        "alert_id": "alert-1",
        "proposed_actions": actions,
        "audit_events": [],
        "errors": [],
    }


def action(action_type="collect_more_evidence"):
    return {
        "action_type": action_type,
        "target": "agent-001",
        "reason": "Investigation recommendation",
        "risk_level": "medium",
        "operational_impact": "Analyst review required",
    }


def test_no_actions_goes_to_final_report():
    state = {**base_state([]), **prepare_actions(base_state([]))}

    assert route_after_action_policy(state) == "final_report"


def test_read_only_recommendation_goes_to_final_report():
    initial = base_state([action()])
    state = {**initial, **prepare_actions(initial)}

    assert state["proposed_actions"][0]["requires_approval"] is False
    assert route_after_action_policy(state) == "final_report"


@pytest.mark.parametrize("action_type", sorted(WRITE_ACTIONS))
def test_every_write_action_requires_approval(action_type):
    assert requires_approval(action(action_type)) is True


def test_model_supplied_policy_value_is_ignored():
    proposed = {**action("block_ip"), "requires_approval": False}
    initial = base_state([proposed])

    update = prepare_actions(initial)
    state = {**initial, **update}

    assert update["proposed_actions"][0]["requires_approval"] is True
    assert route_after_action_policy(state) == "awaiting_approval"


def test_malformed_action_fails_closed():
    initial = base_state([{"action_type": "block_ip"}])

    update = prepare_actions(initial)
    state = {**initial, **update}

    assert update["status"] == "failed"
    assert update["errors"][0]["code"] == "INVALID_PROPOSED_ACTIONS"
    assert route_after_action_policy(state) == "failed"


def test_approval_checkpoint_contains_only_write_actions():
    initial = base_state(
        [
            action("collect_more_evidence"),
            action("block_ip"),
        ]
    )
    prepared = prepare_actions(initial)
    state = {**initial, **prepared}

    update = mark_awaiting_approval(state)

    assert update["status"] == "awaiting_approval"
    assert update["current_stage"] == "human_approval"
    assert len(update["approval_request"]["proposed_actions"]) == 1
    assert (
        update["approval_request"]["proposed_actions"][0]["action_type"]
        == "block_ip"
    )
    assert "executed_actions" not in update
