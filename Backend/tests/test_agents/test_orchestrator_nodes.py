import json

from app.coreAgents.orchestration.nodes import run_l1, run_l2, run_l3
from app.coreAgents.orchestration.schemas import L1Result, L2Result, L3Result


class FakeAgent:
    def __init__(self, structured_response=None, error: Exception | None = None):
        self.structured_response = structured_response
        self.error = error
        self.input = None

    def invoke(self, input_data):
        self.input = input_data
        if self.error is not None:
            raise self.error
        return {"structured_response": self.structured_response}


def base_state():
    return {
        "investigation_id": "INV-2026-0001",
        "status": "running",
        "current_stage": "l1",
        "alert_id": "alert-1",
        "normalized_alert": {
            "alert_id": "alert-1",
            "rule_level": 10,
        },
        "evidence": [],
        "audit_events": [],
        "errors": [],
    }


def test_l1_node_stores_validated_structured_output():
    result = L1Result(
        summary="Suspicious authentication failures",
        classification="suspicious",
        severity="medium",
        confidence=0.82,
        escalate=True,
        evidence=[{"alert_id": "alert-1"}],
    )
    agent = FakeAgent(result)

    update = run_l1(base_state(), agent=agent)

    assert update["l1_result"]["classification"] == "suspicious"
    assert update["severity"] == "medium"
    assert update["confidence"] == 0.82
    assert update["evidence"] == [{"alert_id": "alert-1"}]
    assert update["audit_events"][0]["event"] == "analysis_completed"

    message = agent.input["messages"][0]
    assert message["role"] == "user"
    assert json.loads(message["content"])["alert"]["alert_id"] == "alert-1"


def test_l2_node_stores_timeline_and_assets():
    state = {
        **base_state(),
        "l1_result": {
            "summary": "Escalate",
            "classification": "suspicious",
            "severity": "medium",
            "confidence": 0.8,
        },
    }
    agent = FakeAgent(
        L2Result(
            summary="Related activity confirmed",
            severity="high",
            confidence=0.91,
            timeline=[{"timestamp": "2026-07-23T10:00:00Z"}],
            affected_assets=["agent-001"],
            requires_l3=True,
        )
    )

    update = run_l2(state, agent=agent)

    assert update["l2_result"]["requires_l3"] is True
    assert update["timeline"][0]["timestamp"] == "2026-07-23T10:00:00Z"
    assert update["affected_assets"] == ["agent-001"]


def test_l3_node_can_propose_but_not_execute_actions():
    state = {
        **base_state(),
        "l1_result": {"summary": "Escalated"},
        "l2_result": {
            "summary": "Compromise likely",
            "severity": "high",
            "confidence": 0.95,
        },
    }
    agent = FakeAgent(
        L3Result(
            summary="Containment recommended",
            proposed_actions=[
                {
                    "action_type": "block_ip",
                    "target": "192.0.2.10",
                    "reason": "Malicious authentication",
                    "risk_level": "medium",
                    "operational_impact": "May block a legitimate administrator",
                }
            ],
        )
    )

    update = run_l3(state, agent=agent)

    assert update["proposed_actions"][0]["action_type"] == "block_ip"
    assert update["proposed_actions"][0]["requires_approval"] is True
    assert "executed_actions" not in update


def test_missing_prerequisite_fails_without_invoking_agent():
    agent = FakeAgent()

    l1_update = run_l1(
        {
            "investigation_id": "INV-1",
            "status": "running",
            "current_stage": "l1",
            "alert_id": "alert-1",
        },
        agent=agent,
    )
    l2_update = run_l2(base_state(), agent=agent)
    l3_update = run_l3(base_state(), agent=agent)

    assert l1_update["errors"][0]["code"] == "ALERT_NOT_NORMALIZED"
    assert l2_update["errors"][0]["code"] == "L1_RESULT_MISSING"
    assert l3_update["errors"][0]["code"] == "L2_RESULT_MISSING"
    assert agent.input is None


def test_agent_failure_returns_safe_failed_state():
    agent = FakeAgent(error=RuntimeError("secret provider detail"))

    update = run_l1(base_state(), agent=agent)

    assert update["status"] == "failed"
    assert update["current_stage"] == "failed"
    assert update["errors"][0]["code"] == "L1_AGENT_FAILED"
    assert "secret provider detail" not in str(update)
