from datetime import UTC, datetime
from types import SimpleNamespace

from langgraph.types import Command

from app.coreAgents.orchestration.graph import (
    create_investigation_graph,
    investigation_config,
)
from app.coreAgents.orchestration.schemas import L1Result, L2Result, L3Result
from app.services.wazuh.models import AlertEvidence


class FakeGateway:
    def __init__(self, alert=None, error: Exception | None = None):
        self.alert = alert
        self.error = error

    def get_alert_by_id(self, alert_id):
        if self.error is not None:
            raise self.error
        return self.alert


class FakeAgent:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def invoke(self, input_data):
        self.calls += 1
        return {"structured_response": self.result}


class FakeResponder:
    def __init__(self):
        self.calls = []

    def run_active_response(self, **kwargs):
        self.calls.append(kwargs)
        return {"data": {"affected_items": ["001"]}}

    def restart_agent(self, agent_id):
        self.calls.append({"restart_agent": agent_id})
        return {"data": {"affected_items": [agent_id]}}


def enabled_response_settings():
    return SimpleNamespace(
        WAZUH_READ_ONLY=False,
        WAZUH_ALLOW_DANGEROUS_TOOLS=True,
    )


def initial_state():
    return {
        "investigation_id": "INV-2026-0001",
        "status": "created",
        "current_stage": "created",
        "alert_id": "alert-1",
        "evidence": [],
        "timeline": [],
        "affected_assets": [],
        "proposed_actions": [],
        "executed_actions": [],
        "audit_events": [],
        "errors": [],
    }


def graph_config():
    return investigation_config("INV-2026-0001")


def sample_alert():
    return AlertEvidence(
        alert_id="alert-1",
        timestamp=datetime(2026, 7, 23, 10, 0, tzinfo=UTC),
        agent_id="001",
        rule_id="5710",
        rule_level=10,
        description="Repeated SSH authentication failures",
        source_ip="192.0.2.10",
        target_user="root",
        event_outcome="failure",
    )


def l1_result(severity="low", confidence=0.95):
    return L1Result(
        summary="L1 triage completed",
        classification="suspicious",
        severity=severity,
        confidence=confidence,
        evidence_refs=["alert:alert-1"],
    )


def l2_result(severity="medium"):
    return L2Result(
        summary="L2 investigation completed",
        severity=severity,
        confidence=0.9,
        evidence_refs=["alert:alert-1"],
    )


def graph_with_write_action(*, responder=None, response_settings=None):
    return create_investigation_graph(
        gateway=FakeGateway(sample_alert()),
        l1_agent=FakeAgent(l1_result(severity="high")),
        l2_agent=FakeAgent(l2_result(severity="high")),
        l3_agent=FakeAgent(
            L3Result(
                summary="Containment is recommended",
                evidence_refs=["alert:alert-1"],
                proposed_actions=[
                    {
                        "action_type": "block_ip",
                        "target": "192.0.2.10",
                        "reason": "Confirmed malicious authentication",
                        "risk_level": "medium",
                        "operational_impact": "May block a legitimate administrator",
                        "evidence_refs": ["alert:alert-1"],
                    }
                ],
            )
        ),
        responder=responder,
        response_settings=response_settings,
    )


def test_low_risk_alert_stops_after_l1():
    l1 = FakeAgent(l1_result())
    l2 = FakeAgent(l2_result())
    l3 = FakeAgent(L3Result(
        summary="L3 completed",
        evidence_refs=["alert:alert-1"],
    ))
    graph = create_investigation_graph(
        gateway=FakeGateway(sample_alert()),
        l1_agent=l1,
        l2_agent=l2,
        l3_agent=l3,
    )

    result = graph.invoke(initial_state(), config=graph_config())

    assert result["status"] == "completed"
    assert result["final_report"]["summary"] == "L1 triage completed"
    assert l1.calls == 1
    assert l2.calls == 0
    assert l3.calls == 0


def test_medium_alert_reaches_l2_then_reports():
    l1 = FakeAgent(l1_result(severity="medium"))
    l2 = FakeAgent(l2_result())
    l3 = FakeAgent(L3Result(
        summary="L3 completed",
        evidence_refs=["alert:alert-1"],
    ))
    graph = create_investigation_graph(
        gateway=FakeGateway(sample_alert()),
        l1_agent=l1,
        l2_agent=l2,
        l3_agent=l3,
    )

    result = graph.invoke(initial_state(), config=graph_config())

    assert result["final_report"]["summary"] == "L2 investigation completed"
    assert l1.calls == 1
    assert l2.calls == 1
    assert l3.calls == 0


def test_high_alert_reaches_l3_then_reports():
    l1 = FakeAgent(l1_result(severity="high"))
    l2 = FakeAgent(l2_result(severity="high"))
    l3 = FakeAgent(
        L3Result(
            summary="L3 containment analysis completed",
            remediation_steps=["Review containment options"],
            evidence_refs=["alert:alert-1"],
        )
    )
    graph = create_investigation_graph(
        gateway=FakeGateway(sample_alert()),
        l1_agent=l1,
        l2_agent=l2,
        l3_agent=l3,
    )

    result = graph.invoke(initial_state(), config=graph_config())

    assert result["final_report"]["summary"] == "L3 containment analysis completed"
    assert result["final_report"]["recommendations"] == [
        "Review containment options"
    ]
    assert l1.calls == 1
    assert l2.calls == 1
    assert l3.calls == 1


def test_wazuh_failure_ends_in_safe_failed_state():
    l1 = FakeAgent(l1_result())
    graph = create_investigation_graph(
        gateway=FakeGateway(error=RuntimeError("secret connection detail")),
        l1_agent=l1,
    )

    result = graph.invoke(initial_state(), config=graph_config())

    assert result["status"] == "failed"
    assert result["current_stage"] == "failed"
    assert result["errors"][0]["code"] == "WAZUH_ALERT_LOAD_FAILED"
    assert "secret connection detail" not in str(result)
    assert l1.calls == 0


def test_completed_investigation_is_available_from_checkpoint():
    graph = create_investigation_graph(
        gateway=FakeGateway(sample_alert()),
        l1_agent=FakeAgent(l1_result()),
    )
    config = graph_config()

    result = graph.invoke(initial_state(), config=config)
    snapshot = graph.get_state(config)

    assert result["status"] == "completed"
    assert snapshot.values["investigation_id"] == "INV-2026-0001"
    assert snapshot.values["status"] == "completed"
    assert snapshot.values["final_report"] == result["final_report"]
    assert snapshot.next == ()


def test_write_action_stops_in_awaiting_approval_without_execution():
    graph = graph_with_write_action()
    config = graph_config()

    result = graph.invoke(initial_state(), config=config)
    snapshot = graph.get_state(config)

    assert result["status"] == "awaiting_approval"
    assert result["current_stage"] == "human_approval"
    assert result["approval_request"]["proposed_actions"][0][
        "action_type"
    ] == "block_ip"
    assert result["executed_actions"] == []
    assert "final_report" not in result
    assert snapshot.values["status"] == "awaiting_approval"
    assert snapshot.next == ("human_approval",)
    assert result["__interrupt__"][0].value["allowed_decisions"] == [
        "approve",
        "reject",
        "modify",
    ]


def test_rejected_action_resumes_to_final_report_without_execution():
    graph = graph_with_write_action()
    config = graph_config()
    interrupted = graph.invoke(initial_state(), config=config)

    result = graph.invoke(
        Command(
            resume={
                "decision": "reject",
                "approved_by": "analyst@example.com",
                "approval_id": interrupted["approval_request"]["approval_id"],
            }
        ),
        config=config,
    )

    assert result["status"] == "completed"
    assert result["final_report"]["response_status"] == "rejected"
    assert result["executed_actions"] == []
    assert result["approval_decision"]["decision"] == "reject"


def test_approval_stops_before_separate_response_execution():
    responder = FakeResponder()
    graph = graph_with_write_action(
        responder=responder,
        response_settings=enabled_response_settings(),
    )
    config = graph_config()
    interrupted = graph.invoke(initial_state(), config=config)

    approved = graph.invoke(
        Command(
            resume={
                "decision": "approve",
                "approved_by": "analyst@example.com",
                "approval_id": interrupted["approval_request"]["approval_id"],
            }
        ),
        config=config,
    )

    assert approved["status"] == "approved"
    assert approved["current_stage"] == "response_approved"
    assert approved["executed_actions"] == []
    assert responder.calls == []

    result = graph.invoke(
        Command(
            resume={
                "approval_id": approved["approval_request"]["approval_id"],
                "execution_id": "EXE-001",
                "executed_by": "responder@example.com",
                "action_ids": ["ACT-001"],
            }
        ),
        config=config,
    )

    assert result["status"] == "completed"
    assert result["current_stage"] == "final_report"
    assert result["executed_actions"][0]["status"] == (
        "verification_pending"
    )
    assert result["final_report"]["response_status"] == (
        "verification_pending"
    )
    assert responder.calls[0]["command"] == "firewall-drop"
    assert responder.calls[0]["arguments"] == ["192.0.2.10"]


def test_modified_read_only_action_is_revalidated_and_reported():
    graph = graph_with_write_action()
    config = graph_config()
    interrupted = graph.invoke(initial_state(), config=config)

    result = graph.invoke(
        Command(
            resume={
                "decision": "modify",
                "approved_by": "analyst@example.com",
                "approval_id": interrupted["approval_request"]["approval_id"],
                "modified_actions": [
                    {
                        "action_type": "collect_more_evidence",
                        "target": "agent-001",
                        "reason": "Collect evidence before containment",
                        "risk_level": "low",
                        "operational_impact": "Longer investigation",
                        "requires_approval": False,
                    }
                ],
            }
        ),
        config=config,
    )

    assert result["status"] == "completed"
    assert result["proposed_actions"][0]["requires_approval"] is False
    assert result["executed_actions"] == []


def test_modified_write_action_interrupts_again():
    graph = graph_with_write_action()
    config = graph_config()
    interrupted = graph.invoke(initial_state(), config=config)

    result = graph.invoke(
        Command(
            resume={
                "decision": "modify",
                "approved_by": "analyst@example.com",
                "approval_id": interrupted["approval_request"]["approval_id"],
                "modified_actions": [
                    {
                        "action_type": "restart_agent",
                        "target": "001",
                        "reason": "Restart the affected Wazuh agent",
                        "risk_level": "high",
                        "operational_impact": "Temporary telemetry interruption",
                        "requires_approval": False,
                    }
                ],
            }
        ),
        config=config,
    )

    assert result["status"] == "awaiting_approval"
    assert result["proposed_actions"][0]["requires_approval"] is True
    assert result["__interrupt__"]


def test_invalid_approval_fails_closed():
    graph = graph_with_write_action()
    config = graph_config()
    interrupted = graph.invoke(initial_state(), config=config)

    result = graph.invoke(
        Command(
            resume={
                "decision": "approve",
                "approval_id": interrupted["approval_request"]["approval_id"],
            }
        ),
        config=config,
    )

    assert result["status"] == "failed"
    assert result["errors"][-1]["code"] == "INVALID_APPROVAL_DECISION"
    assert result["executed_actions"] == []
