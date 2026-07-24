import json
from datetime import UTC, datetime
from unittest.mock import Mock

from langchain.agents.middleware import ToolCallLimitMiddleware
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.prebuilt.tool_node import ToolCallRequest

from app.coreAgents.orchestration.graph import (
    create_investigation_graph,
    investigation_config,
)
from app.coreAgents.orchestration.schemas import (
    L1AlertContextFindings,
    L1Result,
    L1RiskClassificationFindings,
    L2AssetInvestigationFindings,
    L2CorrelationFindings,
    L2Result,
    L3DetectionEngineeringFindings,
    L3ResponsePlanningFindings,
    L3Result,
)
from app.coreAgents.orchestration.soc_teams import (
    SPECIALIST_TOOL_CALL_LIMIT,
    _specialist_middleware,
    create_l1_team,
    create_l2_team,
    create_l3_team,
    reject_duplicate_tool_call,
)
from app.coreAgents.orchestration.team_registry import (
    SPECIALIST_SPECS,
    get_specialist_tools,
)
from app.services.wazuh.models import AlertEvidence


class FakeAgent:
    def __init__(self, role, result=None, error=None, call_order=None):
        self.role = role
        self.result = result
        self.error = error
        self.call_order = call_order if call_order is not None else []
        self.calls = []

    def invoke(self, input_data):
        self.call_order.append(self.role)
        self.calls.append(input_data)
        if self.error is not None:
            raise self.error
        return {"structured_response": self.result}


def l1_agents(*, first_error=None, second_error=None):
    order = []
    return {
        "l1_alert_context": FakeAgent(
            "l1_alert_context",
            L1AlertContextFindings(
                summary="Alert and host context verified",
                verified_alert={"alert_id": "alert-1"},
                affected_entities=["agent-001"],
                evidence=[{"alert_id": "alert-1"}],
            ),
            error=first_error,
            call_order=order,
        ),
        "l1_risk_classification": FakeAgent(
            "l1_risk_classification",
            L1RiskClassificationFindings(
                summary="Authentication activity is suspicious",
                classification="suspicious",
                severity="high",
                confidence=0.9,
                escalation_indicators=["Repeated authentication failures"],
            ),
            error=second_error,
            call_order=order,
        ),
        "l1_supervisor": FakeAgent(
            "l1_supervisor",
            L1Result(
                summary="Suspicious authentication activity",
                classification="suspicious",
                severity="high",
                confidence=0.9,
                escalate=True,
                evidence=[{"alert_id": "alert-1"}],
            ),
            call_order=order,
        ),
        "_order": order,
    }


def l2_agents():
    order = []
    return {
        "l2_correlation": FakeAgent(
            "l2_correlation",
            L2CorrelationFindings(
                summary="Related authentication alerts correlated",
                timeline=[{"timestamp": "2026-07-23T10:00:00Z"}],
                related_alert_ids=["alert-2"],
            ),
            call_order=order,
        ),
        "l2_asset_investigation": FakeAgent(
            "l2_asset_investigation",
            L2AssetInvestigationFindings(
                summary="Agent context reviewed",
                affected_assets=["agent-001"],
                compromise_indicators=["Repeated failures"],
            ),
            call_order=order,
        ),
        "l2_supervisor": FakeAgent(
            "l2_supervisor",
            L2Result(
                summary="Correlated compromise activity",
                severity="high",
                confidence=0.91,
                timeline=[{"timestamp": "2026-07-23T10:00:00Z"}],
                affected_assets=["agent-001"],
                requires_l3=True,
            ),
            call_order=order,
        ),
        "_order": order,
    }


def l3_agents():
    order = []
    return {
        "l3_detection_engineering": FakeAgent(
            "l3_detection_engineering",
            L3DetectionEngineeringFindings(
                summary="Detection coverage reviewed",
                root_cause="Credential attack",
                detection_gaps=["Missing successful-login correlation"],
            ),
            call_order=order,
        ),
        "l3_response_planning": FakeAgent(
            "l3_response_planning",
            L3ResponsePlanningFindings(
                summary="Containment proposal prepared",
                proposed_actions=[
                    {
                        "action_type": "block_ip",
                        "target": "192.0.2.10",
                        "reason": "Confirmed malicious authentication",
                        "risk_level": "medium",
                        "operational_impact": "May block a legitimate administrator",
                    }
                ],
            ),
            call_order=order,
        ),
        "l3_supervisor": FakeAgent(
            "l3_supervisor",
            L3Result(
                summary="Containment requires approval",
                proposed_actions=[
                    {
                        "action_type": "block_ip",
                        "target": "192.0.2.10",
                        "reason": "Confirmed malicious authentication",
                        "risk_level": "medium",
                        "operational_impact": "May block a legitimate administrator",
                    }
                ],
            ),
            call_order=order,
        ),
        "_order": order,
    }


def team_agents(values):
    return {key: value for key, value in values.items() if not key.startswith("_")}


def team_state():
    return {
        "investigation_id": "INV-1",
        "alert_id": "alert-1",
        "normalized_alert": {
            "alert_id": "alert-1",
            "agent_id": "001",
            "rule_level": 12,
        },
        "evidence": [],
        "timeline": [],
        "affected_assets": [],
    }


def test_l1_team_runs_two_specialists_then_no_tool_supervisor():
    agents = l1_agents()
    result = create_l1_team(agents=team_agents(agents)).invoke(team_state())

    assert agents["_order"] == [
        "l1_alert_context",
        "l1_risk_classification",
        "l1_supervisor",
    ]
    assert result["l1_result"]["classification"] == "suspicious"
    assert result["current_stage"] == "l1_completed"
    assert [run["role"] for run in result["specialist_runs"]] == [
        "l1_alert_context",
        "l1_risk_classification",
        "supervisor",
    ]
    assert all(run["status"] == "completed" for run in result["specialist_runs"])
    supervisor_run = result["specialist_runs"][-1]
    assert supervisor_run["parent_run_id"] is None
    assert all(
        run["parent_run_id"] == supervisor_run["run_id"]
        for run in result["specialist_runs"][:2]
    )
    assert [event["event"] for event in result["audit_events"]].count(
        "subagent_started"
    ) == 3
    assert [event["event"] for event in result["audit_events"]].count(
        "subagent_completed"
    ) == 3

    supervisor_payload = json.loads(
        agents["l1_supervisor"].calls[0]["messages"][0]["content"]
    )
    assert set(supervisor_payload["specialist_findings"]) == {
        "l1_alert_context",
        "l1_risk_classification",
    }


def test_l2_and_l3_teams_preserve_authoritative_result_contracts():
    l2 = l2_agents()
    l2_state = {
        **team_state(),
        "l1_result": L1Result(
            summary="Escalated",
            classification="suspicious",
            severity="high",
            confidence=0.9,
        ).model_dump(mode="json"),
    }
    l2_result = create_l2_team(agents=team_agents(l2)).invoke(l2_state)

    assert l2["_order"] == [
        "l2_correlation",
        "l2_asset_investigation",
        "l2_supervisor",
    ]
    assert L2Result.model_validate(l2_result["l2_result"]).requires_l3 is True
    assert l2_result["affected_assets"] == ["agent-001"]

    l3 = l3_agents()
    l3_result = create_l3_team(agents=team_agents(l3)).invoke(
        {
            **l2_state,
            "l2_result": l2_result["l2_result"],
            "timeline": l2_result["timeline"],
            "affected_assets": l2_result["affected_assets"],
        }
    )

    assert l3["_order"] == [
        "l3_detection_engineering",
        "l3_response_planning",
        "l3_supervisor",
    ]
    assert L3Result.model_validate(l3_result["l3_result"])
    assert l3_result["proposed_actions"][0]["requires_approval"] is True
    assert "executed_actions" not in l3_result


def test_team_continues_after_one_specialist_fails():
    agents = l1_agents(first_error=TimeoutError("provider timeout"))
    result = create_l1_team(agents=team_agents(agents)).invoke(team_state())

    assert result["status"] == "running"
    assert [run["status"] for run in result["specialist_runs"]] == [
        "failed",
        "completed",
        "completed",
    ]
    assert result["specialist_runs"][0]["error_code"] == (
        "L1_ALERT_CONTEXT_FAILED"
    )
    supervisor_payload = json.loads(
        agents["l1_supervisor"].calls[0]["messages"][0]["content"]
    )
    assert supervisor_payload["specialist_failures"] == [
        {
            "role": "l1_alert_context",
            "error_code": "L1_ALERT_CONTEXT_FAILED",
        }
    ]
    assert "provider timeout" not in str(result)


def test_team_fails_closed_when_both_specialists_fail():
    agents = l1_agents(
        first_error=RuntimeError("secret one"),
        second_error=RuntimeError("secret two"),
    )
    result = create_l1_team(agents=team_agents(agents)).invoke(team_state())

    assert result["status"] == "failed"
    assert result["errors"][0]["code"] == "L1_SPECIALISTS_FAILED"
    assert agents["l1_supervisor"].calls == []
    assert [run["status"] for run in result["specialist_runs"]] == [
        "failed",
        "failed",
        "failed",
    ]
    assert "secret one" not in str(result)
    assert "secret two" not in str(result)


def test_specialist_tool_allowlists_are_exact_and_read_only():
    gateway = Mock()
    expected = {
        role: set(spec.tool_names)
        for role, spec in SPECIALIST_SPECS.items()
    }

    for role, names in expected.items():
        actual = {tool.name for tool in get_specialist_tools(role, gateway)}
        assert actual == names
        assert not any("response" in name for name in actual)
        assert not actual & {"request", "post", "put", "delete", "execute"}


def test_specialist_middleware_enforces_four_tool_calls(monkeypatch):
    from app.coreAgents.llm import model_pool

    monkeypatch.setattr(model_pool, "get_agent_middleware", lambda _tier: [])
    middleware = _specialist_middleware("l2")
    limits = [
        item
        for item in middleware
        if isinstance(item, ToolCallLimitMiddleware)
    ]

    assert SPECIALIST_TOOL_CALL_LIMIT == 4
    assert len(limits) == 1
    assert limits[0].run_limit == 4


def test_duplicate_tool_call_is_rejected_before_execution():
    call = {
        "name": "get_alert_by_id",
        "args": {"alert_id": "alert-1"},
        "id": "call-2",
        "type": "tool_call",
    }
    request = ToolCallRequest(
        tool_call=call,
        tool=None,
        state={
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {**call, "id": "call-1"},
                        call,
                    ],
                )
            ]
        },
        runtime=Mock(),
    )
    handler = Mock(
        return_value=ToolMessage(content="executed", tool_call_id="call-2")
    )

    result = reject_duplicate_tool_call.wrap_tool_call(request, handler)

    assert result.status == "error"
    assert "DUPLICATE_TOOL_CALL" in str(result.content)
    handler.assert_not_called()


def test_first_of_two_identical_tool_calls_is_allowed():
    first_call = {
        "name": "get_alert_by_id",
        "args": {"alert_id": "alert-1"},
        "id": "call-1",
        "type": "tool_call",
    }
    request = ToolCallRequest(
        tool_call=first_call,
        tool=None,
        state={
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        first_call,
                        {**first_call, "id": "call-2"},
                    ],
                )
            ]
        },
        runtime=Mock(),
    )
    handler = Mock(
        return_value=ToolMessage(content="executed", tool_call_id="call-1")
    )

    result = reject_duplicate_tool_call.wrap_tool_call(request, handler)

    assert result.content == "executed"
    handler.assert_called_once_with(request)


class FakeGateway:
    def get_alert_by_id(self, alert_id):
        return AlertEvidence(
            alert_id=alert_id,
            timestamp=datetime(2026, 7, 23, 10, 0, tzinfo=UTC),
            agent_id="001",
            rule_id="5710",
            rule_level=4,
            description="Low-risk test alert",
        )


def test_parent_graph_inherits_team_state_without_duplicate_run_records():
    l1 = l1_agents()
    l1["l1_supervisor"].result = L1Result(
        summary="Low-risk alert",
        classification="benign",
        severity="low",
        confidence=0.95,
    )
    graph = create_investigation_graph(
        gateway=FakeGateway(),
        l1_team=create_l1_team(agents=team_agents(l1)),
        l2_team=create_l2_team(agents=team_agents(l2_agents())),
        l3_team=create_l3_team(agents=team_agents(l3_agents())),
    )
    initial = {
        "investigation_id": "INV-1",
        "organization_id": "org_123",
        "owner_user_id": "user_123",
        "status": "created",
        "current_stage": "created",
        "alert_id": "alert-1",
        "evidence": [],
        "timeline": [],
        "affected_assets": [],
        "proposed_actions": [],
        "executed_actions": [],
        "specialist_runs": [],
        "audit_events": [],
        "errors": [],
    }

    result = graph.invoke(initial, config=investigation_config("INV-1"))

    assert result["status"] == "completed"
    assert result["organization_id"] == "org_123"
    assert result["owner_user_id"] == "user_123"
    assert len(result["specialist_runs"]) == 3
    assert len({run["run_id"] for run in result["specialist_runs"]}) == 3
