import json
from datetime import UTC, datetime
from time import sleep
from types import SimpleNamespace

from langchain_core.language_models.fake_chat_models import (
    FakeMessagesListChatModel,
)
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver

from app.coreAgents.orchestration.conversation_agent import (
    create_soc_chat_agent,
)
from app.coreAgents.orchestration.conversation_runner import (
    _client_tool_results,
    run_soc_conversation,
    serialize_conversation_result,
    stream_soc_conversation,
)
from app.coreAgents.orchestration import conversation_runner
from app.coreAgents.orchestration.conversation_state import SOCChatContext
from app.coreAgents.orchestration.conversation_tools import (
    build_soc_chat_tools,
)
from app.coreAgents.tools.python_functions.yaml_loader import (
    load_prompt_template,
)
from app.services.wazuh.models import (
    AlertEvidence,
    AlertSearchResult,
    ArchivedLogSearchResult,
    AuthenticationTimeline,
    DetectionEvidence,
    EndpointInventory,
    RawAlertDocument,
    RuleMitreContext,
)


class ToolCallingFakeModel(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


class FakeGateway:
    def __init__(self):
        self.alert_calls = []

    def get_alert_by_id(self, alert_id):
        self.alert_calls.append(alert_id)
        return AlertEvidence(
            alert_id=alert_id,
            timestamp=datetime(2026, 7, 23, 10, 0, tzinfo=UTC),
            agent_id="001",
            rule_id="5710",
            rule_level=10,
            description="Synthetic authentication failure",
            source_ip="192.0.2.10",
            event_outcome="failure",
        )


class FakeInvestigationService:
    def __init__(self):
        self.started_alerts = []

    def start(
        self,
        *,
        alert_id,
        initiated_by,
        initiation_reason,
        agent_id=None,
        organization_id="local",
        owner_user_id=None,
    ):
        self.started_alerts.append(alert_id)
        return self.snapshot(
            "INV-TEST001",
            organization_id=organization_id,
        )

    def snapshot(self, investigation_id, *, organization_id=None):
        return {
            "investigation_id": investigation_id,
            "alert_id": "synthetic-1",
            "agent_id": "001",
            "status": "completed",
            "current_stage": "final_report",
            "severity": "high",
            "confidence": 0.9,
            "l1_result": {"summary": "Structured triage"},
            "l2_result": None,
            "l3_result": None,
            "final_report": {"summary": "Formal workflow completed"},
            "proposed_actions": [],
            "approval_request": None,
            "approval_decision": None,
            "executed_actions": [],
            "errors": [],
            "audit_events": [],
            "pending_nodes": [],
        }

    def list_recent(self, *, limit, organization_id="local"):
        return []


def chat_context():
    return SOCChatContext(
        current_time="2026-07-23T10:00:00Z",
        wazuh_status="healthy",
        permissions=("wazuh:read",),
        allowed_tools=tuple(
            tool.name
            for tool in build_soc_chat_tools(
                FakeGateway(),
                FakeInvestigationService(),
            )
        ),
        active_response_enabled=False,
    )


def test_chat_tool_surface_is_bounded_and_read_only():
    names = {
        tool.name
        for tool in build_soc_chat_tools(
            FakeGateway(),
            FakeInvestigationService(),
        )
    }
    assert names == {
        "get_recent_wazuh_alerts",
        "get_high_severity_alerts",
        "search_archived_wazuh_logs",
        "get_wazuh_log_statistics",
        "get_alert_details",
        "get_raw_alert_document",
        "search_related_alerts",
        "search_alerts_by_agent_and_time",
        "build_authentication_timeline",
        "check_successful_login_after_failures",
        "investigate_alert_attribution",
        "get_endpoint_context",
        "get_endpoint_inventory",
        "get_endpoint_security_findings",
        "search_endpoint_vulnerabilities",
        "get_detection_rule_context",
        "collect_host_diagnostic",
        "get_open_investigations",
        "start_investigation",
        "get_investigation_status",
    }
    assert not names & {
        "block_ip",
        "isolate_agent",
        "restart_service",
        "active_response",
    }


def test_chat_prompt_requires_scoped_authentication_conclusions():
    prompt = load_prompt_template("soc_chat_system_prompt")

    assert "check_successful_login_after_failures before claiming" in prompt
    assert "No successful authentication is present" in prompt
    assert "Do not call it credential stuffing" in prompt
    assert "private source address identifies a LAN host" in prompt
    assert '"Not present in this event"' in prompt
    assert "archive_status" in prompt


def test_endpoint_evidence_tools_use_bounded_gateway_operations():
    class EndpointGateway(FakeGateway):
        def get_agent_inventory(self, **kwargs):
            assert kwargs == {
                "agent_id": "001",
                "component": "ports",
                "limit": 10,
                "text": "ssh",
            }
            return EndpointInventory(
                agent_id="001",
                component="ports",
                total=1,
                returned=1,
                truncated=False,
                items=[
                    {
                        "local": {"port": 22},
                        "internal_noise": "not required for analysis",
                    }
                ],
            )

        def get_detection_evidence(self, **kwargs):
            assert kwargs == {"agent_id": "001", "limit": 20}
            return DetectionEvidence(
                agent_id="001",
                fim_findings=[{"file": "/etc/ssh/sshd_config"}],
                sca_findings=[],
                rootcheck_findings=[],
                fim_total=1,
                sca_total=0,
                rootcheck_total=0,
                truncated=False,
            )

        def search_vulnerabilities(self, **kwargs):
            assert kwargs == {
                "severity": "Critical",
                "agent_id": "001",
                "limit": 5,
            }
            return ([{"id": "CVE-2026-0001"}], 1)

        def get_rule_and_mitre_context(self, rule_id):
            assert rule_id == "2502"
            return RuleMitreContext(
                rule_id="2502",
                description="Authentication failures",
                level=10,
                mitre_ids=["T1110"],
            )

    tools = {
        item.name: item
        for item in build_soc_chat_tools(
            EndpointGateway(),
            FakeInvestigationService(),
        )
    }

    inventory = tools["get_endpoint_inventory"].invoke({
        "agent_id": "001",
        "component": "ports",
        "limit": 10,
        "text": "ssh",
    })
    findings = tools["get_endpoint_security_findings"].invoke({
        "agent_id": "001",
        "limit": 20,
    })
    vulnerabilities = tools["search_endpoint_vulnerabilities"].invoke({
        "severity": "Critical",
        "agent_id": "001",
        "limit": 5,
    })
    rule = tools["get_detection_rule_context"].invoke({"rule_id": "2502"})

    assert inventory["data"]["items"][0]["local"]["port"] == 22
    assert "internal_noise" not in inventory["data"]["items"][0]
    assert inventory["data"]["normalized_for_analysis"] is True
    assert findings["data"]["fim_total"] == 1
    assert vulnerabilities["data"]["vulnerabilities"][0]["id"] == (
        "CVE-2026-0001"
    )
    assert rule["data"]["context"]["mitre_ids"] == ["T1110"]


def test_conversation_executes_tool_then_returns_natural_answer():
    gateway = FakeGateway()
    service = FakeInvestigationService()
    tools = build_soc_chat_tools(gateway, service)
    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "get_alert_details",
                        "args": {"alert_id": "synthetic-1"},
                        "id": "call-1",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(
                content=(
                    "The alert is high severity and affects agent 001. "
                    "The evidence is synthetic."
                )
            ),
        ]
    )
    agent = create_soc_chat_agent(
        model=model,
        tools=tools,
        checkpointer=InMemorySaver(),
    )

    result = run_soc_conversation(
        message="Inspect synthetic-1.",
        conversation_id="conversation-1",
        agent=agent,
        context=chat_context(),
        investigation_service=service,
    )

    assert gateway.alert_calls == ["synthetic-1"]
    assert result["tools_used"] == ["get_alert_details"]
    assert result["active_alert_id"] == "synthetic-1"
    assert result["assistant_message"].startswith("The alert is high severity")
    assert result["activities"][0]["status"] == "completed"


def test_same_conversation_id_preserves_prior_messages():
    model = ToolCallingFakeModel(
        responses=[
            AIMessage(content="I will remember synthetic-1."),
            AIMessage(content="You previously referenced synthetic-1."),
        ]
    )
    agent = create_soc_chat_agent(
        model=model,
        tools=[],
        checkpointer=InMemorySaver(),
    )
    context = SOCChatContext(
        current_time="2026-07-23T10:00:00Z",
        wazuh_status="healthy",
        permissions=("wazuh:read",),
        allowed_tools=(),
        active_response_enabled=False,
    )

    run_soc_conversation(
        message="Remember synthetic-1.",
        conversation_id="conversation-memory",
        agent=agent,
        context=context,
    )
    result = run_soc_conversation(
        message="Which alert did I reference?",
        conversation_id="conversation-memory",
        agent=agent,
        context=context,
    )
    state = agent.get_state(
        {"configurable": {"thread_id": "local:conversation-memory"}}
    )

    humans = [
        message
        for message in state.values["messages"]
        if isinstance(message, HumanMessage)
    ]
    assert len(humans) == 2
    assert result["assistant_message"] == (
        "You previously referenced synthetic-1."
    )


def test_chat_can_start_formal_investigation_as_a_tool():
    service = FakeInvestigationService()
    tools = build_soc_chat_tools(FakeGateway(), service)
    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "get_alert_details",
                        "args": {"alert_id": "synthetic-1"},
                        "id": "call-verify-alert",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "start_investigation",
                        "args": {
                            "alert_id": "synthetic-1",
                            "reason": "High-severity authentication evidence.",
                        },
                        "id": "call-investigation",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(
                content=(
                    "The formal investigation completed. "
                    "Review the validated report before taking action."
                )
            ),
        ]
    )
    agent = create_soc_chat_agent(
        model=model,
        tools=tools,
        checkpointer=InMemorySaver(),
    )

    result = run_soc_conversation(
        message="Start the formal investigation for synthetic-1.",
        conversation_id="conversation-investigation",
        agent=agent,
        context=chat_context(),
        investigation_service=service,
    )

    assert result["active_investigation_id"] == "INV-TEST001"
    assert result["tools_used"] == [
        "get_alert_details",
        "start_investigation",
    ]
    assert result["response"]["summary"] == "Formal workflow completed"
    assert result["investigation"]["status"] == "completed"


def test_stream_emits_safe_activity_and_final_result():
    gateway = FakeGateway()
    service = FakeInvestigationService()
    tools = build_soc_chat_tools(gateway, service)
    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "get_alert_details",
                        "args": {"alert_id": "synthetic-1"},
                        "id": "call-stream",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="The synthetic alert was inspected."),
        ]
    )
    agent = create_soc_chat_agent(
        model=model,
        tools=tools,
        checkpointer=InMemorySaver(),
    )

    events = list(
        stream_soc_conversation(
            message="Inspect synthetic-1.",
            conversation_id="conversation-stream",
            agent=agent,
            context=chat_context(),
            investigation_service=service,
        )
    )

    event_names = [event for event, _ in events]
    activity_payloads = [
        payload for event, payload in events if event == "activity"
    ]
    final = next(payload for event, payload in events if event == "final")
    assert "token" in event_names
    assert any(
        payload["label"] == "Inspecting alert details"
        and payload["status"] == "completed"
        for payload in activity_payloads
    )
    assert final["assistant_message"] == "The synthetic alert was inspected."


def test_stream_emits_heartbeat_and_progress_while_model_is_slow(monkeypatch):
    class SlowAgent:
        def stream(self, *args, **kwargs):
            sleep(0.03)
            yield (
                "messages",
                (
                    AIMessage(content="Completed after waiting."),
                    {"langgraph_node": "model"},
                ),
            )

        def get_state(self, config):
            return SimpleNamespace(values={
                "messages": [
                    HumanMessage(content="Analyze."),
                    AIMessage(content="Completed after waiting."),
                ]
            })

    monkeypatch.setattr(
        conversation_runner,
        "STREAM_HEARTBEAT_SECONDS",
        0.005,
    )
    events = list(
        stream_soc_conversation(
            message="Analyze.",
            conversation_id="conversation-slow",
            agent=SlowAgent(),
            context=chat_context(),
            investigation_service=FakeInvestigationService(),
        )
    )

    assert any(name == "heartbeat" for name, _ in events)
    assert any(
        name == "activity"
        and payload["id"] == "analysis"
        and payload["label"] in {
            "Contacting the analysis model",
            "Analysis is still running",
        }
        for name, payload in events
    )
    assert events[-1][0] == "final"


def test_formal_investigation_verifies_alert_inside_start_tool():
    service = FakeInvestigationService()
    gateway = FakeGateway()
    tools = build_soc_chat_tools(gateway, service)
    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "start_investigation",
                        "args": {
                            "alert_id": "guessed-alert",
                            "reason": "The user requested an investigation.",
                        },
                        "id": "call-unverified",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(
                content="The exact alert was verified and investigated."
            ),
        ]
    )
    agent = create_soc_chat_agent(
        model=model,
        tools=tools,
        checkpointer=InMemorySaver(),
    )

    result = run_soc_conversation(
        message="Investigate guessed-alert.",
        conversation_id="conversation-unverified",
        agent=agent,
        context=chat_context(),
        investigation_service=service,
    )

    assert gateway.alert_calls == ["guessed-alert"]
    assert service.started_alerts == ["guessed-alert"]
    assert result["active_investigation_id"] == "INV-TEST001"


def test_formal_investigation_rejects_alert_missing_from_wazuh():
    class MissingAlertGateway(FakeGateway):
        def get_alert_by_id(self, alert_id):
            self.alert_calls.append(alert_id)
            return None

    service = FakeInvestigationService()
    gateway = MissingAlertGateway()
    tools = build_soc_chat_tools(gateway, service)
    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "start_investigation",
                        "args": {
                            "alert_id": "missing-alert",
                            "reason": "The user requested an investigation.",
                        },
                        "id": "call-missing",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="The exact alert does not exist in Wazuh."),
        ]
    )
    agent = create_soc_chat_agent(
        model=model,
        tools=tools,
        checkpointer=InMemorySaver(),
    )

    result = run_soc_conversation(
        message="Investigate missing-alert.",
        conversation_id="conversation-missing",
        agent=agent,
        context=chat_context(),
        investigation_service=service,
    )

    assert gateway.alert_calls == ["missing-alert"]
    assert service.started_alerts == []
    assert result["active_investigation_id"] is None
    assert result["response"]["tool_results"][0]["result"]["error"]["code"] == (
        "ALERT_NOT_FOUND"
    )


def test_client_inventory_result_is_compacted_without_mutating_agent_evidence():
    tool_results = [
        {
            "tool": "get_endpoint_inventory",
            "result": {
                "ok": True,
                "data": {
                    "component": "processes",
                    "total": 50,
                    "returned": 20,
                    "items": [{"pid": str(index)} for index in range(20)],
                },
            },
        }
    ]

    compacted = _client_tool_results(tool_results)

    data = compacted[0]["result"]["data"]
    assert len(data["items"]) == 10
    assert data["response_items"] == 10
    assert data["response_truncated"] is True
    assert len(tool_results[0]["result"]["data"]["items"]) == 20


def test_client_security_findings_are_compacted():
    findings = [{"id": str(index)} for index in range(20)]
    tool_results = [
        {
            "tool": "get_endpoint_security_findings",
            "result": {
                "ok": True,
                "data": {
                    "fim_findings": findings,
                    "sca_findings": findings,
                    "rootcheck_findings": findings,
                },
            },
        }
    ]

    data = _client_tool_results(tool_results)[0]["result"]["data"]

    assert len(data["fim_findings"]) == 10
    assert len(data["sca_findings"]) == 10
    assert len(data["rootcheck_findings"]) == 10
    assert data["response_truncated"] is True


class AttributionGateway(FakeGateway):
    def get_alert_by_id(self, alert_id):
        self.alert_calls.append(alert_id)
        return AlertEvidence(
            alert_id=alert_id,
            timestamp=datetime(2026, 7, 23, 10, 0, tzinfo=UTC),
            agent_id="001",
            agent_name="linux-vm",
            rule_id="2502",
            rule_level=10,
            description="User missed the password more than one time",
            event_outcome="failure",
        )

    def get_raw_alert_by_id(self, alert_id):
        alert = self.get_alert_by_id(alert_id)
        return RawAlertDocument(
            alert_id=alert_id,
            normalized=alert,
            raw_document={
                "@timestamp": "2026-07-23T10:00:00Z",
                "agent": {"id": "001", "name": "linux-vm"},
                "rule": {"id": "2502"},
            },
        )

    def search_alerts_by_agent_and_time(self, **kwargs):
        event = AlertEvidence(
            alert_id="lower-level-1",
            timestamp=datetime(2026, 7, 23, 9, 59, tzinfo=UTC),
            agent_id="001",
            rule_id="5710",
            rule_level=8,
            description="Failed password",
            source_ip="192.0.2.44",
            target_user="root",
            full_log="Failed password for root from 192.0.2.44 port 22 ssh2",
            event_outcome="failure",
        )
        return AlertSearchResult(
            total=1,
            returned=1,
            truncated=False,
            alerts=[event],
        )

    def build_authentication_timeline(self, **kwargs):
        events = self.search_alerts_by_agent_and_time().alerts
        return AuthenticationTimeline(
            total=1,
            returned=1,
            truncated=False,
            events=events,
        )

    def search_archived_logs(self, **kwargs):
        return ArchivedLogSearchResult(
            index_pattern="wazuh-archives-*",
            total=0,
            returned=0,
            truncated=False,
            events=[],
        )


def test_attribution_tool_widens_when_correlated_alert_lacks_fields():
    gateway = AttributionGateway()
    service = FakeInvestigationService()
    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "investigate_alert_attribution",
                        "args": {"alert_id": "correlated-1"},
                        "id": "call-attribution",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(
                content=(
                    "The correlated alert was attributed using its surrounding "
                    "lower-level authentication event."
                )
            ),
        ]
    )
    agent = create_soc_chat_agent(
        model=model,
        tools=build_soc_chat_tools(gateway, service),
        checkpointer=InMemorySaver(),
    )

    result = run_soc_conversation(
        message="Identify the source and user for correlated-1.",
        conversation_id="conversation-attribution",
        agent=agent,
        context=chat_context(),
        investigation_service=service,
    )

    assert result["response"]["status"] == "identified"
    assert result["response"]["source_ip"] == "192.0.2.44"
    assert result["response"]["target_user"] == "root"
    assert result["response"]["source_address_scope"] == "private"
    assert result["response"]["attributed_person"] is None
    assert result["response"]["successful_login_search_completed"] is True
    assert result["response"]["steps_completed"] <= 8
    assert result["investigation_progress"]["complete"] is True
    assert result["missing_evidence"] == ["full_log"]


def archive_tool_messages():
    return [
        HumanMessage(
            content="Search archived Wazuh logs for suspicious SSH activity."
        ),
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "search_archived_wazuh_logs",
                    "args": {"text": "suspicious SSH"},
                    "id": "call-archive",
                    "type": "tool_call",
                }
            ],
        ),
        ToolMessage(
            name="search_archived_wazuh_logs",
            tool_call_id="call-archive",
            content=(
                '{"ok": true, "data": {"index_pattern": '
                '"wazuh-archives-*", "total": 0, "returned": 0, '
                '"truncated": false, "events": []}}'
            ),
        ),
    ]


def test_completed_archive_tool_has_grounded_fallback_without_final_model_answer():
    result = serialize_conversation_result(
        {"messages": archive_tool_messages()},
        conversation_id="conversation-archive-fallback",
        investigation_service=FakeInvestigationService(),
    )

    assert result["assistant_message"].startswith(
        "The archived Wazuh searches completed"
    )
    assert result["response"]["tool_results"][0]["result"]["ok"] is True


def test_stream_recovers_completed_tool_result_after_model_provider_failure():
    class FailingAfterToolAgent:
        def stream(self, *args, **kwargs):
            raise RuntimeError("provider unavailable")
            yield

        def get_state(self, config):
            return SimpleNamespace(values={"messages": archive_tool_messages()})

    events = list(
        stream_soc_conversation(
            message="Search archived Wazuh logs.",
            conversation_id="conversation-stream-recovery",
            agent=FailingAfterToolAgent(),
            context=chat_context(),
            investigation_service=FakeInvestigationService(),
        )
    )

    assert [name for name, _ in events] == ["activity", "final"]
    final = events[-1][1]
    assert final["assistant_message"].startswith(
        "The archived Wazuh searches completed"
    )


def test_stream_recovers_started_investigation_after_provider_failure():
    snapshot = FakeInvestigationService().snapshot("INV-TEST001")
    messages = [
        HumanMessage(content="Start a formal investigation for synthetic-1."),
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "start_investigation",
                    "args": {
                        "alert_id": "synthetic-1",
                        "reason": "User requested formal triage.",
                    },
                    "id": "call-start",
                    "type": "tool_call",
                }
            ],
        ),
        ToolMessage(
            name="start_investigation",
            tool_call_id="call-start",
            content=json.dumps({"ok": True, "data": snapshot}),
        ),
    ]

    class FailingAfterStartAgent:
        def stream(self, *args, **kwargs):
            raise RuntimeError("provider unavailable")
            yield

        def get_state(self, config):
            return SimpleNamespace(values={
                "messages": messages,
                "active_investigation_id": "INV-TEST001",
                "active_alert_id": "synthetic-1",
            })

    events = list(
        stream_soc_conversation(
            message="Start the formal workflow.",
            conversation_id="conversation-start-recovery",
            agent=FailingAfterStartAgent(),
            context=chat_context(),
            investigation_service=FakeInvestigationService(),
        )
    )

    assert [name for name, _ in events] == ["activity", "final"]
    final = events[-1][1]
    assert final["active_investigation_id"] == "INV-TEST001"
    assert final["assistant_message"].startswith(
        "The exact alert was verified and formal investigation INV-TEST001"
    )
    assert final["response"]["summary"] == "Formal workflow completed"
