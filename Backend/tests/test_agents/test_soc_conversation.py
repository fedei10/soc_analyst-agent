from datetime import UTC, datetime

from langchain_core.language_models.fake_chat_models import (
    FakeMessagesListChatModel,
)
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import InMemorySaver

from app.coreAgents.orchestration.conversation_agent import (
    create_soc_chat_agent,
)
from app.coreAgents.orchestration.conversation_runner import (
    run_soc_conversation,
    stream_soc_conversation,
)
from app.coreAgents.orchestration.conversation_state import SOCChatContext
from app.coreAgents.orchestration.conversation_tools import (
    build_soc_chat_tools,
)
from app.services.wazuh.models import (
    AlertEvidence,
    AlertSearchResult,
    ArchivedLogSearchResult,
    AuthenticationTimeline,
    RawAlertDocument,
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

    def start(self, *, alert_id, initiated_by, initiation_reason, agent_id=None):
        self.started_alerts.append(alert_id)
        return self.snapshot("INV-TEST001")

    def snapshot(self, investigation_id):
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

    def list_recent(self, *, limit):
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
        {"configurable": {"thread_id": "conversation-memory"}}
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


def test_formal_investigation_rejects_unverified_alert_id():
    service = FakeInvestigationService()
    tools = build_soc_chat_tools(FakeGateway(), service)
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
                content=(
                    "I need to retrieve the exact alert before starting "
                    "the formal workflow."
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
        message="Investigate guessed-alert.",
        conversation_id="conversation-unverified",
        agent=agent,
        context=chat_context(),
        investigation_service=service,
    )

    assert service.started_alerts == []
    assert result["active_investigation_id"] is None


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
    assert result["response"]["steps_completed"] <= 8
    assert result["investigation_progress"]["complete"] is True
    assert result["missing_evidence"] == ["full_log"]
