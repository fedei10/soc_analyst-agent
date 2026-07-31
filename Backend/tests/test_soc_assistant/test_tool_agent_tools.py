"""Checks for the tool-calling agent's tool wrappers, especially save_report."""

import json

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.errors import GraphRecursionError
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from app.db.repositories.reports import InMemoryReportRepository
from app.soc_assistant.tool_agent import (
    SOCToolAgent,
    _safe_tool_error,
    _select_agent_tools,
    build_tools,
)


def _tools(report_repository, organization_id="user_1", created_by="user_1"):
    return {
        item.name: item
        for item in build_tools(
            gateway=None,
            report_repository=report_repository,
            investigations=None,
            organization_id=organization_id,
            created_by=created_by,
            conversation_id="conv-1",
        )
    }


def test_save_report_persists_under_the_calling_context():
    repo = InMemoryReportRepository()
    tools = _tools(repo, organization_id="user_42", created_by="user_42")

    raw = tools["save_report"].invoke(
        {
            "title": "SSH brute force write-up",
            "summary": "Repeated failed logins, one source IP.",
            "body_markdown": "## Summary\nBrute force.\n## Recommendations\n- Block IP",
            "severity": "high",
            "related_alert_ids": ["ssh-1"],
        }
    )
    result = json.loads(raw)
    assert result["saved"] is True
    report_id = result["report_id"]

    stored = repo.get(report_id, organization_id="user_42")
    assert stored is not None
    assert stored["title"] == "SSH brute force write-up"
    assert stored["conversation_id"] == "conv-1"
    assert stored["created_by"] == "user_42"
    assert stored["related_alert_ids"] == ["ssh-1"]

    # Not visible from a different organization scope.
    assert repo.get(report_id, organization_id="someone_else") is None


def test_save_report_is_idempotent_for_the_same_agent_call():
    repo = InMemoryReportRepository()
    tool = _tools(repo)["save_report"]
    payload = {
        "title": "Incident report",
        "summary": "One bounded summary.",
        "body_markdown": "## Summary\nEvidence-backed report.",
        "related_alert_ids": ["alert-1"],
    }

    first = json.loads(tool.invoke(payload))
    second = json.loads(tool.invoke(payload))

    assert first["report_id"] == second["report_id"]
    assert len(repo.list(organization_id="user_1", limit=10)) == 1


def test_mutating_tools_are_only_exposed_for_matching_intent():
    tools = list(_tools(InMemoryReportRepository()).values())

    lookup = {item.name for item in _select_agent_tools("show alerts", tools)}
    response = {
        item.name
        for item in _select_agent_tools(
            "investigate and contain alert alert-1",
            tools,
        )
    }
    report = {
        item.name
        for item in _select_agent_tools("save an incident report", tools)
    }

    assert "start_investigation" not in lookup
    assert "save_report" not in lookup
    assert "start_investigation" in response
    assert "save_report" in report


def test_alert_id_from_tool_result_reads_get_alert_and_search_alerts():
    extract = SOCToolAgent._alert_id_from_tool_result

    assert extract("get_alert", json.dumps({"alert_id": "alert-1"})) == "alert-1"
    assert extract(
        "search_alerts",
        json.dumps({"alerts": [{"alert_id": "alert-2"}, {"alert_id": "alert-3"}]}),
    ) == "alert-2"
    assert extract("search_alerts", json.dumps({"alerts": []})) is None
    assert extract("get_alert", json.dumps({"error": "not found"})) is None
    assert extract("agent_status", json.dumps({"alert_id": "alert-1"})) is None
    assert extract("get_alert", "not json") is None


def test_answer_stops_cleanly_on_graph_recursion_limit(monkeypatch):
    class FakeLLM:
        def get_client(self):
            return object()

    class FakeAgent:
        def invoke(self, *args, **kwargs):
            raise GraphRecursionError("recursion limit reached")

    monkeypatch.setattr(
        "app.soc_assistant.tool_agent.create_react_agent",
        lambda *args, **kwargs: FakeAgent(),
    )
    agent = SOCToolAgent(
        gateway=None,
        llm=FakeLLM(),
        report_repository=InMemoryReportRepository(),
        investigations=None,
    )

    result = agent.answer(
        question="analyze everything", history=[]
    )
    answer, tool_calls, active_alert_id = result

    assert tool_calls == []
    assert active_alert_id is None
    assert result.failed_tools == []
    assert "reasoning-step limit" in answer


def test_answer_flags_a_failed_tool_the_model_narrated_as_success(monkeypatch):
    class FakeLLM:
        def get_client(self):
            return object()

    class FakeAgent:
        def invoke(self, *args, **kwargs):
            return {
                "messages": [
                    ToolMessage(
                        content="Error: relation \"soc_reports\" does not exist",
                        name="save_report",
                        tool_call_id="call-1",
                        status="error",
                    ),
                    AIMessage(content="Report saved successfully."),
                ]
            }

    monkeypatch.setattr(
        "app.soc_assistant.tool_agent.create_react_agent",
        lambda *args, **kwargs: FakeAgent(),
    )
    agent = SOCToolAgent(
        gateway=None,
        llm=FakeLLM(),
        report_repository=InMemoryReportRepository(),
        investigations=None,
    )

    result = agent.answer(question="save a report", history=[])
    answer, tool_calls, _ = result

    assert tool_calls == ["save_report"]
    assert result.failed_tools == ["save_report"]
    assert result.grounded is False
    assert "Tool failure" in answer
    assert "`save_report`" in answer


def test_answer_does_not_attach_every_tool_reference_as_a_footer(monkeypatch):
    class FakeLLM:
        def get_client(self):
            return object()

    class FakeAgent:
        def invoke(self, *args, **kwargs):
            return {
                "messages": [
                    ToolMessage(
                        content=json.dumps(
                            {
                                "alerts": [
                                    {"alert_id": "alert-relevant"},
                                    {"alert_id": "alert-unrelated"},
                                ]
                            }
                        ),
                        name="search_alerts",
                        tool_call_id="call-1",
                    ),
                    AIMessage(
                        content="The relevant evidence is alert-relevant."
                    ),
                ]
            }

    monkeypatch.setattr(
        "app.soc_assistant.tool_agent.create_react_agent",
        lambda *args, **kwargs: FakeAgent(),
    )
    agent = SOCToolAgent(
        gateway=None,
        llm=FakeLLM(),
        report_repository=InMemoryReportRepository(),
        investigations=None,
    )

    result = agent.answer(question="which alert matters?", history=[])

    assert result.evidence_references == ["alert-relevant"]
    assert "alert-unrelated" not in result.answer


def test_tool_node_converts_runtime_errors_to_safe_error_messages():
    @tool
    def failing_lookup(indicator: str) -> str:
        """Look up one indicator."""
        raise RuntimeError("postgresql://secret-user:secret-password@db")

    node = ToolNode(
        [failing_lookup],
        handle_tool_errors=_safe_tool_error,
    )
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    graph = builder.compile()
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "failing_lookup",
                            "args": {"indicator": "192.0.2.10"},
                            "id": "call-1",
                            "type": "tool_call",
                        }
                    ],
                )
            ]
        }
    )

    message = result["messages"][-1]
    assert isinstance(message, ToolMessage)
    assert message.status == "error"
    assert "TOOL_EXECUTION_FAILED" in str(message.content)
    assert "secret-password" not in str(message.content)


def test_save_report_truncates_oversized_fields():
    repo = InMemoryReportRepository()
    tools = _tools(repo)

    raw = tools["save_report"].invoke(
        {
            "title": "x" * 500,
            "summary": "y" * 3000,
            "body_markdown": "z" * 30000,
        }
    )
    result = json.loads(raw)
    stored = repo.get(result["report_id"], organization_id="user_1")
    assert len(stored["title"]) == 256
    assert len(stored["summary"]) == 2000
    assert len(stored["body_markdown"]) == 20000


# --- Wazuh tool payload compaction ----------------------------------------


def _dpkg_alert(index: int):
    from datetime import UTC, datetime

    from app.services.wazuh.normalization.schemas import NormalizedAlert

    return NormalizedAlert(
        alert_id=f"alert-{index}",
        timestamp=datetime.now(UTC),
        agent_id="001",
        agent_name="srv",
        hostname="srv",
        rule_id="2501",
        rule_level=7,
        rule_description="dpkg (Debian Package) installed.",
        rule_groups=["syslog", "dpkg"],
        category="system",
        attack_family="none",
        event_type="package_install",
        summary="dpkg installed a package.",
        evidence_ref=f"wazuh:alert:alert-{index}",
        normalization_quality="complete",
    )


def test_compact_alert_drops_empty_fields_but_keeps_citation_data():
    from app.soc_assistant.tool_agent import _compact_alert

    compacted = _compact_alert(_dpkg_alert(1))

    # Null/unknown noise is gone.
    assert "source_ip" not in compacted
    assert "target_user" not in compacted
    assert "cve_id" not in compacted
    assert compacted.get("outcome") is None
    # Everything needed to cite the alert survives.
    assert compacted["alert_id"] == "alert-1"
    assert compacted["evidence_ref"] == "wazuh:alert:alert-1"
    assert compacted["rule_id"] == "2501"


def test_rule_rollup_counts_repeated_rules():
    from app.soc_assistant.tool_agent import _rule_rollup

    rollup = _rule_rollup([_dpkg_alert(index) for index in range(10)])

    assert rollup == [
        {
            "rule_id": "2501",
            "count": 10,
            "level": 7,
            "description": "dpkg (Debian Package) installed.",
            "groups": ["syslog", "dpkg"],
        }
    ]


def test_compaction_materially_shrinks_a_repetitive_burst():
    """The payload is replayed every ReAct round, so size is a real cost."""
    import json

    from app.soc_assistant.tool_agent import _compact_alert, _rule_rollup

    alerts = [_dpkg_alert(index) for index in range(10)]
    before = json.dumps(
        [item.model_dump(mode="json", exclude={"full_log"}) for item in alerts],
        default=str,
    )
    after = json.dumps(
        {
            "rule_summary": _rule_rollup(alerts),
            "alerts": [
                _compact_alert(item, drop_rule_metadata=True) for item in alerts
            ],
        },
        default=str,
    )
    assert len(after) < len(before) * 0.6
