"""Checks for the tool-calling agent's tool wrappers, especially save_report."""

import json

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.errors import GraphRecursionError

from app.db.repositories.reports import InMemoryReportRepository
from app.soc_assistant.tool_agent import (
    SOCToolAgent,
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

    answer, tool_calls, active_alert_id = agent.answer(
        question="analyze everything", history=[]
    )

    assert tool_calls == []
    assert active_alert_id is None
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

    answer, tool_calls, _ = agent.answer(question="save a report", history=[])

    assert tool_calls == ["save_report"]
    assert "Tool failure" in answer
    assert "`save_report`" in answer


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
