"""Regression cover for evidence coverage and grounding claims.

A tool having run is not evidence. What the analyst may claim depends on how
much of the matching population it actually saw, so the coverage the tool
reported is carried through to the response metadata rather than inferred from
the model's own prose.
"""

import json

from langchain_core.messages import AIMessage, ToolMessage

from app.db.repositories.reports import InMemoryReportRepository
from app.services.wazuh.models import AlertSearchResult
from app.soc_assistant.tool_agent import (
    SYSTEM_PROMPT,
    SOCAnalyst,
    _clip,
    _safe_tool_error,
    _tool_miss,
    _ToolCallBudget,
    build_tools,
)


class FakeLLM:
    def get_client(self):
        return object()


def analyst(monkeypatch, messages):
    class FakeAgent:
        def invoke(self, *_args, **_kwargs):
            return {"messages": messages}

    monkeypatch.setattr(
        "app.soc_assistant.tool_agent.create_react_agent",
        lambda *args, **kwargs: FakeAgent(),
    )
    return SOCAnalyst(
        gateway=None,
        llm=FakeLLM(),
        report_repository=InMemoryReportRepository(),
        investigations=None,
    )


def search_result(total: int, returned: int, alert_id: str = "alert-1") -> str:
    return json.dumps(
        {
            "total": total,
            "returned": returned,
            "alerts": [{"alert_id": alert_id, "rule_id": "5712"}],
        }
    )


def test_coverage_is_read_from_a_flat_search_result():
    matched, returned, truncated = SOCAnalyst._coverage_from_tool_result(
        search_result(871, 100)
    )

    assert (matched, returned, truncated) == (871, 100, False)


def test_coverage_is_read_from_a_nested_coverage_block():
    payload = json.dumps(
        {"coverage": {"matched": 42, "returned": 42, "truncated": False}}
    )

    assert SOCAnalyst._coverage_from_tool_result(payload) == (42, 42, False)


def test_sampled_results_are_not_reported_as_full_population(monkeypatch):
    agent = analyst(
        monkeypatch,
        [
            ToolMessage(
                content=search_result(871, 100),
                name="search_alerts",
                tool_call_id="call-1",
            ),
            AIMessage(content="Reviewed alert-1 among the returned sample."),
        ],
    )

    result = agent.answer(question="which IP is behind these?", history=[])

    assert result.metrics["matched_records"] == 871
    assert result.metrics["sampled_records"] == 100
    # Cited real evidence, but over a sample - that is partial, not grounded.
    assert result.metrics["coverage_status"] == "partial"
    assert result.grounded is False


def test_complete_coverage_with_a_citation_is_grounded(monkeypatch):
    agent = analyst(
        monkeypatch,
        [
            ToolMessage(
                content=search_result(3, 3),
                name="search_alerts",
                tool_call_id="call-1",
            ),
            AIMessage(content="All three matches relate to alert-1."),
        ],
    )

    result = agent.answer(question="what happened?", history=[])

    assert result.metrics["coverage_status"] == "grounded"
    assert result.grounded is True
    assert result.evidence_references == ["wazuh:alert:alert-1"]


def test_an_uncited_answer_is_reported_as_ungrounded(monkeypatch):
    agent = analyst(
        monkeypatch,
        [
            ToolMessage(
                content=search_result(3, 3),
                name="search_alerts",
                tool_call_id="call-1",
            ),
            AIMessage(content="Nothing of concern in the environment."),
        ],
    )

    result = agent.answer(question="anything suspicious?", history=[])

    assert result.metrics["coverage_status"] == "ungrounded"
    assert result.grounded is False


def test_unknown_rule_id_returns_an_explicit_miss_not_a_description():
    class GatewayWithoutTheRule:
        def get_rule_and_mitre_context(self, rule_id):
            return None

    tools = {
        item.name: item
        for item in build_tools(
            GatewayWithoutTheRule(),
            report_repository=InMemoryReportRepository(),
            investigations=None,
            organization_id="org-a",
            created_by="analyst-1",
            conversation_id="conv-1",
        )
    }

    result = json.loads(tools["rule_mitre_context"].invoke({"rule_id": "99999"}))

    # Same envelope a runtime tool failure uses, so the model cannot read a
    # miss as data just because it arrived in a different shape.
    assert result == {
        "ok": False,
        "error": {
            "code": "RULE_NOT_FOUND",
            "message": "Rule 99999 not found.",
            "retryable": False,
        },
    }


def test_identical_tool_calls_reuse_evidence_without_spending_budget():
    budget = _ToolCallBudget(5)
    executions = []

    class Request:
        tool_call = {
            "name": "search_alerts",
            "args": {"hours": 24, "min_level": 10},
            "id": "call-1",
        }

    def execute(_request):
        executions.append(1)
        return ToolMessage(
            content=search_result(3, 3),
            name="search_alerts",
            tool_call_id="call-1",
        )

    first = budget(Request(), execute)
    second = budget(Request(), execute)

    assert len(executions) == 1
    assert budget.used == 1
    assert second.content == first.content


def test_a_clamped_argument_is_reported_not_silently_applied():
    class Gateway:
        def __init__(self):
            self.calls = []

        def search_alerts(self, **kwargs):
            self.calls.append(kwargs)
            return AlertSearchResult(
                total=0, returned=0, truncated=False, alerts=[]
            )

    gateway = Gateway()
    tools = {
        item.name: item
        for item in build_tools(
            gateway,
            report_repository=InMemoryReportRepository(),
            investigations=None,
            organization_id="org-a",
            created_by="analyst-1",
            conversation_id="conv-1",
        )
    }

    result = json.loads(
        tools["search_alerts"].invoke({"hours": 720, "limit": 5000})
    )

    # A model that asked for 30 days, silently got 7, and then said "over the
    # last month" is stating something the evidence does not support.
    assert gateway.calls[0]["hours"] == 168
    assert result["query"]["applied"]["hours"] == 168
    assert result["query"]["adjusted"]["hours"]["requested"] == 720
    assert result["query"]["adjusted"]["hours"]["applied"] == 168
    assert "reduced" in result["query"]["note"]


def test_an_in_range_argument_adds_no_adjustment_noise():
    class Gateway:
        def search_alerts(self, **_kwargs):
            return AlertSearchResult(
                total=0, returned=0, truncated=False, alerts=[]
            )

    tools = {
        item.name: item
        for item in build_tools(
            Gateway(),
            report_repository=InMemoryReportRepository(),
            investigations=None,
            organization_id="org-a",
            created_by="analyst-1",
            conversation_id="conv-1",
        )
    }

    result = json.loads(tools["search_alerts"].invoke({"hours": 24}))

    assert result["query"]["applied"]["hours"] == 24
    assert "adjusted" not in result["query"]


def test_truncation_reports_how_many_records_were_dropped():
    payload = {"alerts": [{"alert_id": f"a{index}"} for index in range(400)]}

    result = json.loads(_clip(payload))

    assert result["truncated"] is True
    dropped = result["dropped_records"]["alerts"]
    # "truncated: true" alone cannot support a coverage statement.
    assert dropped == 400 - len(result["alerts"])
    assert dropped > 0


def test_a_miss_and_a_runtime_failure_share_one_envelope():
    miss = json.loads(_tool_miss("RULE_NOT_FOUND", "Rule 1 not found."))
    failure = json.loads(_safe_tool_error(RuntimeError("boom")))

    assert miss["ok"] is False and failure["ok"] is False
    assert set(miss["error"]) == set(failure["error"])


def test_system_prompt_keeps_the_evidence_discipline():
    # These rules are the difference between an assessment and a guess; a
    # prompt edit that drops them should fail here rather than in production.
    for rule in (
        "you are holding a SAMPLE",
        "A rule ID is not a description",
        "queried a comparable earlier window",
        "not evidence of malice",
        "the alert volume is high",
        "backslash-escape Markdown",
    ):
        assert rule in SYSTEM_PROMPT
