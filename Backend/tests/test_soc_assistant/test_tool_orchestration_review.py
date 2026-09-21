"""Verification for the tool-orchestration review: availability, prompt
discipline, metric accuracy, evidence preservation, and validation recovery.

These exercise the real SOCAnalyst.answer() pipeline against a scripted,
local chat model (no network, no live LLM) so the wiring - tool binding,
budget accounting, evidence extraction - is verified end to end. What a real
model chooses to call is not something a scripted trace can prove; these
confirm the pipeline does not force or block any particular choice.
"""

import json

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from app.config import settings
from app.db.repositories.reports import InMemoryReportRepository
from app.soc_assistant.tool_agent import (
    SYSTEM_PROMPT,
    SOCAnalyst,
    _AdaptiveSpecializedAccess,
    _clip,
    _select_agent_tools,
    _ToolCallBudget,
    build_tools,
)


class ScriptedModel(BaseChatModel):
    """A local, deterministic stand-in for the chat model - no network calls."""

    replies: list[AIMessage]

    @property
    def _llm_type(self):
        return "local-scripted-test"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, **kwargs):
        return ChatResult(generations=[ChatGeneration(message=self.replies.pop(0))])


def budgeted_clip(value):
    budget = _ToolCallBudget(1)

    class Request:
        tool_call = {"name": "search_alerts", "args": {}, "id": "clip-1"}

    def execute(request):
        return ToolMessage(
            content=_clip(value),
            name="search_alerts",
            tool_call_id=request.tool_call["id"],
        )

    result = budget(Request(), execute)
    return result.content, budget.evidence_ledger[0]


def test_a_plain_overview_can_cite_wazuhs_own_rule_description_without_enrichment():
    """Priority 2: the prompt permits citing rule_summary/by_rule directly."""
    assert "report the rule_summary/by_rule" in SYSTEM_PROMPT
    assert "not call rule_mitre_context or a MITRE lookup for" in SYSTEM_PROMPT
    assert "every rule_id first" in SYSTEM_PROMPT
    # The original evidence-discipline rule this builds on must survive.
    assert "A rule ID is not a description" in SYSTEM_PROMPT
    tools = {
        t.name: t
        for t in build_tools(
            None,
            report_repository=InMemoryReportRepository(),
            investigations=None,
            organization_id="org",
            created_by="analyst",
            conversation_id=None,
        )
    }
    assert "carry the rule's own description and groups" in tools["rule_mitre_context"].description
    assert "instead of calling this for every rule_id" in tools["rule_mitre_context"].description


def test_simple_alert_overview_completes_without_a_mitre_lookup(monkeypatch):
    """A scripted trace where the model answers straight from search_alerts'
    own rule_summary, never calling rule_mitre_context, still resolves to a
    grounded answer with a minimal tool budget - the pipeline does not
    require enrichment to complete a basic overview."""

    class Gateway:
        def __init__(self):
            self.calls = []

        def search_alerts(self, **filters):
            self.calls.append(filters)
            from app.services.wazuh.models import AlertEvidence, AlertSearchResult
            from datetime import UTC, datetime

            alert = AlertEvidence(
                alert_id="alert-9",
                timestamp=datetime(2026, 9, 18, tzinfo=UTC),
                rule_id="5712",
                rule_level=5,
                rule_description="SSHD authentication failed.",
                description="SSHD authentication failed.",
            )
            return AlertSearchResult(total=1, returned=1, truncated=False, alerts=[alert])

    class LLM:
        def get_client(self):
            return ScriptedModel(
                replies=[
                    AIMessage(
                        content="",
                        tool_calls=[{"id": "c1", "name": "search_alerts", "args": {}}],
                    ),
                    AIMessage(
                        content=(
                            "One alert, alert-9: rule 5712, \"SSHD authentication "
                            "failed.\" per Wazuh's rule description."
                        )
                    ),
                ]
            )

    gateway = Gateway()
    agent = SOCAnalyst(
        gateway=gateway,
        llm=LLM(),
        report_repository=InMemoryReportRepository(),
        investigations=object(),
    )

    result = agent.answer(question="show me the alerts", history=[], organization_id="system")

    assert result.tool_calls == ["search_alerts"]
    assert "rule_mitre_context" not in result.tool_calls
    assert result.metrics["tool_calls_executed"] == 1
    assert result.grounded is True


def test_open_ended_host_investigation_can_reach_correlation_tools_without_keywords():
    """Priority 1: availability is not gated on the opening message's words."""
    tools = build_tools(
        None,
        report_repository=InMemoryReportRepository(),
        investigations=None,
        organization_id="org",
        created_by="analyst",
        conversation_id=None,
    )
    question = "What's going on with agent 007 right now?"
    assert not any(
        hint in question.lower()
        for hint in ("correlat", "sequence", "attack chain", "parent process")
    )
    selected = {
        t.name for t in _select_agent_tools(question, tools, allow_state_changes=False)
    }
    assert {"correlated_alerts", "get_alert", "threat_hunt", "get_agent_context"} <= selected


def test_a_lead_discovered_mid_investigation_is_pursued_without_a_scripted_classifier():
    """A second-round tool choice driven by what round one returned, not by
    a hardcoded per-topic branch keyed on the opening question's wording."""

    class Gateway:
        def __init__(self):
            self.calls = []

        def threat_hunt(self, **filters):
            self.calls.append(("hunt", filters))
            return {
                "total": 1,
                "returned": 1,
                "truncated": False,
                "alerts": [
                    {
                        "alert_id": "raw-1",
                        "timestamp": "2026-09-18T14:11:32+00:00",
                        "agent_id": "001",
                        "process": {"executable": "/usr/bin/tcpdump"},
                    }
                ],
            }

    class LLM:
        def get_client(self):
            return ScriptedModel(
                replies=[
                    AIMessage(
                        content="",
                        tool_calls=[{"id": "c1", "name": "threat_hunt", "args": {"agent_id": "001"}}],
                    ),
                    AIMessage(
                        content="",
                        tool_calls=[{
                            "id": "c2",
                            "name": "correlated_alerts",
                            "args": {
                                "agent_id": "001",
                                "timestamp": "2026-09-18T14:11:32+00:00",
                            },
                        }],
                    ),
                    AIMessage(
                        content=(
                            "Alert raw-1 (tcpdump) on agent 001 sits inside a "
                            "correlated sequence confirming no privilege change."
                        )
                    ),
                ]
            )

    gateway = Gateway()
    agent = SOCAnalyst(
        gateway=gateway,
        llm=LLM(),
        report_repository=InMemoryReportRepository(),
        investigations=object(),
    )
    question = "What's happening on agent 001 right now?"
    result = agent.answer(question=question, history=[], organization_id="system")

    assert {"threat_hunt", "correlated_alerts"} <= set(result.tool_calls)
    assert len(gateway.calls) == 2


def test_invalid_timestamp_is_a_recoverable_structured_error_not_a_stall():
    """Priority 5, end to end: a bad first attempt does not end the turn -
    the model can read the error and retry with a fixed argument."""

    class Gateway:
        def __init__(self):
            self.calls = []

        def threat_hunt(self, **filters):
            self.calls.append(filters)
            return {"total": 0, "returned": 0, "truncated": False, "alerts": []}

    class LLM:
        def get_client(self):
            return ScriptedModel(
                replies=[
                    AIMessage(
                        content="",
                        tool_calls=[{
                            "id": "c1",
                            "name": "correlated_alerts",
                            "args": {"agent_id": "001", "timestamp": "2026-09-18T14:11:30"},
                        }],
                    ),
                    AIMessage(
                        content="",
                        tool_calls=[{
                            "id": "c2",
                            "name": "correlated_alerts",
                            "args": {
                                "agent_id": "001",
                                "timestamp": "2026-09-18T14:11:30+00:00",
                            },
                        }],
                    ),
                    AIMessage(content="No related alerts in the correlation window."),
                ]
            )

    agent = SOCAnalyst(
        gateway=Gateway(),
        llm=LLM(),
        report_repository=InMemoryReportRepository(),
        investigations=object(),
    )
    result = agent.answer(
        question="Correlate what happened around that time on agent 001",
        history=[],
        organization_id="system",
    )

    assert result.tool_calls == ["correlated_alerts", "correlated_alerts"]
    # The first, invalid call is not a failure - the tool answered with data
    # the model corrected from, so it is not in the disclosed failure list.
    assert result.failed_tools == []
    assert result.metrics["tool_calls_executed"] == 1
    assert result.metrics["tool_validation_errors"] == 1
    assert result.metrics["tool_calls_successful"] == 1


def test_evidence_references_survive_singular_and_plural_shapes():
    """Priority 4: evidence_ref, *_evidence_ref, *_evidence_refs and the
    flat evidence_references list must all be extracted, not just the bare
    singular key."""
    payload = json.dumps(
        {
            "evidence_references": ["wazuh:alert:a1", "wazuh:alert:a2"],
            "observations": {
                "success_after_failures_exact_match": [
                    {
                        "success_evidence_ref": "wazuh:alert:a3",
                        "failure_evidence_refs": ["wazuh:alert:a4", "wazuh:alert:a5"],
                    }
                ]
            },
            "timeline": [{"evidence_ref": "wazuh:alert:a6"}],
        }
    )
    refs = SOCAnalyst._evidence_refs_from_tool_result(payload)
    assert set(refs) == {
        "wazuh:alert:a1",
        "wazuh:alert:a2",
        "wazuh:alert:a3",
        "wazuh:alert:a4",
        "wazuh:alert:a5",
        "wazuh:alert:a6",
    }


def test_thirty_four_summary_references_survive_clipping_and_extraction(monkeypatch):
    references = [f"wazuh:alert:alert-{index:02d}" for index in range(34)]
    rendered = _clip(
        {
            "coverage": {
                "matched": 34,
                "returned": 34,
                "truncated": False,
                "status": "complete",
            },
            "counts": {"by_rule_id": {"5712": 34}},
            "evidence_references": references,
        }
    )

    assert SOCAnalyst._evidence_refs_from_tool_result(rendered) == references

    from langchain_core.messages import ToolMessage

    class FakeAgent:
        def invoke(self, *_args, **_kwargs):
            return {
                "messages": [
                    ToolMessage(
                        content=rendered,
                        name="summarize_alert_activity",
                        tool_call_id="summary-1",
                    ),
                    AIMessage(content="Relevant events: alert-00 and alert-33."),
                ]
            }

    monkeypatch.setattr(
        "app.soc_assistant.tool_agent.create_react_agent",
        lambda *args, **kwargs: FakeAgent(),
    )

    class LLM:
        def get_client(self):
            return object()

    result = SOCAnalyst(
        gateway=None,
        llm=LLM(),
        report_repository=InMemoryReportRepository(),
        investigations=None,
    ).answer(question="summarize these alerts", history=[])

    assert result.retrieved_evidence_references == references
    assert result.evidence_references == [references[0], references[-1]]
    assert result.metrics["evidence_retrieved"] == 34
    assert result.metrics["evidence_cited"] == 2

    _content, ledger = budgeted_clip(json.loads(rendered))
    assert ledger["source_evidence_references"] == references
    assert ledger["delivered_evidence_references"] == references
    assert ledger["delivery_status"] == "complete"
    assert ledger["summary_or_aggregate"] is True
    assert ledger["delivered_event_detail_references"] == []
    assert ledger["delivered_reference_only_references"] == references


def test_oversized_result_keeps_structured_provenance_and_truthful_coverage(monkeypatch):
    monkeypatch.setattr(settings, "SOC_ANALYST_MAX_TOOL_OUTPUT_CHARS", 1000)
    alerts = [
        {
            "alert_id": f"large-{index:02d}",
            "full_log": "x" * 1000,
        }
        for index in range(34)
    ]

    payload = json.loads(
        _clip(
            {
                "coverage": {
                    "matched": 80,
                    "returned": 34,
                    "truncated": True,
                    "status": "partial",
                },
                "alerts": alerts,
            }
        )
    )

    provenance = payload["_provenance"]
    assert provenance["source_evidence_reference_count"] == 34
    assert provenance["delivered_evidence_references"] == []
    assert provenance["undelivered_evidence_reference_count"] == 34
    assert payload["coverage"]["matched"] == 80
    assert payload["coverage"]["source_returned"] == 34
    assert payload["coverage"]["search_status"] == "partial"
    assert payload["coverage"]["output_truncated"] is True

    class FakeAgent:
        def invoke(self, *_args, **_kwargs):
            return {
                "messages": [
                    ToolMessage(
                        content=json.dumps(payload),
                        name="search_alerts",
                        tool_call_id="oversized-1",
                    ),
                    AIMessage(content="The delivered evidence includes large-00."),
                ]
            }

    monkeypatch.setattr(
        "app.soc_assistant.tool_agent.create_react_agent",
        lambda *args, **kwargs: FakeAgent(),
    )

    class LLM:
        def get_client(self):
            return object()

    result = SOCAnalyst(
        gateway=None,
        llm=LLM(),
        report_repository=InMemoryReportRepository(),
        investigations=None,
    ).answer(question="inspect the oversized result", history=[])

    assert result.metrics["query_coverage_status"] == "partial"
    assert result.metrics["investigation_status"] == "complete"
    assert result.metrics["evidence_retrieved"] == 0
    assert result.evidence_references == []

    _content, ledger = budgeted_clip(
        {
            "coverage": {
                "matched": 80,
                "returned": 34,
                "truncated": True,
                "status": "partial",
            },
            "alerts": alerts,
        }
    )
    assert ledger["source_evidence_reference_count"] == 34
    assert ledger["delivered_evidence_reference_count"] == 0
    assert ledger["delivery_status"] == "compact_fallback"
    assert ledger["evidence_delivery_kinds"] == ["none"]


def test_partial_clip_counts_only_retained_event_details_as_delivered(monkeypatch):
    monkeypatch.setattr(settings, "SOC_ANALYST_MAX_TOOL_OUTPUT_CHARS", 2200)
    rendered = _clip(
        {
            "coverage": {
                "matched": 12,
                "returned": 12,
                "truncated": False,
                "status": "complete",
            },
            "alerts": [
                {
                    "alert_id": f"partial-{index}",
                    "timestamp": f"2026-09-18T14:{index:02d}:00+00:00",
                    "description": "x" * 180,
                }
                for index in range(12)
            ],
        }
    )
    payload = json.loads(rendered)
    retained = [f"wazuh:alert:{item['alert_id']}" for item in payload["alerts"]]

    assert 0 < len(retained) < 12
    assert payload["_provenance"]["source_evidence_reference_count"] == 12
    assert payload["_provenance"]["delivered_evidence_references"] == retained
    assert SOCAnalyst._evidence_refs_from_tool_result(rendered) == retained

    _content, ledger = budgeted_clip(
        {
            "coverage": {
                "matched": 12,
                "returned": 12,
                "truncated": False,
                "status": "complete",
            },
            "alerts": [
                {
                    "alert_id": f"partial-{index}",
                    "timestamp": f"2026-09-18T14:{index:02d}:00+00:00",
                    "description": "x" * 180,
                }
                for index in range(12)
            ],
        }
    )
    assert ledger["source_evidence_reference_count"] == 12
    assert ledger["delivered_evidence_references"] == retained
    assert ledger["delivered_event_detail_references"] == retained
    assert ledger["delivered_reference_only_references"] == []


def test_reference_only_id_is_not_counted_as_examined_or_citable(monkeypatch):
    class FakeAgent:
        def invoke(self, *_args, **_kwargs):
            return {
                "messages": [
                    ToolMessage(
                        content=json.dumps(
                            {"alerts": [{"alert_id": "reference-only"}]}
                        ),
                        name="search_alerts",
                        tool_call_id="reference-only-1",
                    ),
                    AIMessage(content="The ID is reference-only."),
                ]
            }

    monkeypatch.setattr(
        "app.soc_assistant.tool_agent.create_react_agent",
        lambda *args, **kwargs: FakeAgent(),
    )

    class LLM:
        def get_client(self):
            return object()

    result = SOCAnalyst(
        gateway=None,
        llm=LLM(),
        report_repository=InMemoryReportRepository(),
        investigations=None,
    ).answer(question="inspect the alert", history=[])

    assert result.retrieved_evidence_references == [
        "wazuh:alert:reference-only"
    ]
    assert result.evidence_references == []
    assert result.metrics["event_details_examined"] == 0
    assert result.metrics["queries"] == []


def test_trimmed_specialized_tool_remains_discoverable_and_invokable(monkeypatch):
    class Gateway:
        def get_sca_evidence(self, **arguments):
            return {
                "total": 1,
                "returned": 1,
                "items": [{"evidence_id": "sca-1", **arguments}],
            }

    tools = build_tools(
        Gateway(),
        report_repository=InMemoryReportRepository(),
        investigations=object(),
        organization_id="org",
        created_by="analyst",
        conversation_id=None,
    )
    adaptive = _AdaptiveSpecializedAccess(tools)
    monkeypatch.setattr(
        "app.soc_assistant.tool_agent._tool_schema_token_budget", lambda: 1
    )
    selected = _select_agent_tools(
        "a new lead surfaced",
        [*tools, adaptive.tool],
        allow_state_changes=False,
    )
    selected_names = {item.name for item in selected}
    assert "specialized_capability" in selected_names
    assert "sca_failed_checks" not in selected_names

    discovered = json.loads(
        adaptive.tool.invoke({"action": "discover", "query": "failed SCA checks"})
    )
    assert any(item["name"] == "sca_failed_checks" for item in discovered["matches"])

    invoked = json.loads(
        adaptive.tool.invoke(
            {
                "action": "invoke",
                "capability": "sca_failed_checks",
                "arguments": {"agent_id": "001", "policy_id": "cis_linux"},
            }
        )
    )
    assert invoked["total"] == 1
    assert adaptive.metrics()["events"][1]["capability"] == "sca_failed_checks"


def test_json_error_is_not_cached_as_success_and_validation_can_retry():
    budget = _ToolCallBudget(1)

    class Request:
        def __init__(self, call_id, value):
            self.tool_call = {
                "name": "correlated_alerts",
                "args": {"timestamp": value},
                "id": call_id,
            }

    def invalid(request):
        from langchain_core.messages import ToolMessage

        return ToolMessage(
            content=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "INVALID_TOOL_INPUT",
                        "message": "timezone required",
                        "retryable": True,
                    },
                }
            ),
            name="correlated_alerts",
            tool_call_id=request.tool_call["id"],
        )

    def valid(request):
        from langchain_core.messages import ToolMessage

        return ToolMessage(
            content=json.dumps({"total": 0, "returned": 0, "alerts": []}),
            name="correlated_alerts",
            tool_call_id=request.tool_call["id"],
        )

    first = budget(Request("bad", "no-zone"), invalid)
    second = budget(Request("fixed", "2026-09-18T14:11:30+00:00"), valid)

    assert first.status == "error"
    assert second.status == "success"
    assert budget.attempted == 2
    assert budget.used == 1
    assert budget.validation_errors == 1
    assert budget.successful == 1
    assert budget.cache_hits == 0


def test_source_failure_is_counted_separately_and_never_cached():
    budget = _ToolCallBudget(2)
    executions = []

    class Request:
        def __init__(self, call_id):
            self.tool_call = {
                "name": "search_alerts",
                "args": {"hours": 2},
                "id": call_id,
            }

    def unavailable(request):
        from langchain_core.messages import ToolMessage

        executions.append(request.tool_call["id"])
        return ToolMessage(
            content=json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "WAZUH_UNAVAILABLE",
                        "message": "source unavailable",
                        "retryable": True,
                    },
                }
            ),
            name="search_alerts",
            tool_call_id=request.tool_call["id"],
        )

    budget(Request("first"), unavailable)
    budget(Request("second"), unavailable)

    assert executions == ["first", "second"]
    assert budget.source_failures == 2
    assert budget.successful == 0
    assert budget.cache_hits == 0


def test_retrieved_evidence_is_tracked_separately_from_cited_evidence(monkeypatch):
    """Priority 4: retrieved (everything a tool returned) and cited (what
    the final answer actually references) are two different counts."""
    from langchain_core.messages import AIMessage as _AI, ToolMessage

    class FakeAgent:
        def invoke(self, *_args, **_kwargs):
            return {
                "messages": [
                    ToolMessage(
                        content=json.dumps(
                            {
                                "total": 2,
                                "returned": 2,
                                "alerts": [
                                    {
                                        "alert_id": "cited-1",
                                        "timestamp": "2026-09-20T10:00:00Z",
                                        "description": "Delivered event one",
                                    },
                                    {
                                        "alert_id": "not-cited-2",
                                        "timestamp": "2026-09-20T10:01:00Z",
                                        "description": "Delivered event two",
                                    },
                                ],
                            }
                        ),
                        name="search_alerts",
                        tool_call_id="call-1",
                    ),
                    _AI(content="Only cited-1 is relevant here."),
                ]
            }

    monkeypatch.setattr(
        "app.soc_assistant.tool_agent.create_react_agent",
        lambda *args, **kwargs: FakeAgent(),
    )

    class LLM:
        def get_client(self):
            return object()

    agent = SOCAnalyst(
        gateway=None,
        llm=LLM(),
        report_repository=InMemoryReportRepository(),
        investigations=None,
    )
    result = agent.answer(question="what happened?", history=[])

    assert result.metrics["evidence_retrieved"] == 2
    assert result.metrics["evidence_references"] == 1
    assert result.metrics["event_details_examined"] == 2
    assert result.metrics["grounding_status"] == "cited"
    assert result.metrics["citation_scope"] == "reference_level_only"
    assert result.evidence_references == ["wazuh:alert:cited-1"]


def test_tool_call_metrics_distinguish_attempted_from_executed(monkeypatch):
    """Priority 3, literally: seven ToolMessages against a budget of four
    must not be reported as four - or seven - successful executions."""
    monkeypatch.setattr(settings, "SOC_ANALYST_MAX_TOOL_CALLS", 4)

    class Gateway:
        def __init__(self):
            self.calls = []

        def get_agent_summary(self, agent_id):
            self.calls.append(agent_id)
            return None

    class LLM:
        def get_client(self):
            return ScriptedModel(
                replies=[
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "id": f"call-{i}",
                                "name": "agent_status",
                                "args": {"agent_id": f"{i:03d}"},
                            }
                            for i in range(7)
                        ],
                    ),
                    AIMessage(content="Checked the requested agents."),
                ]
            )

    gateway = Gateway()
    agent = SOCAnalyst(
        gateway=gateway,
        llm=LLM(),
        report_repository=InMemoryReportRepository(),
        investigations=object(),
    )
    result = agent.answer(question="check these agents", history=[], organization_id="system")

    metrics = result.metrics
    assert metrics["tool_calls"] == 7
    assert metrics["tool_calls_attempted"] == 7
    assert metrics["tool_calls_executed"] == 4
    assert metrics["tool_calls_rejected"] == 3
    assert metrics["tool_calls_cache_hits"] == 0
    # The number of ToolMessages is not the number of successful executions.
    assert metrics["tool_calls_executed"] != metrics["tool_calls"]
    assert len(gateway.calls) == 4


def test_cache_hits_are_not_counted_as_fresh_executions():
    budget = _ToolCallBudget(5)
    executions = []

    class Request:
        def __init__(self, call_id):
            self.tool_call = {
                "name": "search_alerts",
                "args": {"hours": 24},
                "id": call_id,
            }

    def execute(request):
        executions.append(1)
        from langchain_core.messages import ToolMessage

        return ToolMessage(
            content=json.dumps({"total": 1, "returned": 1, "alerts": []}),
            name="search_alerts",
            tool_call_id=request.tool_call["id"],
        )

    budget(Request("a"), execute)
    budget(Request("b"), execute)  # same args as "a": served from cache

    assert budget.attempted == 2
    assert budget.used == 1
    assert budget.cache_hits == 1
    assert len(executions) == 1
