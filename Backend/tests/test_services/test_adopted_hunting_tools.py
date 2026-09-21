"""Read-only prototype adoption, pinned windows and evidence preservation."""

import json
from datetime import datetime

import pytest
from langchain_core.messages import HumanMessage

from app.db.repositories.reports import InMemoryReportRepository
from app.services.wazuh.exceptions import WazuhAPIError
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.indexer_client import WazuhIndexerClient
from app.soc_assistant.tool_agent import (
    READ_ONLY_TOOLS, SYSTEM_PROMPT, _bounded_analyst_prompt, _select_agent_tools, build_tools,
)


class Search:
    def __init__(self, aggregations=None, total=0, hits=(), **extra):
        self.response = {"hits": {"total": {"value": total, "relation": "eq"}, "hits": list(hits)},
                         "aggregations": aggregations or {}, **extra}
        self.calls = []

    def search(self, index, body, **options):
        self.calls.append((index, body))
        return self.response


class Server:
    def __init__(self, items=(), total=None):
        self.items = list(items)
        self.total = len(self.items) if total is None else total
        self.calls = []

    def get(self, path, params=None):
        self.calls.append((path, params))
        return {"data": {"affected_items": self.items, "total_affected_items": self.total}}


def tools(gateway):
    return {item.name: item for item in build_tools(
        gateway, report_repository=InMemoryReportRepository(), investigations=None,
        organization_id="org-1", created_by="user-1", conversation_id="conv-1",
    )}


def test_sca_failed_checks_preserve_native_remediation_and_pagination():
    server = Server([{"id": 123, "title": "Disable root SSH login", "result": "failed",
                      "rationale": "Restrict privileged remote access", "remediation": "Set PermitRootLogin no",
                      "compliance": {"cis": "5.2.10"}, "unrelated": "omit"}], total=12)
    result = json.loads(tools(WazuhGateway(server=server, indexer=object()))["sca_failed_checks"].invoke(
        {"agent_id": "001", "policy_id": "cis_ubuntu24-04", "limit": 10},
    ))
    assert server.calls == [("/sca/001/checks/cis_ubuntu24-04", {"limit": 10, "offset": 0, "result": "failed"})]
    assert result["items"][0]["remediation"] == "Set PermitRootLogin no"
    assert result["items"][0]["evidence_ref"] == "wazuh:sca:001:cis_ubuntu24-04:123"
    assert "unrelated" not in result["items"][0]
    assert result["coverage"]["status"] == "partial" and result["next_offset"] == 1


@pytest.mark.parametrize("filters", [{"policy_id": "../../security"}, {"agent_id": "001/config"},
                                      {"limit": 51}, {"offset": -1}])
def test_invalid_sca_arguments_never_reach_server(filters):
    server = Server()
    with pytest.raises(ValueError):
        WazuhGateway(server=server, indexer=object()).get_sca_evidence(**({"agent_id": "001"} | filters))
    assert not server.calls


def test_mitre_keyword_search_keeps_external_id_distinct_from_stix_id():
    server = Server([{"id": "attack-pattern--uuid", "external_id": "T1040", "name": "Network Sniffing"}])
    result = WazuhGateway(server=server, indexer=object()).search_mitre_catalog(keyword="sniffing")
    assert server.calls == [("/mitre/techniques", {"search": "sniffing", "limit": 10})]
    assert result["items"][0]["external_id"] == "T1040"
    assert "not observed" in result["scope"]
    with pytest.raises(ValueError):
        WazuhGateway(server=server, indexer=object()).search_mitre_catalog(keyword="x", resource="../agents")


def test_baseline_is_one_query_with_disjoint_windows_and_normalized_rates():
    search = Search({"current": {"doc_count": 12}, "baseline": {"doc_count": 24}}, total=36)
    result = WazuhIndexerClient(client=search).alert_statistics(
        mode="baseline", hours=1, baseline_hours=6, agent_id="001", rule_id="80792",
    )
    index, body = search.calls[0]
    assert index == "wazuh-alerts-*" and body["size"] == 0 and body["track_total_hits"]
    assert {"term": {"agent.id": "001"}} in body["query"]["bool"]["must"]
    assert {"term": {"rule.id": "80792"}} in body["query"]["bool"]["must"]
    current = body["aggs"]["current"]["filter"]["range"]["@timestamp"]
    baseline = body["aggs"]["baseline"]["filter"]["range"]["@timestamp"]
    assert baseline["lt"] == current["gte"]
    assert (datetime.fromisoformat(baseline["lt"]) - datetime.fromisoformat(baseline["gte"])).total_seconds() == 6 * 3600
    assert result["comparison"]["current_per_hour"] == 12
    assert result["comparison"]["baseline_per_hour"] == 4
    assert result["comparison"]["rate_ratio"] == 3


def test_zero_baseline_is_not_infinite_ratio_or_never_seen_claim():
    search = Search({"current": {"doc_count": 5}, "baseline": {"doc_count": 0}}, total=5)
    result = WazuhIndexerClient(client=search).alert_statistics(mode="baseline")
    assert result["comparison"]["rate_ratio"] is None
    assert result["comparison"]["baseline_zero"] is True


def test_timeline_is_compact_and_clipping_marks_series_coverage_partial(monkeypatch):
    from app.config import settings
    from app.soc_assistant.tool_agent import _clip

    search = Search({"timeline": {"buckets": [
        {"key": number, "key_as_string": f"2026-09-18T14:{number:02d}:00Z", "doc_count": 2}
        for number in range(60)
    ]}}, total=120)
    result = WazuhIndexerClient(client=search).alert_statistics(mode="timeline", hours=1, interval_minutes=1)
    assert len(result["series"]) == 60
    assert "aggregations" not in result and "key" not in result["series"][0]
    histogram = search.calls[0][1]["aggs"]["timeline"]["date_histogram"]
    assert histogram["min_doc_count"] == 0 and "extended_bounds" in histogram
    monkeypatch.setattr(settings, "SOC_ANALYST_MAX_TOOL_OUTPUT_CHARS", 1000)
    clipped = json.loads(_clip(result))
    assert clipped["coverage"]["status"] == "partial"
    assert clipped["truncated"] is True


@pytest.mark.parametrize("filters", [{"mode": "raw"}, {"mode": "baseline", "hours": 168},
                                      {"mode": "timeline", "hours": 168, "interval_minutes": 1},
                                      {"mode": "timeline", "min_level": 17}])
def test_analytics_rejects_unbounded_or_unknown_parameters(filters):
    search = Search()
    with pytest.raises(ValueError):
        WazuhIndexerClient(client=search).alert_statistics(**filters)
    assert not search.calls


@pytest.mark.parametrize("extra", [{"timed_out": True}, {"_shards": {"failed": 1}},
                                    {"hits": {"total": {"value": 10000, "relation": "gte"}}}])
def test_analytics_failure_is_not_zero_matches(extra):
    search = Search()
    search.response.update(extra)
    with pytest.raises(WazuhAPIError):
        WazuhIndexerClient(client=search).alert_statistics(mode="timeline")


def test_mitre_activity_reports_unmapped_alerts_and_aggregation_errors():
    search = Search({"mapped": {"doc_count": 3},
                     "techniques": {"buckets": [], "sum_other_doc_count": 1, "doc_count_error_upper_bound": 2},
                     "tactics": {"buckets": [], "sum_other_doc_count": 0, "doc_count_error_upper_bound": 0}}, total=10)
    result = WazuhIndexerClient(client=search).alert_statistics(mode="mitre")
    assert result["mapped_alerts"] == 3 and result["unmapped_alerts"] == 7
    assert result["coverage"]["status"] == "partial"
    assert "not detection-gap proof" in result["note"]


def test_ioc_cross_host_summary_is_indexer_computed_not_sample_counts():
    search = Search({"agents": {"sum_other_doc_count": 0, "doc_count_error_upper_bound": 0,
                     "buckets": [{"key": "001", "doc_count": 88, "doc_count_error_upper_bound": 0,
                                  "first_seen": {"value_as_string": "2026-09-18T14:00:00Z"},
                                  "last_seen": {"value_as_string": "2026-09-18T14:20:00Z"},
                                  "name": {"hits": {"hits": [{"_source": {"agent": {"name": "linux-vm-atomic"}}}]}}}]}}, total=88)
    result = WazuhIndexerClient(client=search).ioc_agent_summary(indicator="tcpdump", indicator_type="process")
    assert result["agents"][0]["count"] == 88 and result["agents"][0]["hostname"] == "linux-vm-atomic"
    assert result["total_alerts"] == 88 and result["coverage"]["status"] == "complete"
    assert search.calls[0][1]["size"] == 0


def test_correlation_preserves_distinct_commands_with_same_description():
    hits = [{"_id": ident, "_index": "wazuh-alerts-test", "_source": {
        "@timestamp": f"2026-09-18T14:11:{second}Z", "agent": {"id": "001"},
        "rule": {"description": "Process execution observed"},
        "data": {"win": {"eventdata": {"image": command, "commandLine": command + " --test"}}},
    }} for ident, second, command in [("tcpdump-id", "30", "tcpdump"), ("ping-id", "31", "ping")]]
    search = Search(hits=hits, total=2)
    wrapper = tools(WazuhGateway(server=object(), indexer=WazuhIndexerClient(client=search)))["correlated_alerts"]
    result = json.loads(wrapper.invoke({"agent_id": "001", "timestamp": "2026-09-18T14:11:30Z"}))
    assert [item["alert_id"] for item in result["alerts"]] == ["tcpdump-id", "ping-id"]
    assert [item["process"]["command_line"] for item in result["alerts"]] == ["tcpdump --test", "ping --test"]

    invalid = json.loads(
        wrapper.invoke({"agent_id": "001", "timestamp": "2026-09-18T14:11:30"})
    )
    # A bad argument comes back as data the model can read and retry from,
    # not a raised exception it has no way to recover from mid-conversation.
    assert invalid["ok"] is False
    assert invalid["error"]["code"] == "INVALID_TOOL_INPUT"
    assert invalid["error"]["field"] == "timestamp"
    assert "timezone" in invalid["error"]["message"]
    assert invalid["error"]["retryable"] is True


def test_compact_prompt_and_task_selection_preserve_read_only_boundary():
    available = list(tools(None).values())
    cases = [("Harden agent 001 using SCA", {"sca_policy_summary", "sca_failed_checks"}),
             ("Compare unusual spikes on agent 001", {"compare_alert_windows"}),
             ("Show MITRE coverage overview", {"mitre_attack_coverage", "mitre_search"}),
             ("Correlate the attack chain on agent 001", {"correlated_alerts", "get_alert"})]
    for question, required in cases:
        selected = _select_agent_tools(question, available, allow_state_changes=False)
        names = {item.name for item in selected}
        assert required <= names <= READ_ONLY_TOOLS
        assert "save_report" not in names and "raw_alert_query" not in names
        _bounded_analyst_prompt(selected)({"messages": [HumanMessage(content=question)]})
    assert len(SYSTEM_PROMPT) < 5500
    assert "never invent a fixed version" in SYSTEM_PROMPT
