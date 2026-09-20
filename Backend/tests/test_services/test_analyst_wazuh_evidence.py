"""Wazuh-documented, bounded MITRE/hunt/vulnerability evidence contracts."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.db.repositories.reports import InMemoryReportRepository
from app.services.wazuh.analyst_evidence import process_evidence
from app.services.wazuh.exceptions import WazuhAPIError
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.indexer_client import WazuhIndexerClient
from app.soc_assistant.tool_agent import READ_ONLY_TOOLS, _bounded_analyst_prompt, _clip, _select_agent_tools, build_tools


class Search:
    def __init__(self, hits=(), total=None, **extra):
        self.response = {"hits": {"total": {"value": len(hits) if total is None else total, "relation": "eq"}, "hits": list(hits)}, **extra}
        self.calls = []

    def search(self, index, body, **options):
        self.calls.append((index, body))
        return self.response


def audit_source(success="yes", with_argv=True):
    command = "icmp and host 127.0.0.1".encode().hex()
    log = 'type=SYSCALL msg=audit(1789740685.024:25109): SYSCALL=execve UID="vboxuser" EUID="root"'
    if with_argv:
        log += ' type=EXECVE msg=audit(1789740685.024:25109): argc=12 a0="sudo" a1="timeout" a2="20s" a3="tcpdump" a4="-i" a5="lo" a6="-nn" a7="-c" a8="5" a9="-w" a10="/tmp/capture.pcap" a11=' + command
    return {
        "@timestamp": "2026-09-18T14:11:25.672Z", "agent": {"id": "001", "name": "linux-vm-atomic"},
        "rule": {"id": "80792", "level": 3}, "full_log": log,
        "data": {"audit": {"exe": "/usr/bin/sudo", "syscall": "59", "pid": "53243", "ppid": "53232", "uid": "1000", "euid": "0", "success": success, "exit": "0" if success == "yes" else "-2"}},
    }


def test_hunt_uses_exact_mitre_and_executable_filters_with_process_evidence():
    search = Search([{"_id": "exact-document-id", "_index": "wazuh-alerts-test", "_source": audit_source()}], total=88)
    result = WazuhIndexerClient(client=search).threat_hunt(agent_id="001", technique="t1040", executable="/usr/bin/sudo")
    index, body = search.calls[0]
    assert index == "wazuh-alerts-*"
    assert {"term": {"rule.mitre.id": "T1040"}} in body["query"]["bool"]["must"]
    assert {"term": {"agent.id": "001"}} in body["query"]["bool"]["must"]
    assert "multi_match" not in json.dumps(body)
    assert body["track_total_hits"] is True
    process = result["alerts"][0]["process"]
    assert process["command_line"] == "sudo timeout 20s tcpdump -i lo -nn -c 5 -w /tmp/capture.pcap 'icmp and host 127.0.0.1'"
    assert process["executable"] == "/usr/bin/sudo"
    assert process["pid"] == "53243" and process["ppid"] == "53232"
    assert process["user"] == "vboxuser" and process["effective_user"] == "root"
    assert result["alerts"][0]["alert_id"] == "exact-document-id"
    assert result["coverage"] == {"matched": 88, "returned": 1, "truncated": True, "status": "partial"}
    assert result["next_offset"] == 1


def test_missing_arguments_are_not_invented_and_failed_launch_is_preserved():
    result = process_evidence(audit_source(success="no", with_argv=False))
    assert result["command_line"] is None
    assert result["argv_complete"] is False
    assert result["execve_success"] == "no"
    assert result["execve_return"] == "-2"


def test_windows_process_evidence_preserves_parent_and_user():
    result = process_evidence({"data": {"win": {"eventdata": {"image": "C:\\Windows\\cmd.exe", "commandLine": "cmd.exe /c whoami", "processId": "12", "parentProcessId": "10", "user": "LAB\\alice"}}}})
    assert result["command_line"] == "cmd.exe /c whoami"
    assert result["ppid"] == "10"
    assert result["user"] == "LAB\\alice"


def test_non_execution_audit_success_is_not_labeled_a_successful_launch():
    result = process_evidence({"data": {"audit": {"exe": "/usr/bin/cat", "syscall": "2", "success": "yes", "exit": "3"}}})
    assert result["execve_success"] is None
    assert result["execve_return"] is None


@pytest.mark.parametrize("extra", [{"timed_out": True}, {"_shards": {"failed": 1}}])
def test_partial_search_cannot_be_reported_as_zero_evidence(extra):
    indexer = WazuhIndexerClient(client=Search(**extra))
    with pytest.raises(WazuhAPIError, match="incomplete"):
        indexer.threat_hunt()
    with pytest.raises(WazuhAPIError, match="incomplete"):
        indexer.vulnerability_evidence()


@pytest.mark.parametrize("filters", [{"technique": "T1040,external_id=T1000"}, {"offset": -1}, {"limit": 201}, {"start_time": datetime.now(UTC)}, {"start_time": datetime.now(UTC), "end_time": datetime.now(UTC) + timedelta(days=8)}, {"start_time": datetime(2026, 9, 1), "end_time": datetime(2026, 9, 2)}])
def test_hunt_invalid_inputs_never_reach_wazuh(filters):
    search = Search()
    with pytest.raises(ValueError):
        WazuhIndexerClient(client=search).threat_hunt(**filters)
    assert search.calls == []


def test_vulnerability_filters_preserve_patch_condition_advisory_and_identifiers():
    source = {"agent": {"id": "002", "name": "Windows"}, "host": {"os": {"name": "Windows 11"}},
              "package": {"name": "Google Chrome", "version": "134.0.6998.118", "type": "win"},
              "vulnerability": {"id": "CVE-2025-4050", "severity": "High", "score": {"base": 8.8}, "detected_at": "2026-09-18T14:00:00Z", "scanner": {"condition": "Package less than 136.0.7103.59", "reference": "https://cti.wazuh.com/vulnerabilities/cves/CVE-2025-4050"}}}
    search = Search([{"_id": "002_pkg_CVE-2025-4050", "_index": "wazuh-states-vulnerabilities-test", "_source": source}])
    result = WazuhIndexerClient(client=search).vulnerability_evidence(severity="high", agent_id="002", cve_id="cve-2025-4050", package_name="Google Chrome")
    index, body = search.calls[0]
    assert index == "wazuh-states-vulnerabilities-*"
    assert body["query"]["bool"]["must"] == [{"term": {"vulnerability.severity": "High"}}, {"term": {"vulnerability.id": "CVE-2025-4050"}}, {"term": {"agent.id": "002"}}, {"term": {"package.name": "Google Chrome"}}]
    item = result["items"][0]
    assert item["package"]["version"] == "134.0.6998.118"
    assert item["vulnerability"]["scanner"]["condition"] == "Package less than 136.0.7103.59"
    assert item["evidence_ref"] == "wazuh:vulnerability:wazuh-states-vulnerabilities-test:002_pkg_CVE-2025-4050"
    assert result["coverage"]["status"] == "complete"


@pytest.mark.parametrize("filters", [{"cve_id": "CVE-2025-4050 OR *"}, {"severity": "severe"}, {"offset": 5001}])
def test_invalid_vulnerability_inputs_are_rejected(filters):
    search = Search()
    with pytest.raises(ValueError):
        WazuhIndexerClient(client=search).vulnerability_evidence(**filters)
    assert search.calls == []


def test_mitre_external_id_and_mitigation_stix_id_are_not_confused():
    class Server:
        def __init__(self):
            self.calls = []

        def get(self, path, params=None):
            self.calls.append((path, params))
            items = [{"id": "attack-pattern--test", "external_id": "T1040", "name": "Network Sniffing", "mitigations": ["course-of-action--test"]}] if path == "/mitre/techniques" else [{"id": "course-of-action--test", "external_id": "M1041", "name": "Encrypt Sensitive Information", "description": "Use encryption."}]
            return {"data": {"affected_items": items, "total_affected_items": len(items)}}

    gateway = WazuhGateway.__new__(WazuhGateway)
    gateway.server = Server()
    result = gateway.get_mitre_technique_context("t1040")
    assert gateway.server.calls == [("/mitre/techniques", {"q": "external_id=T1040", "limit": 1}), ("/mitre/mitigations", {"mitigation_ids": "course-of-action--test", "limit": 10})]
    assert result["mitigations"][0]["description"] == "Use encryption."
    assert "not observed" in result["scope"]


def test_tool_clipping_updates_coverage_and_does_not_skip_records_on_next_page(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "SOC_ANALYST_MAX_TOOL_OUTPUT_CHARS", 1500)
    result = json.loads(_clip({"total": 8, "returned": 8, "offset": 20, "next_offset": 28, "items": [{"evidence_ref": f"vuln-{i}", "description": "x" * 350} for i in range(8)], "coverage": {"matched": 8, "returned": 8, "truncated": False, "status": "complete"}}))
    assert result["returned"] == len(result["items"]) < 8
    assert result["coverage"]["returned"] == result["returned"]
    assert result["coverage"]["status"] == "partial"
    assert result["next_offset"] == 20 + result["returned"]


def test_new_capabilities_are_selected_read_only_and_use_scoped_filters():
    class Gateway:
        def vulnerability_evidence(self, **filters):
            self.filters = filters
            return {"total": 0, "returned": 0, "truncated": False, "items": []}

    gateway = Gateway()
    tools = build_tools(gateway, report_repository=InMemoryReportRepository(), investigations=None, organization_id="org-1", created_by="analyst", conversation_id=None)
    by_name = {t.name: t for t in tools}
    selected = {t.name for t in _select_agent_tools("Hunt MITRE T1040 and fix CVE vulnerabilities", tools, allow_state_changes=False)}
    assert {"threat_hunt", "mitre_technique_context", "hunt_ioc", "vulnerability_overview"} <= selected <= READ_ONLY_TOOLS
    assert "save_report" not in selected
    by_name["vulnerability_overview"].invoke({"agent_id": "002", "cve_id": "CVE-2025-4050", "limit": 999})
    assert gateway.filters["agent_id"] == "002"
    assert gateway.filters["cve_id"] == "CVE-2025-4050"
    assert gateway.filters["limit"] == 100


def test_request_budget_drops_old_history_but_preserves_current_evidence(monkeypatch):
    from app.config import settings
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    monkeypatch.setattr(settings, "MAPEK_MAX_INPUT_TOKENS", 4000)
    monkeypatch.setattr(settings, "LLM_RATE_LIMIT_MAX_TOKENS", 6000)
    monkeypatch.setattr(settings, "LLM_OUTPUT_TOKEN_RESERVE", 1000)
    current = [HumanMessage(content="Hunt T1040"), AIMessage(content="", tool_calls=[{"id": "c1", "name": "threat_hunt", "args": {}}]), ToolMessage(content='{"alert_id":"raw-1"}', tool_call_id="c1")]
    history = [HumanMessage(content="old" * 6000), AIMessage(content="old answer")]
    result = _bounded_analyst_prompt([])({"messages": history + current})
    assert result[1:] == current


def test_current_turn_that_exceeds_budget_is_not_silently_truncated(monkeypatch):
    from app.config import settings
    from app.mape_k.llm import LLMInputLimitError
    from langchain_core.messages import HumanMessage
    monkeypatch.setattr(settings, "MAPEK_MAX_INPUT_TOKENS", 100)
    with pytest.raises(LLMInputLimitError):
        _bounded_analyst_prompt([])({"messages": [HumanMessage(content="Hunt T1040")]})


def test_ioc_archive_result_is_structured_and_unavailable_archive_is_partial():
    from app.services.wazuh.models import AlertEvidence, AlertSearchResult, ArchivedLogSearchResult, IOCHuntResult, RawAlertDocument
    class Gateway:
        def hunt_ioc_telemetry(self, **filters):
            return IOCHuntResult(indicator=filters["indicator"], indicator_type=filters["indicator_type"],
                alerts=AlertSearchResult(total=0, returned=0, truncated=False, alerts=[]),
                archived_logs=ArchivedLogSearchResult(index_pattern="wazuh-archives-*", archive_status="partial", total=1, returned=1, truncated=False,
                    events=[RawAlertDocument(alert_id="archive-1", index_name="wazuh-archives-test", normalized=AlertEvidence(alert_id="archive-1", timestamp=datetime(2026, 9, 18, tzinfo=UTC), rule_id="80792", rule_level=3, description="Audit"), raw_document=audit_source(), raw_document_hash="a" * 64)]))
    tools = {t.name: t for t in build_tools(Gateway(), report_repository=InMemoryReportRepository(), investigations=None, organization_id="system", created_by="test", conversation_id=None)}
    result = json.loads(tools["hunt_ioc"].invoke({"indicator": "tcpdump", "indicator_type": "process"}))
    event = result["archive_events"][0]
    assert event["document_id"] == "archive-1"
    assert event["evidence_ref"] == "wazuh:archive:wazuh-archives-test:archive-1"
    assert event["process"]["command_line"].startswith("sudo timeout")
    assert result["coverage"]["status"] == "partial"


def test_actual_agent_graph_uses_mitre_and_hunt_before_grounded_recommendation():
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from app.soc_assistant.tool_agent import SOCAnalyst

    class ScriptedModel(BaseChatModel):
        replies: list[AIMessage]

        @property
        def _llm_type(self):
            return "local-scripted-test"

        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, messages, **kwargs):
            return ChatResult(generations=[ChatGeneration(message=self.replies.pop(0))])

    class Gateway:
        def __init__(self):
            self.calls = []

        def get_mitre_technique_context(self, technique):
            self.calls.append(("mitre", technique))
            return {"technique_id": technique, "evidence_ref": "wazuh:mitre:T1040", "scope": "reference_catalog", "mitigations": [{"external_id": "M1041", "name": "Encrypt Sensitive Information"}]}

        def threat_hunt(self, **filters):
            self.calls.append(("hunt", filters))
            return {"total": 1, "returned": 1, "truncated": False, "alerts": [{"alert_id": "exact-raw-id", "timestamp": "2026-09-18T14:11:32Z", "agent_id": "001", "process": {"executable": "/usr/bin/tcpdump", "command_line": "tcpdump -nn -r /tmp/capture.pcap"}}]}

    class LLM:
        def get_client(self):
            return ScriptedModel(replies=[
                AIMessage(content="", tool_calls=[{"id": "m1", "name": "mitre_technique_context", "args": {"technique_id": "T1040"}}, {"id": "h1", "name": "threat_hunt", "args": {"agent_id": "001", "executable": "/usr/bin/tcpdump"}}]),
                AIMessage(content="Alert exact-raw-id supports tcpdump readback, not packet capture. T1040 context recommends M1041 encryption. Recommended next steps: confirm authorized use, review encryption coverage, and verify with another bounded hunt. No action executed."),
            ])

    gateway = Gateway()
    reports = InMemoryReportRepository()
    agent = SOCAnalyst(gateway=gateway, llm=LLM(), report_repository=reports, investigations=object())
    result = agent.answer(question="Hunt MITRE T1040 on agent 001 and recommend fixes", history=[], organization_id="system")
    assert set(result.tool_calls) == {"mitre_technique_context", "threat_hunt"}
    assert result.grounded is True
    assert result.active_alert_id == "exact-raw-id"
    assert "No action executed" in result.answer
    assert reports.list(organization_id="system", limit=10) == []
