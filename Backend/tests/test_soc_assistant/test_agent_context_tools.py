"""Checks for the endpoint-context tools: inventory, detection evidence,
connectivity health, and the combined get_agent_context bundle."""

import json
from datetime import UTC, datetime

from app.services.wazuh.models import (
    AgentConnectivitySummary,
    AgentSummary,
    AlertEvidence,
    AlertSearchResult,
    DetectionEvidence,
    EndpointInventory,
)
from app.soc_assistant.tool_agent import build_tools


class FakeGateway:
    def get_agent_summary(self, agent_id):
        return AgentSummary(
            agent_id=agent_id,
            name="servervb",
            status="active",
            os_name="Windows 11",
        )

    def get_agent_inventory(self, *, agent_id, component, limit=50, text=None):
        items_by_component = {
            "hardware": [{"cpu_cores": 4, "ram_total": 8192}],
            "processes": [{"name": "powershell.exe", "pid": 4242}],
            "ports": [{"local_port": 4444, "protocol": "tcp"}],
        }
        items = items_by_component.get(component, [])
        return EndpointInventory(
            agent_id=agent_id,
            component=component,
            total=len(items),
            returned=len(items),
            truncated=False,
            items=items,
        )

    def get_detection_evidence(self, *, agent_id, limit=100):
        return DetectionEvidence(
            agent_id=agent_id,
            fim_findings=[{"file": "/etc/passwd"}],
            sca_findings=[],
            rootcheck_findings=[],
            fim_total=1,
            sca_total=0,
            rootcheck_total=0,
            truncated=False,
        )

    def agent_connectivity_summary(self):
        return AgentConnectivitySummary(
            by_status={"active": 4, "disconnected": 1},
            total=5,
        )

    def search_vulnerabilities(self, *, severity=None, agent_id=None, limit=20):
        return [{"vulnerability": {"id": "CVE-2024-9999", "severity": "Critical"}}], 1

    def search_alerts(self, **kwargs):
        return AlertSearchResult(
            total=1,
            returned=1,
            truncated=False,
            alerts=[
                AlertEvidence(
                    alert_id="alert-1",
                    timestamp=datetime(2026, 7, 26, 10, 0, tzinfo=UTC),
                    agent_id=kwargs.get("agent_id", "004"),
                    rule_id="92300",
                    rule_level=12,
                    description="Suspicious PowerShell child process",
                )
            ],
        )


def _tools():
    from app.db.repositories.reports import InMemoryReportRepository

    return {
        item.name: item
        for item in build_tools(
            gateway=FakeGateway(),
            report_repository=InMemoryReportRepository(),
            investigations=None,
            organization_id="user_1",
            created_by="user_1",
            conversation_id=None,
        )
    }


def test_get_agent_inventory_returns_the_requested_component():
    tools = _tools()
    raw = tools["get_agent_inventory"].invoke(
        {"agent_id": "004", "component": "ports"}
    )
    result = json.loads(raw)
    assert result["component"] == "ports"
    assert result["items"][0]["local_port"] == 4444


def test_get_agent_detection_evidence_returns_fim_sca_rootcheck():
    tools = _tools()
    raw = tools["get_agent_detection_evidence"].invoke({"agent_id": "004"})
    result = json.loads(raw)
    assert result["fim_total"] == 1
    assert result["fim_findings"][0]["file"] == "/etc/passwd"


def test_wazuh_health_summary_reports_connectivity_counts():
    tools = _tools()
    raw = tools["wazuh_health_summary"].invoke({})
    result = json.loads(raw)
    assert result["by_status"]["disconnected"] == 1
    assert result["total"] == 5


def test_get_agent_context_bundles_everything_for_one_agent():
    tools = _tools()
    raw = tools["get_agent_context"].invoke({"agent_id": "004", "hours": 24})
    result = json.loads(raw)

    assert result["agent_id"] == "004"
    assert result["status"]["os_name"] == "Windows 11"
    assert result["hardware"]["items"][0]["cpu_cores"] == 4
    assert result["processes"]["items"][0]["name"] == "powershell.exe"
    assert result["ports"]["items"][0]["local_port"] == 4444
    assert result["vulnerabilities"]["total"] == 1
    assert result["detection_evidence"]["fim_total"] == 1
    assert result["recent_alerts"]["total"] == 1
    assert (
        result["recent_alerts"]["alerts"][0]["description"]
        == "Suspicious PowerShell child process"
    )


def test_get_agent_context_survives_a_failing_section(monkeypatch):
    gateway = FakeGateway()

    def broken_vulnerabilities(*, severity=None, agent_id=None, limit=20):
        raise RuntimeError("vulnerability module unavailable")

    monkeypatch.setattr(gateway, "search_vulnerabilities", broken_vulnerabilities)
    from app.db.repositories.reports import InMemoryReportRepository

    tools = {
        item.name: item
        for item in build_tools(
            gateway=gateway,
            report_repository=InMemoryReportRepository(),
            investigations=None,
            organization_id="user_1",
            created_by="user_1",
            conversation_id=None,
        )
    }

    raw = tools["get_agent_context"].invoke({"agent_id": "004"})
    result = json.loads(raw)

    assert result["vulnerabilities"]["error"] == "RuntimeError"
    # Other sections still populated despite the one failure.
    assert result["processes"]["items"][0]["name"] == "powershell.exe"
