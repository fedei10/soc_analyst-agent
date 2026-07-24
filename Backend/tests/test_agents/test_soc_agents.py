"""Contract tests for the narrow, cumulative SOC Wazuh toolsets."""

import json
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app.coreAgents.tools.wazuh.tool_registry import (
    get_all_read_only_tools,
    get_soc_l1_tools,
    get_soc_l2_tools,
    get_soc_l3_tools,
)
from app.services.wazuh.exceptions import WazuhAPIError
from app.services.wazuh.models import (
    AgentSummary,
    AlertEvidence,
    AlertSearchResult,
    ArchivedLogSearchResult,
    DetectionEvidence,
    EndpointForensics,
    EndpointInventory,
    IOCHuntResult,
)


def names(tools) -> set[str]:
    return {tool.name for tool in tools}


def tool(tools, name):
    return next(item for item in tools if item.name == name)


@pytest.fixture
def gateway():
    return Mock()


def sample_alert() -> AlertEvidence:
    return AlertEvidence(
        alert_id="alert-1",
        timestamp=datetime(2026, 7, 16, 9, 10, tzinfo=UTC),
        agent_id="001",
        rule_id="5710",
        rule_level=12,
        description="Failed password",
        source_ip="203.0.113.10",
        target_user="root",
        event_outcome="failure",
    )


def test_tiers_are_cumulative_and_bounded(gateway):
    l1 = get_soc_l1_tools(gateway)
    l2 = get_soc_l2_tools(gateway)
    l3 = get_soc_l3_tools(gateway)
    assert len(l1) == 3
    assert len(l2) == 9
    assert len(l3) == 12
    assert names(l1) < names(l2) < names(l3)


def test_exact_agent_tool_surface(gateway):
    assert names(get_all_read_only_tools(gateway)) == {
        "get_high_severity_alerts",
        "get_alert_by_id",
        "get_agent_summary",
        "get_related_alerts",
        "build_authentication_timeline",
        "check_successful_login_after_failures",
        "hunt_archived_security_logs",
        "get_endpoint_forensics",
        "collect_host_diagnostic",
        "get_rule_and_mitre_context",
        "get_detection_evidence",
        "hunt_ioc_across_telemetry",
    }


def test_no_response_or_generic_client_tools_are_registered(gateway):
    registered = names(get_soc_l3_tools(gateway))
    assert not any("response" in name for name in registered)
    assert not registered & {"request", "get", "post", "put", "delete", "search"}


def test_high_severity_tool_returns_compact_finding_result(gateway):
    gateway.get_high_severity_alerts.return_value = AlertSearchResult(
        total=10, returned=1, truncated=True, alerts=[sample_alert()]
    )
    result = tool(get_soc_l1_tools(gateway), "get_high_severity_alerts").invoke({
        "min_level": 12, "hours": 24, "limit": 1,
    })
    assert result["ok"] is True
    assert result["data"]["truncated"] is True
    assert result["data"]["total_raw_alerts"] == 10
    assert result["data"]["finding_count"] == 1
    assert result["data"]["findings"][0]["representative_alert_id"] == "alert-1"
    assert "alerts" not in result["data"]


def test_agent_summary_uses_only_numeric_agent_ids(gateway):
    gateway.get_agent_summary.return_value = AgentSummary(agent_id="001", name="server-1")
    agent_tool = tool(get_soc_l1_tools(gateway), "get_agent_summary")
    assert agent_tool.invoke({"agent_id": "001"})["data"]["found"] is True
    with pytest.raises(ValidationError):
        agent_tool.invoke({"agent_id": "../manager"})


def test_authentication_tool_validates_ip_and_window(gateway):
    timeline_tool = tool(get_soc_l2_tools(gateway), "build_authentication_timeline")
    with pytest.raises(ValidationError):
        timeline_tool.invoke({"source_ip": "not-an-ip"})
    with pytest.raises(ValidationError):
        timeline_tool.invoke({"source_ip": "203.0.113.10", "hours": 1000})


def test_l2_hunting_and_forensics_tools_are_bounded(gateway):
    gateway.search_archived_logs.return_value = ArchivedLogSearchResult(
        index_pattern="wazuh-archives-*",
        archive_status="available",
        total=0,
        returned=0,
        truncated=False,
        events=[],
    )
    large_value = "x" * 5000
    gateway.get_endpoint_forensics.return_value = EndpointForensics(
        agent_id="001",
        inventories={
            "processes": EndpointInventory(
                agent_id="001",
                component="processes",
                total=20,
                returned=20,
                truncated=False,
                items=[
                    {
                        "pid": index,
                        "ppid": 1,
                        "name": "python",
                        "cmd": large_value,
                    }
                    for index in range(20)
                ],
            )
        },
        detection_evidence=DetectionEvidence(
            agent_id="001",
            fim_findings=[{"path": large_value} for _ in range(20)],
            sca_findings=[],
            rootcheck_findings=[],
            fim_total=20,
            sca_total=0,
            rootcheck_total=0,
            truncated=False,
        ),
    )
    l2_tools = get_soc_l2_tools(gateway)

    hunt_result = tool(
        l2_tools,
        "hunt_archived_security_logs",
    ).invoke({
        "text": "powershell",
        "agent_id": "001",
        "hours": 24,
        "limit": 10,
    })
    forensics_result = tool(
        l2_tools,
        "get_endpoint_forensics",
    ).invoke({"agent_id": "001", "limit": 10})

    assert hunt_result["data"]["archive_status"] == "available"
    assert forensics_result["data"]["agent_id"] == "001"
    assert len(forensics_result["data"]["inventories"]["processes"]["sample"]) == 3
    assert len(json.dumps(forensics_result)) < 6000
    with pytest.raises(ValidationError):
        tool(l2_tools, "get_endpoint_forensics").invoke({
            "agent_id": "../manager",
        })


def test_l3_ioc_hunt_is_compact_and_validates_indicator(gateway):
    gateway.hunt_ioc_telemetry.return_value = IOCHuntResult(
        indicator="192.0.2.10",
        indicator_type="ip",
        alerts=AlertSearchResult(
            total=1,
            returned=1,
            truncated=False,
            alerts=[sample_alert()],
        ),
    )
    hunt_tool = tool(get_soc_l3_tools(gateway), "hunt_ioc_across_telemetry")

    result = hunt_tool.invoke({
        "indicator_type": "ip",
        "indicator": "192.0.2.10",
        "hours": 24,
        "limit": 10,
    })

    assert result["data"]["alerts"]["sample"][0]["evidence_ref"] == (
        "alert:alert-1"
    )
    assert result["data"]["external_intelligence_status"] == "not_configured"
    with pytest.raises(ValidationError):
        hunt_tool.invoke({
            "indicator_type": "ip",
            "indicator": "not-an-ip",
        })


def test_tool_failure_is_structured_and_retryable(gateway):
    gateway.get_high_severity_alerts.side_effect = WazuhAPIError(
        "Wazuh operation failed.", 503
    )
    result = tool(get_soc_l1_tools(gateway), "get_high_severity_alerts").invoke({})
    assert result == {
        "ok": False,
        "error": {
            "code": "WAZUH_API_ERROR",
            "message": "Wazuh operation failed.",
            "retryable": True,
        },
    }


@pytest.mark.parametrize(
    "module_name,expected_tools",
    [
        ("soc_level1_agent", 3),
        ("soc_level2_agent", 9),
        ("soc_level3_agent", 12),
    ],
)
def test_agents_are_wired_with_their_tier(module_name, expected_tools):
    module = __import__(f"app.coreAgents.Agents.{module_name}", fromlist=["agent"])
    assert module.agent is not None
    tiers = {3: get_soc_l1_tools, 9: get_soc_l2_tools, 12: get_soc_l3_tools}
    assert len(tiers[expected_tools]()) == expected_tools
