"""Contract tests for the narrow, cumulative SOC Wazuh toolsets."""

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
from app.services.wazuh.models import AgentSummary, AlertEvidence, AlertSearchResult


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
    assert len(l2) == 6
    assert len(l3) == 8
    assert names(l1) < names(l2) < names(l3)


def test_exact_agent_tool_surface(gateway):
    assert names(get_all_read_only_tools(gateway)) == {
        "get_high_severity_alerts",
        "get_alert_by_id",
        "get_agent_summary",
        "get_related_alerts",
        "build_authentication_timeline",
        "check_successful_login_after_failures",
        "get_rule_and_mitre_context",
        "get_detection_evidence",
    }


def test_no_response_or_generic_client_tools_are_registered(gateway):
    registered = names(get_soc_l3_tools(gateway))
    assert not any("response" in name for name in registered)
    assert not registered & {"request", "get", "post", "put", "delete", "search"}


def test_high_severity_tool_returns_normalized_result(gateway):
    gateway.get_high_severity_alerts.return_value = AlertSearchResult(
        total=10, returned=1, truncated=True, alerts=[sample_alert()]
    )
    result = tool(get_soc_l1_tools(gateway), "get_high_severity_alerts").invoke({
        "min_level": 12, "hours": 24, "limit": 1,
    })
    assert result["ok"] is True
    assert result["data"]["truncated"] is True
    assert result["data"]["alerts"][0]["alert_id"] == "alert-1"


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
        ("soc_level2_agent", 6),
        ("soc_level3_agent", 8),
    ],
)
def test_agents_are_wired_with_their_tier(module_name, expected_tools):
    module = __import__(f"app.coreAgents.Agents.{module_name}", fromlist=["agent"])
    assert module.agent is not None
    tiers = {3: get_soc_l1_tools, 6: get_soc_l2_tools, 8: get_soc_l3_tools}
    assert len(tiers[expected_tools]()) == expected_tools
