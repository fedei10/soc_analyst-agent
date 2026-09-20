"""Telemetry-integrity evidence.

"No alerts matched" and "the pipeline dropped the events" look identical from
the alert index. Wazuh counts the difference - discarded agent messages,
dropped analysis events, per-file log drops, and which sources an agent is
even configured to collect - and these checks pin that the analyst can see it.
"""

import json

import pytest

from app.db.repositories.reports import InMemoryReportRepository
from app.services.wazuh.gateway import WazuhGateway
from app.soc_assistant.tool_agent import build_tools


def items(*records):
    return {"data": {"affected_items": list(records)}}


class FakeGateway(WazuhGateway):
    """Exercises the real bundling logic over canned Wazuh responses."""

    def __init__(self, responses, failures=()):
        self.responses = responses
        self.failures = set(failures)
        self.paths = []

    def server_get(self, path, params=None):
        self.paths.append((path, params))
        if path in self.failures:
            raise ConnectionError("manager unreachable")
        return self.responses.get(path, {"data": {"affected_items": []}})


def healthy_responses(discarded=0, drops=0):
    return {
        "/manager/stats/remoted": items(
            {
                "queue_size": 0,
                "total_queue_size": 131072,
                "tcp_sessions": 3,
                "discarded_count": discarded,
                "dequeued_after_close": 0,
            }
        ),
        "/manager/stats/analysisd": items({"events_dropped": 0}),
        "/manager/logs": items(
            {
                "timestamp": "2026-09-18T01:01:52Z",
                "tag": "wazuh-modulesd",
                "level": "error",
                "description": "Could not connect to the vulnerability feed",
            }
        ),
        "/agents/001/stats/logcollector": items(
            {
                "global": {
                    "files": [
                        {
                            "location": "/var/log/auth.log",
                            "targets": [{"name": "agent", "drops": drops}],
                        }
                    ]
                }
            }
        ),
        "/agents/001/config/logcollector/localfile": items(
            {"localfile": [{"location": "/var/log/auth.log"}]}
        ),
        "/agents/001/config/syscheck/syscheck": items(
            {"syscheck": {"disabled": "no"}}
        ),
    }


def test_a_clean_pipeline_reports_telemetry_as_complete():
    gateway = FakeGateway(healthy_responses())

    result = gateway.telemetry_health(agent_id="001")

    assert result["telemetry_complete"] is True
    assert result["ingestion"]["manager_discarded_messages"] == 0
    assert result["agent_log_drops"] == 0
    assert result["dropping_files"] == []


def test_dropped_agent_logs_make_an_absence_unverifiable():
    gateway = FakeGateway(healthy_responses(drops=417))

    result = gateway.telemetry_health(agent_id="001")

    assert result["telemetry_complete"] is False
    assert result["agent_log_drops"] == 417
    assert result["dropping_files"] == [
        {"location": "/var/log/auth.log", "drops": 417, "period": "global"}
    ]
    assert "collection failure" in result["note"]


def test_manager_discards_are_surfaced_separately_from_agent_drops():
    gateway = FakeGateway(healthy_responses(discarded=93))

    result = gateway.telemetry_health(agent_id="001")

    assert result["ingestion"]["manager_discarded_messages"] == 93
    assert result["agent_log_drops"] == 0
    assert result["telemetry_complete"] is False


def test_configured_sources_show_what_the_agent_can_even_see():
    gateway = FakeGateway(healthy_responses())

    result = gateway.telemetry_health(agent_id="001")

    assert result["monitored_logs"] == ["/var/log/auth.log"]
    assert result["file_integrity_enabled"] is True


def test_manager_errors_are_bounded_and_counted():
    gateway = FakeGateway(healthy_responses())

    result = gateway.telemetry_health(agent_id="001")

    assert result["manager_error_count"] == 1
    assert result["manager_errors"][0]["tag"] == "wazuh-modulesd"
    assert ("/manager/logs", {"level": "error", "limit": 20}) in gateway.paths


def test_one_failed_check_degrades_that_key_not_the_snapshot():
    gateway = FakeGateway(
        healthy_responses(), failures={"/manager/stats/analysisd"}
    )

    result = gateway.telemetry_health(agent_id="001")

    assert result["unavailable_checks"] == {"analysisd": "ConnectionError"}
    # The rest of the evidence still arrives.
    assert result["ingestion"]["tcp_sessions"] == 3


def test_environment_wide_check_skips_agent_scoped_reads():
    gateway = FakeGateway(healthy_responses())

    result = gateway.telemetry_health()

    assert result["agent_id"] is None
    assert result["agent_log_drops"] is None
    assert all("/agents/" not in path for path, _ in gateway.paths)


@pytest.mark.parametrize("agent_id", ["../../manager", "001;rm", "a" * 17])
def test_agent_id_cannot_escape_the_url_path(agent_id):
    gateway = FakeGateway(healthy_responses())

    with pytest.raises(ValueError):
        gateway.telemetry_health(agent_id=agent_id)


def test_the_analyst_tool_returns_a_readable_error_for_a_bad_agent_id():
    class Gateway:
        def telemetry_health(self, **_kwargs):
            raise ValueError("agent_id must be alphanumeric, got '../x'.")

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

    raw = tools["telemetry_health"].invoke({"agent_id": "../x"})
    result = json.loads(raw)

    assert result["ok"] is False
    assert result["error"]["code"] == "INVALID_ARGUMENT"
    assert "alphanumeric" in result["error"]["message"]
