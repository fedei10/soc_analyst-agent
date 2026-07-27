"""Unit tests for Wazuh transport semantics and deterministic analysis."""

from datetime import UTC, datetime

import httpx
import pytest

from app.services.wazuh.exceptions import WazuhAPIError, WazuhValidationError
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.indexer_client import WazuhIndexerClient
from app.services.wazuh.models import (
    AgentSummary,
    AlertEvidence,
    AlertSearchResult,
    DetectionEvidence,
    EndpointInventory,
)
from app.services.wazuh.server_client import WazuhServerClient


def mock_server_client(handler) -> WazuhServerClient:
    client = WazuhServerClient(
        base_url="https://wazuh.test",
        username="reader",
        password="secret",
        verify_ssl=False,
    )
    client._transport._client.close()
    client._transport._client = httpx.Client(
        base_url="https://wazuh.test",
        transport=httpx.MockTransport(handler),
    )
    return client


def test_authentication_uses_post_only_and_raw_token():
    methods = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.url.path == "/security/user/authenticate":
            assert request.url.params["raw"] == "true"
            return httpx.Response(200, text="jwt-token")
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"error": 0, "data": {"affected_items": []}},
        )

    client = mock_server_client(handler)
    try:
        assert client.get("/agents")["error"] == 0
        assert client.get("/agents")["error"] == 0
    finally:
        client.close()
    assert methods == ["POST", "GET"]


@pytest.mark.parametrize("wazuh_error", [1, 2])
def test_http_200_wazuh_error_is_rejected(wazuh_error):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="jwt-token")
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "error": wazuh_error,
                "message": "Some items failed",
                "data": {"failed_items": [{"id": "001"}], "total_failed_items": 1},
            },
        )

    client = mock_server_client(handler)
    try:
        with pytest.raises(WazuhAPIError, match="failed_items=1"):
            client.get("/agents")
    finally:
        client.close()


def test_partial_success_can_be_explicitly_allowed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="jwt-token")
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"error": 2, "data": {"total_failed_items": 1}},
        )

    client = mock_server_client(handler)
    try:
        assert client.get("/agents", allow_partial=True)["error"] == 2
    finally:
        client.close()


def test_server_api_limit_is_bounded():
    client = mock_server_client(lambda request: httpx.Response(500))
    try:
        with pytest.raises(WazuhValidationError):
            client.get("/agents", params={"limit": 501})
    finally:
        client.close()


def test_transport_uses_client_default_timeout_unless_action_overrides_it():
    class RecordingClient:
        def __init__(self):
            self.calls = []

        def request(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            return httpx.Response(
                200,
                request=httpx.Request(method, f"https://wazuh.test{path}"),
            )

    client = WazuhServerClient(
        base_url="https://wazuh.test",
        username="reader",
        password="secret",
        verify_ssl=False,
    )
    client._transport._client.close()
    recorder = RecordingClient()
    client._transport._client = recorder

    client._transport._send("GET", "/agents", None, None, "token")
    client._transport._send(
        "PUT",
        "/active-response",
        None,
        {},
        "token",
        timeout_seconds=7,
    )

    assert "timeout" not in recorder.calls[0][2]
    assert recorder.calls[1][2]["timeout"] == 7


class FakeServer:
    def close(self):
        pass


class FakeIndexer:
    def __init__(self, result):
        self.result = result

    def search_alerts(self, **kwargs):
        return self.result

    def close(self):
        pass


def auth_event(alert_id: str, minute: int, outcome: str) -> AlertEvidence:
    return AlertEvidence(
        alert_id=alert_id,
        timestamp=datetime(2026, 7, 16, 9, minute, tzinfo=UTC),
        agent_id="001",
        rule_id="5710",
        rule_level=8,
        description=outcome,
        source_ip="203.0.113.10",
        target_user="root",
        event_outcome=outcome,
    )


def test_successful_login_after_failures_is_calculated_deterministically():
    events = [
        auth_event("failure-1", 10, "failure"),
        auth_event("failure-2", 12, "failure"),
        auth_event("success-1", 14, "success"),
    ]
    result = AlertSearchResult(total=3, returned=3, truncated=False, alerts=events)
    gateway = WazuhGateway(server=FakeServer(), indexer=FakeIndexer(result))

    analysis = gateway.check_successful_login_after_failures(
        source_ip="203.0.113.10", target_user="root", agent_id="001"
    )

    assert analysis.failed_attempt_count == 2
    assert analysis.successful_login_found is True
    assert analysis.successful_login_timestamp == events[-1].timestamp
    assert analysis.evidence_alert_ids == ["failure-1", "failure-2", "success-1"]
    assert analysis.confidence == 1.0
    assert analysis.successful_login_search_completed is True
    assert analysis.successful_login_observed is True
    assert analysis.returned_authentication_events == 3
    assert analysis.search_scope["source"] == "wazuh-alerts-*"


def test_success_between_failures_is_not_missed():
    events = [
        auth_event("failure-1", 10, "failure"),
        auth_event("success-1", 11, "success"),
        auth_event("failure-2", 12, "failure"),
    ]
    result = AlertSearchResult(total=3, returned=3, truncated=False, alerts=events)
    gateway = WazuhGateway(server=FakeServer(), indexer=FakeIndexer(result))

    analysis = gateway.check_successful_login_after_failures(
        source_ip="203.0.113.10",
        agent_id="001",
    )

    assert analysis.successful_login_found is True
    assert analysis.successful_login_timestamp == events[1].timestamp
    assert analysis.conclusion == "successful_login_observed"


def test_alert_normalization_reads_nested_wazuh_aliases():
    alert = WazuhIndexerClient._normalize_alert({
        "_id": "alert-aliases",
        "_source": {
            "@timestamp": "2026-07-23T10:00:00Z",
            "agent": {"id": "001", "name": "linux-vm"},
            "rule": {
                "id": "2502",
                "level": 10,
                "description": "Authentication failures",
                "groups": ["authentication_failed", "sshd"],
            },
            "data": {
                "remote_ip": "192.0.2.55",
                "username": "ubuntu",
            },
            "predecoder": {"hostname": "endpoint-1"},
            "decoder": {"name": "sshd"},
            "full_log": (
                "Failed password for ubuntu from 192.0.2.55 port 22 ssh2"
            ),
        },
    })

    assert alert.source_ip == "192.0.2.55"
    assert alert.target_user == "ubuntu"
    assert alert.hostname == "endpoint-1"
    assert alert.decoder_name == "sshd"
    assert alert.rule_groups == ["authentication_failed", "sshd"]
    assert alert.full_log.startswith("Failed password")


def test_authentication_timeline_can_use_agent_without_source_ip():
    result = AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
    indexer = FakeIndexer(result)
    gateway = WazuhGateway(server=FakeServer(), indexer=indexer)

    timeline = gateway.build_authentication_timeline(agent_id="001")

    assert timeline.returned == 0


def test_agent_inventory_uses_only_the_allowlisted_syscollector_path():
    class RecordingServer(FakeServer):
        def __init__(self):
            self.calls = []

        def get(self, path, params=None):
            self.calls.append((path, params))
            return {
                "data": {
                    "affected_items": [{"name": "eth0"}],
                    "total_affected_items": 1,
                }
            }

    result = AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
    server = RecordingServer()
    gateway = WazuhGateway(server=server, indexer=FakeIndexer(result))

    inventory = gateway.get_agent_inventory(
        agent_id="001",
        component="network",
        limit=10,
        text="eth",
    )

    assert server.calls == [
        ("/syscollector/001/netiface", {"limit": 10, "search": "eth"})
    ]
    assert inventory.returned == 1
    assert inventory.items[0]["name"] == "eth0"


def test_detection_evidence_includes_fim_sca_and_rootcheck():
    class EvidenceServer(FakeServer):
        def get(self, path, params=None):
            findings = {
                "/syscheck/001": [{"file": "/etc/passwd"}],
                "/sca/001": [{"policy_id": "cis"}],
                "/rootcheck/001": [{"status": "outstanding"}],
            }[path]
            return {
                "data": {
                    "affected_items": findings,
                    "total_affected_items": len(findings),
                }
            }

    result = AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
    gateway = WazuhGateway(
        server=EvidenceServer(),
        indexer=FakeIndexer(result),
    )

    evidence = gateway.get_detection_evidence(agent_id="001", limit=25)

    assert evidence.fim_total == 1
    assert evidence.sca_total == 1
    assert evidence.rootcheck_total == 1
    assert evidence.rootcheck_findings[0]["status"] == "outstanding"


def test_endpoint_forensics_preserves_partial_results_and_limitations(monkeypatch):
    result = AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
    gateway = WazuhGateway(server=FakeServer(), indexer=FakeIndexer(result))
    monkeypatch.setattr(
        gateway,
        "get_agent_summary",
        lambda agent_id: AgentSummary(agent_id=agent_id, name="server-1"),
    )

    def inventory(*, agent_id, component, limit):
        if component == "ports":
            raise WazuhAPIError("ports unavailable", 503)
        return EndpointInventory(
            agent_id=agent_id,
            component=component,
            total=1,
            returned=1,
            truncated=False,
            items=[{"component": component}],
        )

    monkeypatch.setattr(gateway, "get_agent_inventory", inventory)
    monkeypatch.setattr(
        gateway,
        "get_detection_evidence",
        lambda **kwargs: DetectionEvidence(
            agent_id=kwargs["agent_id"],
            fim_findings=[],
            sca_findings=[],
            rootcheck_findings=[],
            fim_total=0,
            sca_total=0,
            rootcheck_total=0,
            truncated=False,
        ),
    )
    monkeypatch.setattr(
        gateway,
        "search_vulnerabilities",
        lambda **kwargs: ([{"id": "CVE-2026-0001"}], 1),
    )

    forensics = gateway.get_endpoint_forensics(agent_id="001", limit=10)

    assert set(forensics.inventories) == {"processes", "network"}
    assert forensics.vulnerability_total == 1
    assert forensics.source_errors == [{
        "source": "inventory:ports",
        "code": "SOURCE_UNAVAILABLE",
    }]
    assert any(
        "memory capture" in item.lower()
        for item in forensics.telemetry_limitations
    )


def test_ioc_hunt_reports_partial_source_coverage():
    result = AlertSearchResult(
        total=1,
        returned=1,
        truncated=False,
        alerts=[auth_event("alert-ioc", 10, "failure")],
    )
    gateway = WazuhGateway(server=FakeServer(), indexer=FakeIndexer(result))

    hunt = gateway.hunt_ioc_telemetry(
        indicator="203.0.113.10",
        indicator_type="ip",
        hours=24,
        limit=10,
    )

    assert hunt.alerts is not None
    assert hunt.alerts.alerts[0].alert_id == "alert-ioc"
    assert hunt.archived_logs is None
    assert hunt.source_errors == [{
        "source": "wazuh_archives",
        "code": "SOURCE_UNAVAILABLE",
    }]
    assert hunt.external_intelligence_status == "not_configured"


def test_archive_search_is_bounded_and_returns_raw_context():
    class RecordingOpenSearch:
        def __init__(self):
            self.calls = []

        def search(self, **kwargs):
            self.calls.append(kwargs)
            return {
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_id": "archive-1",
                            "_source": {
                                "@timestamp": "2026-07-23T10:00:00Z",
                                "agent": {"id": "001", "name": "linux-vm"},
                                "decoder": {"name": "sshd"},
                                "data": {
                                    "srcip": "192.0.2.60",
                                    "dstuser": "root",
                                },
                                "full_log": (
                                    "Failed password for root from "
                                    "192.0.2.60 port 22 ssh2"
                                ),
                            },
                        }
                    ],
                }
            }

        def close(self):
            pass

    client = RecordingOpenSearch()
    indexer = WazuhIndexerClient(client=client)

    result = indexer.search_archived_logs(
        text="failed password",
        hours=24,
        limit=10,
        agent_id="001",
    )

    assert result.total == 1
    assert result.events[0].normalized.source_ip == "192.0.2.60"
    assert result.archive_status == "available"
    assert result.query_scope["agent_id"] == "001"
    assert result.query_scope["hours"] == 24
    assert client.calls[0]["index"] == "wazuh-archives-*"
    assert client.calls[0]["body"]["size"] == 10
    assert client.calls[0]["ignore_unavailable"] is True


def test_archive_search_reports_unavailable_index_without_claiming_no_activity():
    class MissingArchiveOpenSearch:
        def search(self, **kwargs):
            return {
                "_shards": {
                    "total": 0,
                    "successful": 0,
                    "skipped": 0,
                    "failed": 0,
                },
                "hits": {"total": {"value": 0}, "hits": []},
            }

        def close(self):
            pass

    result = WazuhIndexerClient(
        client=MissingArchiveOpenSearch()
    ).search_archived_logs(text="failed password", hours=24)

    assert result.total == 0
    assert result.archive_status == "unavailable"
    assert result.query_scope["text"] == "failed password"


def test_agent_inventory_supports_hardware_component():
    class RecordingServer(FakeServer):
        def __init__(self):
            self.calls = []

        def get(self, path, params=None):
            self.calls.append((path, params))
            return {
                "data": {
                    "affected_items": [{"board_serial": "ABC123"}],
                    "total_affected_items": 1,
                }
            }

    result = AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
    server = RecordingServer()
    gateway = WazuhGateway(server=server, indexer=FakeIndexer(result))

    inventory = gateway.get_agent_inventory(
        agent_id="004",
        component="hardware",
        limit=5,
    )

    assert server.calls == [("/syscollector/004/hardware", {"limit": 5})]
    assert inventory.component == "hardware"
    assert inventory.items[0]["board_serial"] == "ABC123"


def test_agent_connectivity_summary_handles_nested_connection_shape():
    class NestedStatusServer(FakeServer):
        def get(self, path, params=None):
            assert path == "/agents/summary/status"
            return {
                "data": {
                    "connection": {
                        "active": 8,
                        "disconnected": 2,
                        "pending": 0,
                        "never_connected": 1,
                        "total": 11,
                    }
                }
            }

    result = AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
    gateway = WazuhGateway(server=NestedStatusServer(), indexer=FakeIndexer(result))

    summary = gateway.agent_connectivity_summary()

    assert summary.by_status == {
        "active": 8,
        "disconnected": 2,
        "pending": 0,
        "never_connected": 1,
    }
    assert summary.total == 11


def test_agent_connectivity_summary_handles_flat_shape():
    class FlatStatusServer(FakeServer):
        def get(self, path, params=None):
            return {"data": {"active": 3, "disconnected": 1}}

    result = AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
    gateway = WazuhGateway(server=FlatStatusServer(), indexer=FakeIndexer(result))

    summary = gateway.agent_connectivity_summary()

    assert summary.by_status == {"active": 3, "disconnected": 1}
    assert summary.total == 4
