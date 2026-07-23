"""Unit tests for Wazuh transport semantics and deterministic analysis."""

from datetime import UTC, datetime

import httpx
import pytest

from app.services.wazuh.exceptions import WazuhAPIError, WazuhValidationError
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.indexer_client import WazuhIndexerClient
from app.services.wazuh.models import AlertEvidence, AlertSearchResult
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
    assert client.calls[0]["index"] == "wazuh-archives-*"
    assert client.calls[0]["body"]["size"] == 10
    assert client.calls[0]["ignore_unavailable"] is True
