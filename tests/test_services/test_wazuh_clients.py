"""Unit tests for Wazuh transport semantics and deterministic analysis."""

from datetime import UTC, datetime

import httpx
import pytest

from app.services.wazuh.exceptions import WazuhAPIError, WazuhValidationError
from app.services.wazuh.gateway import WazuhGateway
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
