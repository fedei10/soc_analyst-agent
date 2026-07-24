"""Contract tests for auth, dependency boundaries, and API error envelopes."""

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from app.main import app
from app.services.wazuh.dependencies import get_wazuh_gateway, get_wazuh_responder
from app.services.wazuh.models import AlertEvidence, AlertSearchResult

READ = {"Authorization": "Bearer test-read-key"}
WRITE = {"Authorization": "Bearer test-write-key"}


class ASGITestClient:
    def request(self, method: str, path: str, **kwargs):
        async def send():
            transport = httpx.ASGITransport(
                app=app,
                raise_app_exceptions=False,
            )
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(send())

    def get(self, path: str, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs):
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs):
        return self.request("PUT", path, **kwargs)


@pytest.fixture
def gateway():
    return SimpleNamespace()


@pytest.fixture
def responder():
    return SimpleNamespace()


@pytest.fixture
def client(gateway, responder):
    app.dependency_overrides[get_wazuh_gateway] = lambda: gateway
    app.dependency_overrides[get_wazuh_responder] = lambda: responder
    yield ASGITestClient()
    app.dependency_overrides.clear()


def sample_alert() -> AlertEvidence:
    return AlertEvidence(
        alert_id="alert-1",
        timestamp=datetime(2026, 7, 16, 9, 10, tzinfo=UTC),
        agent_id="001",
        agent_name="server-1",
        rule_id="5710",
        rule_level=12,
        description="Failed password",
        source_ip="203.0.113.10",
        target_user="root",
        event_outcome="failure",
    )


def test_liveness_needs_no_auth(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_missing_token_is_401_with_envelope(client):
    response = client.get("/api/v1/alerts")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "unauthorized"
    assert body["request_id"]
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_invalid_token_is_401(client):
    response = client.get("/api/v1/alerts", headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401


def test_read_token_lists_normalized_alerts(client, gateway):
    gateway.search_alerts = lambda **kwargs: AlertSearchResult(
        total=1, returned=1, truncated=False, alerts=[sample_alert()]
    )
    response = client.get("/api/v1/alerts?min_level=12", headers=READ)
    assert response.status_code == 200
    assert response.json()["data"]["affected_items"][0]["alert_id"] == "alert-1"
    assert response.headers["X-Request-ID"]


def test_limit_above_max_is_422(client):
    response = client.get("/api/v1/alerts?limit=1000", headers=READ)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


def test_missing_alert_is_404(client, gateway):
    gateway.get_alert_by_id = lambda alert_id: None
    response = client.get("/api/v1/alerts/nope", headers=READ)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_analyst_cannot_request_direct_response_actions(client, responder):
    restarted = []
    responder.restart_agent = restarted.append

    response = client.put(
        "/api/v1/agents/001/restart", headers=READ, json={}
    )
    assert response.status_code == 403
    assert restarted == []


def test_write_token_uses_separate_responder(client, responder):
    calls = {}

    def run_active_response(**kwargs):
        calls.update(kwargs)
        return {"data": {"affected_items": ["001"]}}

    responder.run_active_response = run_active_response
    response = client.post(
        "/api/v1/agents/001/active-response",
        headers=WRITE,
        json={"command": "firewall-drop", "arguments": ["1.2.3.4"]},
    )
    assert response.status_code == 202
    assert response.json()["data"]["status"] == "queued"
    assert calls["agent_id"] == "001"
    assert calls["command"] == "firewall-drop"
    assert response.json()["data"]["approved_by"] == "user_responder"


def test_unknown_command_and_extra_fields_are_rejected(client):
    for body in (
        {"command": "rm-rf"},
        {},
        {"command": "firewall-drop", "x": 1},
    ):
        response = client.post(
            "/api/v1/agents/001/active-response", headers=WRITE, json=body
        )
        assert response.status_code == 422, body


def test_non_json_body_is_415(client):
    response = client.post(
        "/api/v1/agents/001/active-response",
        headers={**WRITE, "Content-Type": "text/plain"},
        content="hello",
    )
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_media_type"


def test_wazuh_unreachable_maps_to_503(client, gateway):
    def boom(path, params=None):
        raise httpx.ConnectError("connection refused")

    gateway.server_get = boom
    response = client.get("/api/v1/cluster/status", headers=READ)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "wazuh_unavailable"


def test_wazuh_http_error_maps_to_502(client, gateway):
    def boom(path, params=None):
        request = httpx.Request("GET", "https://wazuh/agents")
        response = httpx.Response(401, request=request, json={"title": "Unauthorized"})
        raise httpx.HTTPStatusError("401", request=request, response=response)

    gateway.server_get = boom
    response = client.get("/api/v1/cluster/status", headers=READ)
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "wazuh_api_error"


def test_500_never_leaks_internals(client, gateway):
    def boom(**kwargs):
        raise ValueError("SECRET-INTERNAL-DETAIL")

    gateway.search_alerts = boom
    response = client.get("/api/v1/alerts", headers=READ)
    assert response.status_code == 500
    assert "SECRET-INTERNAL-DETAIL" not in response.text
    assert "ValueError" not in response.text
    assert response.json()["error"]["code"] == "internal_error"
