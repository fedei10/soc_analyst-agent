"""Unit tests for the write-only Wazuh responder client.

This client is the only path that can change endpoint state, so the guards
matter more than the happy path: it must refuse to construct at all unless
dangerous tools are explicitly enabled and responder credentials are set.
"""

import httpx
import pytest
from pydantic import SecretStr

from app.config import settings
from app.services.wazuh.exceptions import WazuhDangerousActionBlocked
from app.services.wazuh.responder_client import WazuhResponderClient


@pytest.fixture
def responder_settings(monkeypatch):
    """Enable the response surface with synthetic credentials."""
    monkeypatch.setattr(settings, "WAZUH_ALLOW_DANGEROUS_TOOLS", True)
    monkeypatch.setattr(settings, "WAZUH_RESPONDER_USERNAME", "responder")
    monkeypatch.setattr(settings, "WAZUH_RESPONDER_PASSWORD", SecretStr("test-secret"))
    monkeypatch.setattr(settings, "WAZUH_VERIFY_SSL", False)
    monkeypatch.setattr(settings, "WAZUH_BASE_URL", "https://wazuh.test")
    return settings


def mock_responder(handler) -> WazuhResponderClient:
    client = WazuhResponderClient()
    client._transport._client.close()
    client._transport._client = httpx.Client(
        base_url="https://wazuh.test",
        transport=httpx.MockTransport(handler),
    )
    return client


def auth_then(handler):
    """Wrap a handler so the transport's authenticate step always succeeds."""

    def wrapped(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="jwt-token")
        return handler(request)

    return wrapped


# --- construction guards --------------------------------------------------


def test_construction_is_blocked_when_dangerous_tools_are_disabled(monkeypatch):
    monkeypatch.setattr(settings, "WAZUH_ALLOW_DANGEROUS_TOOLS", False)

    with pytest.raises(
        WazuhDangerousActionBlocked,
        match="Response actions are disabled",
    ):
        WazuhResponderClient()


@pytest.mark.parametrize(
    ("username", "password"),
    [("", "test-secret"), ("responder", ""), ("", "")],
    ids=["no_username", "no_password", "neither"],
)
def test_construction_requires_responder_credentials(monkeypatch, username, password):
    monkeypatch.setattr(settings, "WAZUH_ALLOW_DANGEROUS_TOOLS", True)
    monkeypatch.setattr(settings, "WAZUH_RESPONDER_USERNAME", username)
    monkeypatch.setattr(settings, "WAZUH_RESPONDER_PASSWORD", SecretStr(password))

    with pytest.raises(
        WazuhDangerousActionBlocked,
        match="Responder credentials are not configured",
    ):
        WazuhResponderClient()


def test_the_disabled_guard_is_checked_before_credentials(monkeypatch):
    """Disabling the surface must win even with credentials present."""
    monkeypatch.setattr(settings, "WAZUH_ALLOW_DANGEROUS_TOOLS", False)
    monkeypatch.setattr(settings, "WAZUH_RESPONDER_USERNAME", "responder")
    monkeypatch.setattr(settings, "WAZUH_RESPONDER_PASSWORD", SecretStr("test-secret"))

    with pytest.raises(
        WazuhDangerousActionBlocked,
        match="Response actions are disabled",
    ):
        WazuhResponderClient()


def test_the_transport_is_tagged_as_the_responder_component(responder_settings):
    client = WazuhResponderClient()
    try:
        assert client._transport.component == "responder"
        assert client._transport.base_url == "https://wazuh.test"
    finally:
        client.close()


@pytest.mark.parametrize(
    ("verify_ssl", "ca_cert", "expected"),
    [(False, None, False), (True, None, True), (True, "/etc/ca.pem", "/etc/ca.pem")],
)
def test_ssl_verification_resolution(monkeypatch, verify_ssl, ca_cert, expected):
    monkeypatch.setattr(settings, "WAZUH_ALLOW_DANGEROUS_TOOLS", True)
    monkeypatch.setattr(settings, "WAZUH_RESPONDER_USERNAME", "responder")
    monkeypatch.setattr(settings, "WAZUH_RESPONDER_PASSWORD", SecretStr("test-secret"))
    monkeypatch.setattr(settings, "WAZUH_VERIFY_SSL", verify_ssl)
    monkeypatch.setattr(settings, "WAZUH_CA_CERT", ca_cert)
    captured = {}

    class RecordingTransport:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(
        "app.services.wazuh.responder_client._AuthenticatedWazuhTransport",
        RecordingTransport,
    )

    WazuhResponderClient()

    assert captured["verify"] == expected


# --- active response ------------------------------------------------------


def test_active_response_targets_the_agent_with_the_command(responder_settings):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["agents_list"] = request.url.params["agents_list"]
        seen["body"] = httpx.Response(200, content=request.content).json()
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"error": 0, "data": {"affected_items": ["004"]}},
        )

    client = mock_responder(auth_then(handler))
    try:
        result = client.run_active_response(
            agent_id="004",
            command="firewall-drop",
            arguments=["10.0.0.9"],
        )
    finally:
        client.close()

    assert seen["method"] == "PUT"
    assert seen["path"] == "/active-response"
    assert seen["agents_list"] == "004"
    assert seen["body"] == {"command": "firewall-drop", "arguments": ["10.0.0.9"]}
    assert result["error"] == 0


def test_active_response_defaults_arguments_to_an_empty_list(responder_settings):
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(httpx.Response(200, content=request.content).json())
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"error": 0, "data": {}},
        )

    client = mock_responder(auth_then(handler))
    try:
        client.run_active_response(agent_id="004", command="restart-wazuh")
    finally:
        client.close()

    assert bodies[0] == {"command": "restart-wazuh", "arguments": []}


def test_active_response_includes_the_alert_only_when_supplied(responder_settings):
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(httpx.Response(200, content=request.content).json())
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"error": 0, "data": {}},
        )

    client = mock_responder(auth_then(handler))
    try:
        client.run_active_response(
            agent_id="004",
            command="firewall-drop",
            alert={"rule": {"id": "5710"}},
        )
        client.run_active_response(agent_id="004", command="firewall-drop", alert={})
    finally:
        client.close()

    assert bodies[0]["alert"] == {"rule": {"id": "5710"}}
    assert "alert" not in bodies[1], "an empty alert must not be sent"


def test_restart_agent_uses_the_agent_scoped_path(responder_settings):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"error": 0, "data": {"affected_items": ["004"]}},
        )

    client = mock_responder(auth_then(handler))
    try:
        result = client.restart_agent("004")
    finally:
        client.close()

    assert seen["method"] == "PUT"
    assert seen["path"] == "/agents/004/restart"
    assert result["error"] == 0


def test_errors_from_wazuh_propagate_rather_than_being_swallowed(responder_settings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"title": "Permission denied"})

    client = mock_responder(auth_then(handler))
    try:
        with pytest.raises(Exception) as excinfo:
            client.run_active_response(agent_id="004", command="firewall-drop")
    finally:
        client.close()

    assert "403" in str(excinfo.value) or "ermission" in str(excinfo.value)
