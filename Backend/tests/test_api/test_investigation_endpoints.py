from types import SimpleNamespace

from app.api.auth.deps import AuthPrincipal
from app.api.v1.endpoints import investigations
from app.api.v1.schemas.investigation import (
    AgentChatRequest,
    InvestigationCreate,
    L1Result,
    L2Result,
    OrchestratorChatRequest,
)
from app.main import app


class FakeAgent:
    def invoke(self, input_data):
        return {
            "messages": [
                SimpleNamespace(
                    tool_calls=[{"name": "get_high_severity_alerts"}]
                )
            ],
            "structured_response": L1Result(
                summary="High-severity alerts reviewed",
                classification="suspicious",
                severity="medium",
                confidence=0.88,
                escalate=True,
                evidence_refs=["alert:alert-1"],
            ),
        }


PRINCIPAL = AuthPrincipal(
    user_id="user_test",
    session_id="sess_test",
    scope_id="user_test",
)


def test_investigation_and_chat_routes_are_registered():
    paths = app.openapi()["paths"]

    assert "/api/v1/investigations" in paths
    assert "/api/v1/investigations/{investigation_id}" in paths
    assert "/api/v1/investigations/{investigation_id}/approval" in paths
    assert "/api/v1/investigations/{investigation_id}/execute" in paths
    assert "/api/v1/investigations/{investigation_id}/report" in paths
    assert "/api/v1/investigations/{investigation_id}/agent-runs" in paths
    assert "/api/v1/investigations/{investigation_id}/audit" in paths
    assert "/api/v1/investigations/{investigation_id}/approvals" in paths
    assert "/api/v1/investigations/{investigation_id}/actions" in paths
    assert "/api/v1/investigations/{investigation_id}/events" in paths
    assert "/api/v1/health/database" in paths
    assert "/api/v1/health/storage" in paths
    assert "/api/v1/soc/chat" in paths
    assert "/api/v1/soc/conversations" in paths
    assert "/api/v1/soc/conversations/{conversation_id}/messages" in paths
    assert "/api/v1/soc/orchestrator/chat" in paths
    assert "/api/v1/soc/orchestrator/chat/stream" in paths


def test_initial_investigation_state_matches_graph_contract():
    request = InvestigationCreate(alert_id="alert-1", agent_id="001")

    state = investigations._initial_state("INV-001", request)

    assert state["investigation_id"] == "INV-001"
    assert state["alert_id"] == "alert-1"
    assert state["agent_id"] == "001"
    assert state["status"] == "created"
    assert state["audit_events"] == []


def test_public_api_data_hides_internal_scope():
    assert investigations._public_data({
        "organization_id": "user_test",
        "nested": [{"organization_id": "user_test", "status": "running"}],
    }) == {"nested": [{"status": "running"}]}


def test_chat_uses_selected_agent_and_returns_structured_output(monkeypatch):
    monkeypatch.setattr(
        investigations,
        "_agent_for_tier",
        lambda tier: (FakeAgent(), L1Result),
    )

    response = investigations.chat_with_soc_agent(
        AgentChatRequest(
            tier="l1",
            message="Review high-severity Wazuh alerts.",
        ),
        PRINCIPAL,
    )

    data = response["data"]
    assert data["tier"] == "l1"
    assert data["response"]["severity"] == "medium"
    assert data["tools_used"] == ["get_high_severity_alerts"]
    assert "High-severity alerts reviewed" in data["assistant_message"]


def test_conversational_endpoint_returns_natural_answer_and_thread(monkeypatch):
    monkeypatch.setattr(
        investigations,
        "run_soc_conversation",
        lambda **kwargs: {
            "conversation_id": kwargs["conversation_id"],
            "assistant_message": (
                "I checked the authentication sequence. "
                "No successful login followed the failures."
            ),
            "response": {
                "successful_login_after_failures": False,
                "severity": "high",
            },
            "tools_used": [
                "build_authentication_timeline",
                "check_successful_login_after_failures",
            ],
            "activities": [],
            "active_investigation_id": None,
            "active_alert_id": "alert-1",
            "investigation": None,
        },
    )

    response = investigations.chat_with_soc_orchestrator(
        OrchestratorChatRequest(
            message="Investigate the failed and successful login sequence.",
            conversation_id="conversation-123",
        ),
        PRINCIPAL,
    )

    data = response["data"]
    assert data["conversation_id"] == "conversation-123"
    assert data["response"]["successful_login_after_failures"] is False
    assert data["tools_used"] == [
        "build_authentication_timeline",
        "check_successful_login_after_failures",
    ]
    assert data["assistant_message"].startswith("I checked")


def test_conversational_endpoint_generates_thread_id(monkeypatch):
    monkeypatch.setattr(
        investigations,
        "run_soc_conversation",
        lambda **kwargs: {
            "conversation_id": kwargs["conversation_id"],
            "assistant_message": "What evidence should I inspect?",
            "response": {},
            "tools_used": [],
            "activities": [],
            "active_investigation_id": None,
            "active_alert_id": None,
            "investigation": None,
        },
    )

    response = investigations.chat_with_soc_orchestrator(
        OrchestratorChatRequest(message="analyze"),
        PRINCIPAL,
    )

    data = response["data"]
    assert len(data["conversation_id"]) == 32
    assert data["assistant_message"] == "What evidence should I inspect?"
    assert data["tools_used"] == []
