from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.auth.deps import AuthPrincipal
from app.api.v1.endpoints import investigations
from app.api.v1.schemas.investigation import (
    AgentChatRequest,
    ApprovalDecisionInput,
    InvestigationCreate,
    L1Result,
    L2Result,
)
from app.main import app
from app.soc_assistant.schemas import (
    AssistantCommandName,
    AssistantRequest,
    AssistantResponse,
)


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
    assert (
        "/api/v1/investigations/{investigation_id}/verification/resume"
        in paths
    )
    assert "/api/v1/investigations/{investigation_id}/report" in paths
    assert "/api/v1/investigations/{investigation_id}/tier-reports" in paths
    assert "/api/v1/investigations/{investigation_id}/agent-runs" in paths
    assert "/api/v1/investigations/{investigation_id}/audit" in paths
    assert "/api/v1/investigations/{investigation_id}/approvals" in paths
    assert "/api/v1/investigations/{investigation_id}/actions" in paths
    assert "/api/v1/investigations/{investigation_id}/events" in paths
    assert "/api/v1/health/database" in paths
    assert "/api/v1/health/storage" in paths
    assert "/api/v1/health/ingestion" in paths
    assert "/api/v1/soc/chat" in paths
    assert "/api/v1/soc/conversations" in paths
    assert "/api/v1/soc/conversations/{conversation_id}/messages" in paths
    assert "/api/v1/soc/orchestrator/chat" in paths
    assert "/api/v1/soc/orchestrator/chat/stream" in paths
    assert "/api/v1/soc/assistant/commands" in paths
    assert "/api/v1/soc/overview" in paths
    assert "/api/v1/soc/platform" in paths


def test_soc_platform_metadata_does_not_initialize_model_providers(monkeypatch):
    service = SimpleNamespace(list_history=lambda **_: [])
    monkeypatch.setattr(investigations, "get_investigation_service", lambda: service)

    response = investigations.get_soc_platform(PRINCIPAL)

    assignments = response["data"]["model_assignments"]
    assert [(item["role"], item["provider"]) for item in assignments] == [
        ("chat", "oxy"),
        ("l1", "cerebras"),
        ("l2", "groq"),
        ("l3", "oxy"),
        ("mape_k", "oxy"),
    ]
    assert response["data"]["response_policy"]["human_approval_required"] is True


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


def test_approval_endpoint_uses_verified_server_actor(monkeypatch):
    captured = {}
    principal = AuthPrincipal(
        user_id="user_analyst",
        session_id="sess_analyst",
        scope_id="user_analyst",
        roles=("soc_l1", "soc_l2"),
    )

    class FakeService:
        def submit_approval(self, investigation_id, **kwargs):
            captured["investigation_id"] = investigation_id
            captured.update(kwargs)
            return {
                "investigation_id": investigation_id,
                "organization_id": principal.scope_id,
                "pending_nodes": ["execution_authorization"],
                "audit_events": [],
            }

    monkeypatch.setattr(
        investigations,
        "_snapshot",
        lambda *args, **kwargs: {"pending_nodes": ["human_approval"]},
    )
    monkeypatch.setattr(
        investigations,
        "get_investigation_service",
        lambda: FakeService(),
    )
    monkeypatch.setattr(investigations, "_publish_activity", lambda _: None)

    investigations.decide_investigation(
        "INV-001",
        ApprovalDecisionInput(
            approval_id="APR-001",
            decision="approve",
            comment="Approved for temporary containment.",
        ),
        principal,
    )

    assert captured["actor_user_id"] == "user_analyst"
    assert captured["actor_roles"] == principal.roles
    assert captured["organization_id"] == principal.scope_id
    assert "approved_by" not in captured
    assert "approver_roles" not in captured


def test_verification_resume_uses_verified_server_actor(monkeypatch):
    captured = {}
    principal = AuthPrincipal(
        user_id="user_executor",
        session_id="sess_executor",
        scope_id="user_executor",
        roles=("soc_l1", "soc_l3"),
    )

    class FakeService:
        def resume_verification(self, investigation_id, **kwargs):
            captured["investigation_id"] = investigation_id
            captured.update(kwargs)
            return {
                "investigation_id": investigation_id,
                "organization_id": principal.scope_id,
                "pending_nodes": [],
                "audit_events": [],
            }

    monkeypatch.setattr(
        investigations,
        "get_investigation_service",
        lambda: FakeService(),
    )
    monkeypatch.setattr(investigations, "_publish_activity", lambda _: None)

    investigations.resume_investigation_verification(
        "INV-001",
        principal,
    )

    assert captured == {
        "investigation_id": "INV-001",
        "resumed_by": "user_executor",
        "executor_roles": principal.roles,
        "organization_id": principal.scope_id,
    }


def test_tier_agent_chat_is_retired():
    with pytest.raises(HTTPException) as error:
        investigations.chat_with_soc_agent(
            AgentChatRequest(
                tier="l1",
                message="Review high-severity Wazuh alerts.",
            ),
            PRINCIPAL,
        )
    assert error.value.status_code == 410


def _assistant_response() -> AssistantResponse:
    return AssistantResponse(
        conversation_id="conversation-123",
        assistant_message="Found 2 alerts.",
        response={"finding_count": 1},
        tools_used=["search_alerts"],
        selected_command=AssistantCommandName.ALERTS,
    )


def test_orchestrator_chat_runs_bounded_assistant(monkeypatch):
    monkeypatch.setattr(investigations, "_enforce_rate_limit", lambda *args, **kwargs: None)

    class FakeAssistant:
        def __init__(self, **kwargs):
            pass

        def respond(self, **kwargs):
            assert kwargs["message"] == "/alerts"
            assert kwargs["organization_id"] == PRINCIPAL.scope_id
            return _assistant_response()

    monkeypatch.setattr(investigations, "SOCAssistant", FakeAssistant)
    response = investigations.chat_with_soc_orchestrator(
        AssistantRequest(
            message="/alerts",
            conversation_id="conversation-123",
        ),
        PRINCIPAL,
        object(),
    )

    assert response["data"]["selected_command"] == "alerts"
    assert response["data"]["tools_used"] == ["search_alerts"]


def test_orchestrator_stream_returns_event_stream(monkeypatch):
    monkeypatch.setattr(investigations, "_enforce_rate_limit", lambda *args, **kwargs: None)

    class FakeAssistant:
        def __init__(self, **kwargs):
            pass

        def respond(self, **kwargs):
            return _assistant_response()

    monkeypatch.setattr(investigations, "SOCAssistant", FakeAssistant)
    response = investigations.stream_with_soc_orchestrator(
        AssistantRequest(message="/alerts"),
        PRINCIPAL,
        object(),
    )
    assert response.media_type == "text/event-stream"
    assert response.headers["cache-control"] == "no-cache"


def test_soc_overview_is_scoped_and_survives_wazuh_outage(monkeypatch):
    class FakeService:
        def list_history(self, *, limit, organization_id):
            assert limit == 100
            assert organization_id == PRINCIPAL.scope_id
            return [
                {
                    "investigation_id": "INV-1",
                    "alert_id": "alert-1",
                    "status": "running",
                    "current_stage": "l1",
                    "executed_actions": [],
                }
            ]

        def history_count(self, *, organization_id):
            assert organization_id == PRINCIPAL.scope_id
            return 1

    class FakeFindingRepository:
        def list(self, *, organization_id, limit):
            assert (
                organization_id
                == investigations.settings.WAZUH_INGESTION_ORGANIZATION_ID
            )
            assert limit == 100
            return []

    class UnavailableGateway:
        def alert_summary(self, *, hours):
            assert hours == 24
            raise ConnectionError("tunnel unavailable")

    monkeypatch.setattr(
        investigations,
        "get_investigation_service",
        lambda: FakeService(),
    )
    response = investigations.get_soc_overview(
        PRINCIPAL,
        UnavailableGateway(),
        FakeFindingRepository(),
        24,
    )

    assert response["data"]["wazuh_status"] == "unavailable"
    assert response["data"]["metrics"]["active_investigations"]["value"] == 1
    assert response["data"]["metrics"]["wazuh_alerts"]["value"] is None
