"""Regression cover for "new" vs "recent" vs "changed" in the SOC chat.

These three questions have three different reference points - the user's
previous successful check, a time window, and a state comparison - and used to
collapse into one broad alert listing that reported a baseline's entire history
as newly created alerts.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.db.repositories.alert_memory import InMemoryAlertMemoryRepository
from app.services.wazuh.models import AlertEvidence, AlertIngestionDocument
from app.soc_assistant.router import AssistantIntentRouter
from app.soc_assistant.schemas import AssistantCommandName
from app.soc_assistant.service import SOCAssistant


class DurableMemory(InMemoryAlertMemoryRepository):
    durable = True


class FakeFindingRepository:
    """Finding store whose rows the test can mutate between checks."""

    def __init__(self, records=None):
        self.records = list(records or [])

    def list(self, **_kwargs):
        return list(self.records)


class FakeGateway:
    def search_alerts(self, **kwargs):  # pragma: no cover - must stay unused
        raise AssertionError("durable memory must not fall back to live Wazuh")


class UnusedToolAgent:
    def answer(self, **_kwargs):  # pragma: no cover - must stay unused
        raise AssertionError("a change report must not spend a model call")


def finding(
    finding_id: str,
    *,
    created_at: datetime,
    updated_at: datetime,
    verdict: str | None = "suspicious",
):
    return {
        "finding_id": finding_id,
        "status": "open",
        "version": 1,
        "event_type": "ssh_brute_force",
        "created_at": created_at,
        "updated_at": updated_at,
        "finding": {
            "finding_id": finding_id,
            "title": "Repeated SSH authentication failures",
            "summary": "Correlated from persisted Wazuh alerts.",
            "severity": "high",
        },
        "verdict": {"verdict": verdict, "confidence": 0.6} if verdict else {},
    }


def alert_document(document_id: str) -> AlertIngestionDocument:
    return AlertIngestionDocument(
        document_id=document_id,
        index_name="wazuh-alerts-test",
        normalized=AlertEvidence(
            alert_id=document_id,
            timestamp=datetime.now(UTC),
            agent_id="001",
            agent_name="server-a",
            rule_id="5712",
            rule_level=10,
            description="sshd brute force",
            source_ip="192.0.2.10",
        ),
        raw_document={},
    )


@pytest.fixture
def wired(monkeypatch):
    memory = DurableMemory()
    findings = FakeFindingRepository()
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    monkeypatch.setattr(
        "app.soc_assistant.service.get_alert_memory_repository",
        lambda: memory,
    )
    monkeypatch.setattr(
        "app.soc_assistant.service.get_finding_repository",
        lambda: findings,
    )
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=object(),
        router=AssistantIntentRouter(),
        tool_agent=UnusedToolAgent(),
    )
    return service, memory, findings


def ask(service, message, *, organization_id="org-a", user_id="analyst-1"):
    return service.respond(
        message=message,
        conversation_id="conversation-test",
        organization_id=organization_id,
        user_id=user_id,
    )


def test_first_new_alerts_question_establishes_a_baseline(wired):
    service, memory, findings = wired
    memory.remember_alert_document(alert_document("alert-old"))
    findings.records = [
        finding(
            "FND-1",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            updated_at=datetime.now(UTC) - timedelta(hours=2),
        )
    ]

    result = ask(service, "any new alerts?")

    assert result.selected_command == AssistantCommandName.ALERTS
    assert result.response["baseline_established"] is True
    # The window's existing history is not "new".
    assert result.response["new_alerts"] is None
    assert result.response["new_findings"] is None
    assert result.response["recent_alerts"] == 1
    assert "cannot yet say what is new" in result.assistant_message
    assert result.response["cursor_advanced"] is True


def test_second_check_with_no_changes_names_the_previous_check(wired):
    service, _, findings = wired
    findings.records = [
        finding(
            "FND-1",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            updated_at=datetime.now(UTC) - timedelta(hours=2),
        )
    ]
    ask(service, "any new alerts?")

    result = ask(service, "any new alerts?")

    assert result.response["baseline_established"] is False
    assert result.response["new_alerts"] == 0
    assert result.response["new_findings"] == 0
    assert result.response["updated_findings"] == 0
    assert "No new alerts have appeared since your previous check at" in (
        result.assistant_message
    )
    assert "1 existing finding" in result.assistant_message


def test_new_alerts_after_the_baseline_are_reported(wired):
    service, memory, _ = wired
    ask(service, "any new alerts?")

    memory.remember_alert_document(alert_document("alert-fresh"))
    result = ask(service, "any new alerts?")

    assert result.response["new_alerts"] == 1
    assert "1 new alert" in result.assistant_message


def test_updated_finding_without_new_alerts(wired):
    service, _, findings = wired
    created = datetime.now(UTC) - timedelta(hours=3)
    findings.records = [finding("FND-1", created_at=created, updated_at=created)]
    ask(service, "any new alerts?")

    findings.records = [
        finding("FND-1", created_at=created, updated_at=datetime.now(UTC))
    ]
    result = ask(service, "any new findings?")

    assert result.response["new_alerts"] == 0
    assert result.response["new_findings"] == 0
    assert result.response["updated_findings"] == 1
    assert "1 updated finding" in result.assistant_message


def test_historical_window_question_does_not_advance_the_cursor(wired):
    service, memory, _ = wired
    ask(service, "any new alerts?")
    baseline = memory.get_user_cursor("org-a:analyst-1")

    result = ask(service, "what alerts came in over the last 6 hours?")

    assert result.response["mode"] == "recent"
    assert result.response["cursor_advanced"] is False
    assert memory.get_user_cursor("org-a:analyst-1") == baseline


def test_recent_question_is_a_window_not_a_comparison(wired):
    service, _, _ = wired

    result = ask(service, "any recent alerts?")

    assert result.response["mode"] == "recent"
    assert result.response["new_alerts"] is None
    assert "time window, not a comparison" in result.assistant_message


def test_new_analysis_question_reports_verdict_activity(wired):
    service, _, findings = wired
    created = datetime.now(UTC) - timedelta(hours=3)
    findings.records = [finding("FND-1", created_at=created, updated_at=created)]
    ask(service, "any new alerts?")

    result = ask(service, "is there any new analysis?")

    assert result.response["change_subject"] == "analysis"
    assert result.response["reanalyzed_findings"] == 0
    assert "No new analysis since your previous check at" in (
        result.assistant_message
    )


def test_change_reports_are_conversational_not_raw_json(wired):
    service, _, _ = wired

    result = ask(service, "any new alerts?")

    assert result.response["display_mode"] == "conversation"
    assert not result.assistant_message.lstrip().startswith("{")


def test_cursor_is_scoped_per_organization(wired):
    service, memory, _ = wired
    ask(service, "any new alerts?", organization_id="org-a")

    other = ask(service, "any new alerts?", organization_id="org-b")

    # A second tenant starts from its own baseline, not org-a's mark.
    assert other.response["baseline_established"] is True
    assert memory.get_user_cursor("org-a:analyst-1") is not None
    assert memory.get_user_cursor("org-b:analyst-1") is not None


def test_out_of_order_check_does_not_rewind_the_cursor():
    memory = DurableMemory()
    later = datetime.now(UTC)
    earlier = later - timedelta(minutes=10)

    memory.advance_user_cursor("org-a:analyst-1", later)
    memory.advance_user_cursor("org-a:analyst-1", earlier)

    assert memory.get_user_cursor("org-a:analyst-1") == later


@pytest.mark.parametrize(
    "message",
    [
        "which IP is responsible for most of these alerts?",
        "why did rule 5712 fire so many times?",
        "is this alert volume a brute force attempt?",
    ],
)
def test_investigative_alert_questions_reach_the_analyst_not_a_listing(message):
    intent, _ = AssistantIntentRouter().route(message)

    assert intent.command == AssistantCommandName.CHAT
    assert intent.arguments["question"] == message


@pytest.mark.parametrize(
    ("message", "mode"),
    [
        ("any new alerts?", "new"),
        ("any new findings?", "new"),
        ("is there any new analysis?", "new"),
        ("any recent alerts?", "recent"),
        ("what changed?", "changed"),
    ],
)
def test_change_questions_classify_into_distinct_modes(message, mode):
    intent, _ = AssistantIntentRouter().route(message)

    assert intent.command == AssistantCommandName.ALERTS
    assert intent.arguments["change_mode"] == mode
