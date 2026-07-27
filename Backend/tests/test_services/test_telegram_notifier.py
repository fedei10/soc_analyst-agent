"""Checks for the Telegram push notifier and severity/allowlist gating."""

from app.services.telegram.notifier import (
    TelegramNotifier,
    allowed_chat_ids,
    format_approval_alert,
    format_escalation_alert,
    format_finding_alert,
    meets_finding_severity_threshold,
)


def test_not_configured_without_both_credentials():
    assert TelegramNotifier(bot_token="", chat_id="123").configured is False
    assert TelegramNotifier(bot_token="tok", chat_id="").configured is False
    assert TelegramNotifier(bot_token="tok", chat_id="123").configured is True


def test_send_without_configuration_is_a_noop_not_an_error():
    notifier = TelegramNotifier(bot_token="", chat_id="")
    assert notifier.send("hello") is False


def test_send_swallows_http_failures(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr("app.services.telegram.notifier.httpx.post", boom)
    notifier = TelegramNotifier(bot_token="tok", chat_id="123")
    assert notifier.send("hello") is False


def test_send_posts_to_the_configured_chat(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        return FakeResponse()

    monkeypatch.setattr("app.services.telegram.notifier.httpx.post", fake_post)
    notifier = TelegramNotifier(bot_token="tok", chat_id="123")
    assert notifier.send("hello") is True
    assert captured["url"] == "https://api.telegram.org/bottok/sendMessage"
    assert captured["json"]["chat_id"] == "123"
    assert captured["json"]["text"] == "hello"


def test_severity_threshold_defaults_to_high(monkeypatch):
    monkeypatch.setattr(
        "app.services.telegram.notifier.settings.TELEGRAM_MIN_FINDING_SEVERITY",
        "high",
    )
    assert meets_finding_severity_threshold("critical") is True
    assert meets_finding_severity_threshold("high") is True
    assert meets_finding_severity_threshold("medium") is False


def test_allowed_chat_ids_falls_back_to_default_chat(monkeypatch):
    monkeypatch.setattr(
        "app.services.telegram.notifier.settings.TELEGRAM_ALLOWED_CHAT_IDS", ""
    )
    monkeypatch.setattr(
        "app.services.telegram.notifier.settings.TELEGRAM_CHAT_ID", "555"
    )
    assert allowed_chat_ids() == frozenset({"555"})

    monkeypatch.setattr(
        "app.services.telegram.notifier.settings.TELEGRAM_ALLOWED_CHAT_IDS",
        "111, 222",
    )
    assert allowed_chat_ids() == frozenset({"111", "222"})


def test_message_formatters_include_key_fields():
    finding_text = format_finding_alert(
        {
            "severity": "critical",
            "finding_id": "FND-1",
            "alert_count": 5,
            "finding": {"title": "SSH brute force"},
            "verdict": {"verdict": "malicious", "confidence": 0.9},
        }
    )
    assert "SSH brute force" in finding_text
    assert "FND-1" in finding_text

    approval_text = format_approval_alert(
        {
            "investigation_id": "INV-1",
            "alert_id": "AL-1",
            "approval_request": {
                "required_role": "soc_l2",
                "action_ids": ["a1", "a2"],
            },
        }
    )
    assert "INV-1" in approval_text
    assert "soc_l2" in approval_text

    escalation_text = format_escalation_alert(
        {
            "status": "failed",
            "investigation_id": "INV-2",
            "alert_id": "AL-2",
            "current_stage": "execute",
            "error": {"message": "executor timed out"},
        }
    )
    assert "INV-2" in escalation_text
    assert "executor timed out" in escalation_text
