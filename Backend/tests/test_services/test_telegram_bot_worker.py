"""Checks for the Telegram command-worker's per-update handling."""

from app.workers.telegram_bot import handle_update


class FakeAssistant:
    def __init__(self, message="here are your alerts"):
        self.calls = []
        self.message = message

    def respond(self, **kwargs):
        self.calls.append(kwargs)
        return type("R", (), {"assistant_message": self.message})()


class FailingAssistant:
    def respond(self, **kwargs):
        raise RuntimeError("assistant unavailable")


def _update(chat_id="123", text="/alerts"):
    return {
        "update_id": 1,
        "message": {"chat": {"id": chat_id}, "text": text},
    }


def test_authorized_chat_gets_routed_to_the_assistant():
    assistant = FakeAssistant()
    result = handle_update(
        _update(),
        assistant=assistant,
        allowed_chats=frozenset({"123"}),
    )
    assert result == ("123", "here are your alerts")
    assert assistant.calls[0]["message"] == "/alerts"
    assert assistant.calls[0]["conversation_id"] == "telegram-123"
    assert assistant.calls[0]["user_id"] == "telegram:123"


def test_unauthorized_chat_is_ignored():
    assistant = FakeAssistant()
    result = handle_update(
        _update(chat_id="999"),
        assistant=assistant,
        allowed_chats=frozenset({"123"}),
    )
    assert result is None
    assert assistant.calls == []


def test_non_message_update_is_ignored():
    assistant = FakeAssistant()
    result = handle_update(
        {"update_id": 2, "channel_post": {}},
        assistant=assistant,
        allowed_chats=frozenset({"123"}),
    )
    assert result is None


def test_empty_text_is_ignored():
    assistant = FakeAssistant()
    result = handle_update(
        _update(text=""),
        assistant=assistant,
        allowed_chats=frozenset({"123"}),
    )
    assert result is None


def test_assistant_failure_replies_with_a_friendly_error():
    result = handle_update(
        _update(),
        assistant=FailingAssistant(),
        allowed_chats=frozenset({"123"}),
    )
    assert result is not None
    chat_id, text = result
    assert chat_id == "123"
    assert "could not process" in text
