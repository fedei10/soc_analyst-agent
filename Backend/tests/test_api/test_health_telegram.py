"""Checks that Telegram status is surfaced without gating overall health."""

from app.api.v1.endpoints import health


class FakeGateway:
    def indexer_health(self):
        return {"status": "healthy"}

    def validate_server(self):
        return {}


def test_telegram_disabled_does_not_flip_overall_health_to_unhealthy(monkeypatch):
    monkeypatch.setattr(health, "effective_llm_api_key", lambda: "key")
    monkeypatch.setattr(
        health,
        "get_telegram_notifier",
        lambda: type("N", (), {"configured": False})(),
    )

    body, code = health._build_services_health(FakeGateway())

    assert code == 200
    assert body.status == "healthy"
    assert body.services["telegram"].status == "disabled"


def test_telegram_configured_reports_healthy(monkeypatch):
    monkeypatch.setattr(health, "effective_llm_api_key", lambda: "key")
    monkeypatch.setattr(
        health,
        "get_telegram_notifier",
        lambda: type("N", (), {"configured": True})(),
    )

    _, _ = health._build_services_health(FakeGateway())
    body, _ = health._build_services_health(FakeGateway())

    assert body.services["telegram"].status == "healthy"
