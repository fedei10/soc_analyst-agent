"""Outbound Telegram connector: push alert notifications.

Credentials come from environment settings only (TELEGRAM_BOT_TOKEN,
TELEGRAM_CHAT_ID), the same as every other credential in this app - never
stored in the database, never returned to the browser.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger("tsage.telegram")

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
MAX_MESSAGE_CHARS = 3500


class TelegramNotifier:
    def __init__(
        self,
        *,
        bot_token: str | None = None,
        chat_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.bot_token = (
            bot_token
            if bot_token is not None
            else settings.TELEGRAM_BOT_TOKEN.get_secret_value().strip()
        )
        self.chat_id = (
            chat_id if chat_id is not None else settings.TELEGRAM_CHAT_ID.strip()
        )
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.TELEGRAM_TIMEOUT_SECONDS
        )

    @property
    def configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send_to(
        self,
        chat_id: str,
        text: str,
        *,
        parse_mode: str | None = "HTML",
    ) -> bool:
        if not self.bot_token or not chat_id:
            return False
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text[:MAX_MESSAGE_CHARS],
            "disable_web_page_preview": True,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        try:
            response = httpx.post(url, json=payload, timeout=self.timeout_seconds)
            response.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("telegram_send_failed", error_type=type(exc).__name__)
            return False

    def send(self, text: str) -> bool:
        if not self.configured:
            return False
        return self.send_to(self.chat_id, text)


def _escape(value: Any) -> str:
    text = str(value if value is not None else "-")
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_finding_alert(record: dict[str, Any]) -> str:
    finding = record.get("finding") or {}
    verdict = record.get("verdict") or {}
    return (
        f"<b>New {_escape(record.get('severity'))} finding</b>\n"
        f"{_escape(finding.get('title') or record.get('finding_id'))}\n"
        f"Verdict: {_escape(verdict.get('verdict'))} "
        f"({round(float(verdict.get('confidence') or 0) * 100)}% confidence)\n"
        f"Alerts: {_escape(record.get('alert_count'))}\n"
        f"Finding ID: {_escape(record.get('finding_id'))}"
    )


def format_approval_alert(snapshot: dict[str, Any]) -> str:
    request = snapshot.get("approval_request") or {}
    return (
        "<b>SOC approval requested</b>\n"
        f"Investigation: {_escape(snapshot.get('investigation_id'))}\n"
        f"Alert: {_escape(snapshot.get('alert_id'))}\n"
        f"Required role: {_escape(request.get('required_role'))}\n"
        f"Actions: {_escape(len(request.get('action_ids') or []))}"
    )


def format_escalation_alert(snapshot: dict[str, Any]) -> str:
    error = snapshot.get("error") or {}
    advisory = snapshot.get("advisory_plan") or {}
    reason = (
        error.get("message")
        or snapshot.get("failure_reason")
        or advisory.get("rationale")
        or advisory.get("summary")
    )
    return (
        f"<b>Investigation {_escape(snapshot.get('status'))}</b>\n"
        f"Investigation: {_escape(snapshot.get('investigation_id'))}\n"
        f"Alert: {_escape(snapshot.get('alert_id'))}\n"
        f"Stage: {_escape(snapshot.get('current_stage'))}\n"
        f"Reason: {_escape(reason)}"
    )


def meets_finding_severity_threshold(severity: str) -> bool:
    return SEVERITY_RANK.get(severity.lower(), 0) >= SEVERITY_RANK.get(
        settings.TELEGRAM_MIN_FINDING_SEVERITY, 3
    )


def allowed_chat_ids() -> frozenset[str]:
    configured = settings.TELEGRAM_ALLOWED_CHAT_IDS.strip()
    if configured:
        return frozenset(
            value.strip() for value in configured.split(",") if value.strip()
        )
    default_chat = settings.TELEGRAM_CHAT_ID.strip()
    return frozenset({default_chat}) if default_chat else frozenset()


@lru_cache(maxsize=1)
def get_telegram_notifier() -> TelegramNotifier:
    return TelegramNotifier()
