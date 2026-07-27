"""Long-polling Telegram command worker.

Answers /alerts, /status, /ask, and every other soc_assistant command through
the same SOCAssistant.respond() the web chat uses - no separate command
parser, no separate read path. Only chats in the configured allowlist are
served; everyone else is silently ignored. The assistant's command catalog
has no approve/execute command, so this worker can never trigger a response
action - it can only read and start investigations up to the human-approval
checkpoint.
"""

from __future__ import annotations

import argparse
import signal
import time
from typing import Any

import httpx
import structlog

from app.config import settings
from app.services.telegram.notifier import allowed_chat_ids, get_telegram_notifier
from app.soc_assistant.service import SOCAssistant

logger = structlog.get_logger("tsage.worker.telegram_bot")
_running = True
TELEGRAM_ORGANIZATION_ID = "telegram"


def _stop(*_: object) -> None:
    global _running
    _running = False


def handle_update(
    update: dict[str, Any],
    *,
    assistant: SOCAssistant,
    allowed_chats: frozenset[str],
) -> tuple[str, str] | None:
    """Returns (chat_id, reply_text), or None if the update should be skipped."""
    message = update.get("message") or update.get("edited_message")
    if not isinstance(message, dict):
        return None
    chat_id = str((message.get("chat") or {}).get("id") or "")
    text = str(message.get("text") or "").strip()
    if not chat_id or not text:
        return None
    if chat_id not in allowed_chats:
        logger.warning("telegram_unauthorized_chat", chat_id=chat_id)
        return None
    try:
        response = assistant.respond(
            message=text,
            conversation_id=f"telegram-{chat_id}",
            organization_id=TELEGRAM_ORGANIZATION_ID,
            user_id=f"telegram:{chat_id}",
        )
        return chat_id, response.assistant_message
    except Exception as exc:
        logger.error("telegram_command_failed", error_type=type(exc).__name__)
        return chat_id, "The SOC assistant could not process that request."


def _get_updates(bot_token: str, offset: int, timeout: int) -> list[dict[str, Any]]:
    response = httpx.get(
        f"https://api.telegram.org/bot{bot_token}/getUpdates",
        params={
            "offset": offset,
            "timeout": timeout,
            "allowed_updates": '["message"]',
        },
        timeout=timeout + 10,
    )
    response.raise_for_status()
    return response.json().get("result", [])


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Answer SOC assistant commands sent through Telegram.",
    )
    parser.parse_args(argv)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    bot_token = settings.TELEGRAM_BOT_TOKEN.get_secret_value().strip()
    if not bot_token:
        logger.error("telegram_bot_token_missing")
        return
    allowed_chats = allowed_chat_ids()
    if not allowed_chats:
        logger.error("telegram_no_allowed_chats_configured")
        return

    notifier = get_telegram_notifier()
    assistant = SOCAssistant()
    offset = 0
    logger.info("telegram_bot_worker_started", allowed_chats=len(allowed_chats))

    while _running:
        try:
            updates = _get_updates(
                bot_token,
                offset,
                settings.TELEGRAM_POLL_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.warning("telegram_poll_failed", error_type=type(exc).__name__)
            time.sleep(5)
            continue

        for update in updates:
            offset = int(update["update_id"]) + 1
            result = handle_update(
                update,
                assistant=assistant,
                allowed_chats=allowed_chats,
            )
            if result is not None:
                chat_id, reply_text = result
                notifier.send_to(chat_id, reply_text, parse_mode=None)


if __name__ == "__main__":
    main()
