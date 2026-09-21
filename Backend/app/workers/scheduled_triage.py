"""Periodically ask the SOC assistant to triage recent alerts, unattended."""

import argparse
import signal
import time
import uuid

import structlog

from app.config import settings
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.soc_assistant.service import SOCAssistant


logger = structlog.get_logger("tsage.worker.scheduled_triage")
_running = True


def _stop(*_: object) -> None:
    global _running
    _running = False


def run_cycle() -> dict[str, object]:
    hours = settings.SCHEDULED_TRIAGE_WINDOW_HOURS
    conversation_id = f"scheduled-triage-{uuid.uuid4().hex}"
    result = SOCAssistant(gateway=get_wazuh_gateway()).respond(
        message=f"perform alert triage on the last {hours} hours",
        conversation_id=conversation_id,
        organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
        user_id="system-scheduler",
    )
    return {
        "conversation_id": conversation_id,
        "command": result.selected_command.value,
        "activity_count": len(result.activities),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Periodically triage recent Wazuh alerts with the SOC assistant.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one triage cycle and exit.",
    )
    args = parser.parse_args(argv)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    if args.once:
        run_cycle()
        return
    if not settings.SCHEDULED_TRIAGE_ENABLED:
        logger.warning("scheduled_triage_disabled")
        return
    interval = max(1, int(settings.SCHEDULED_TRIAGE_INTERVAL_HOURS * 3600))
    logger.info(
        "scheduled_triage_worker_started",
        interval_hours=settings.SCHEDULED_TRIAGE_INTERVAL_HOURS,
        window_hours=settings.SCHEDULED_TRIAGE_WINDOW_HOURS,
    )
    while _running:
        # Wait a full interval before the first run too, so a restart doesn't
        # immediately trigger a fresh triage burst.
        deadline = time.monotonic() + interval
        while _running and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))
        if not _running:
            break
        started = time.monotonic()
        try:
            result = run_cycle()
            logger.info(
                "scheduled_triage_cycle_completed",
                elapsed_ms=round((time.monotonic() - started) * 1000),
                **result,
            )
        except Exception as exc:
            logger.error(
                "scheduled_triage_cycle_failed",
                error_type=type(exc).__name__,
                exc_info=True,
            )


if __name__ == "__main__":
    main()
