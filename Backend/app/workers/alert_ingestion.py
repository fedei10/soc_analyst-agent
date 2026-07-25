"""Continuously ingest and correlate Wazuh alerts."""

import argparse
import signal
import time

import structlog

from app.config import settings
from app.services.wazuh.ingestion import AlertIngestionService


logger = structlog.get_logger("tsage.worker.alert_ingestion")
_running = True


def _stop(*_) -> None:
    global _running
    _running = False


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Ingest and correlate new Wazuh alerts.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one checkpointed ingestion cycle and exit.",
    )
    args = parser.parse_args(argv)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    service = AlertIngestionService()
    if args.once:
        service.ingest()
        return
    logger.info(
        "alert_ingestion_worker_started",
        interval_seconds=settings.WAZUH_INGESTION_INTERVAL_SECONDS,
    )
    while _running:
        started = time.monotonic()
        try:
            service.ingest()
        except Exception as exc:
            logger.error(
                "alert_ingestion_cycle_failed",
                error_type=type(exc).__name__,
            )
        elapsed = time.monotonic() - started
        delay = max(1.0, settings.WAZUH_INGESTION_INTERVAL_SECONDS - elapsed)
        deadline = time.monotonic() + delay
        while _running and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))


if __name__ == "__main__":
    main()
