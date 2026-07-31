"""Run durable investigation, verification, and temporary-action recovery."""

from __future__ import annotations

import argparse
import signal
import time
from typing import Any

import structlog

from app.config import settings
from app.mape_k.temporary_actions import recover_expired_temporary_actions
from app.mape_k.wazuh_response import WazuhTemporaryActionRollbackAdapter
from app.orchestration.investigation_service import get_investigation_service


logger = structlog.get_logger("tsage.worker.orchestration")
_running = True


def _stop(*_: object) -> None:
    global _running
    _running = False


def run_cycle(service=None) -> dict[str, Any]:
    service = service or get_investigation_service()
    orchestration = service.process_background_once()
    adapter = WazuhTemporaryActionRollbackAdapter(
        repository=service.repository,
    )
    recoveries = [
        {
            "organization_id": organization_id,
            **recover_expired_temporary_actions(
                repository=service.repository,
                organization_id=organization_id,
                adapter=adapter,
            ),
        }
        for organization_id
        in service.repository.list_response_action_organizations()
    ]
    return {
        "orchestration": orchestration,
        "recoveries": recoveries,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Run queued TSAGE investigations and recovery tasks.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one orchestration cycle and exit.",
    )
    args = parser.parse_args(argv)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    if args.once:
        run_cycle()
        return
    interval = max(1, int(settings.MAPEK_WORKER_INTERVAL_SECONDS))
    logger.info(
        "orchestration_worker_started",
        interval_seconds=interval,
    )
    while _running:
        started = time.monotonic()
        try:
            result = run_cycle()
            logger.info(
                "orchestration_cycle_completed",
                processed=result["orchestration"]["processed"],
                recovery_organizations=len(result["recoveries"]),
            )
        except Exception as exc:
            logger.error(
                "orchestration_cycle_failed",
                error_type=type(exc).__name__,
                exc_info=True,
            )
        delay = max(1.0, interval - (time.monotonic() - started))
        deadline = time.monotonic() + delay
        while _running and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))


if __name__ == "__main__":
    main()
