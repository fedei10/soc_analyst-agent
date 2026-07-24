"""Safe timers for Wazuh server and indexer operations."""

from __future__ import annotations

import time
from contextlib import contextmanager
from collections.abc import Iterator
from typing import Any

import structlog


logger = structlog.get_logger("tsage.wazuh")


@contextmanager
def observe_wazuh_call(
    *,
    operation: str,
    component: str,
    metadata: dict[str, Any] | None = None,
) -> Iterator[None]:
    started = time.perf_counter()
    safe_metadata = metadata or {}
    logger.info(
        "wazuh_request_started",
        wazuh_operation=operation,
        wazuh_component=component,
        **safe_metadata,
    )
    try:
        yield
    except Exception as exc:
        logger.exception(
            "wazuh_request_failed",
            wazuh_operation=operation,
            wazuh_component=component,
            error_type=type(exc).__name__,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            **safe_metadata,
        )
        raise
    else:
        logger.info(
            "wazuh_request_completed",
            wazuh_operation=operation,
            wazuh_component=component,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            **safe_metadata,
        )
