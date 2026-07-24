"""Context variable helpers shared by logs, traces, and durable audits."""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
from typing import Any

import structlog


CORRELATION_KEYS = {
    "request_id",
    "trace_id",
    "span_id",
    "run_id",
    "thread_id",
    "conversation_id",
    "investigation_id",
    "organization_id",
    "user_id",
    "agent_role",
    "langgraph_node",
}


def bind_context(**values: Any) -> None:
    structlog.contextvars.bind_contextvars(
        **{
            key: value
            for key, value in values.items()
            if key in CORRELATION_KEYS and value not in (None, "")
        }
    )


def get_correlation_context() -> dict[str, Any]:
    return {
        key: value
        for key, value in structlog.contextvars.get_contextvars().items()
        if key in CORRELATION_KEYS and value not in (None, "")
    }


@contextmanager
def correlation_context(**values: Any) -> Iterator[None]:
    tokens = structlog.contextvars.bind_contextvars(
        **{
            key: value
            for key, value in values.items()
            if key in CORRELATION_KEYS and value not in (None, "")
        }
    )
    try:
        yield
    finally:
        structlog.contextvars.reset_contextvars(**tokens)
