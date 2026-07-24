"""LangChain callback events without prompts, model output, or tool payloads."""

from __future__ import annotations

import time
from threading import Lock
from typing import Any
from uuid import UUID

import structlog
from langchain_core.callbacks import BaseCallbackHandler

from app.config import settings


logger = structlog.get_logger("tsage.langchain")


class SOCObservabilityCallback(BaseCallbackHandler):
    """Record model and tool lifecycle metadata while excluding content."""

    def __init__(self) -> None:
        self._started: dict[UUID, float] = {}
        self._names: dict[UUID, str] = {}
        self._lock = Lock()

    def _start(self, run_id: UUID, name: str) -> None:
        with self._lock:
            self._started[run_id] = time.perf_counter()
            self._names[run_id] = name

    def _finish(self, run_id: UUID) -> tuple[str, float]:
        with self._lock:
            started = self._started.pop(run_id, time.perf_counter())
            name = self._names.pop(run_id, "unknown")
        return name, round((time.perf_counter() - started) * 1000, 2)

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        model = str(
            kwargs.get("invocation_params", {}).get("model")
            or serialized.get("name")
            or "unknown"
        )
        self._start(run_id, model)
        logger.info("llm_call_started", model=model, prompt_count=len(prompts))

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        model = str(
            kwargs.get("invocation_params", {}).get("model")
            or serialized.get("name")
            or "unknown"
        )
        self._start(run_id, model)
        logger.info(
            "llm_call_started",
            model=model,
            message_batch_count=len(messages),
        )

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        model, duration_ms = self._finish(run_id)
        logger.info(
            "llm_call_completed",
            model=model,
            duration_ms=duration_ms,
            slow=duration_ms >= settings.SLOW_MODEL_THRESHOLD_MS,
        )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        model, duration_ms = self._finish(run_id)
        logger.error(
            "llm_call_failed",
            model=model,
            duration_ms=duration_ms,
            error_type=type(error).__name__,
        )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        tool_name = str(serialized.get("name") or "unknown")
        self._start(run_id, tool_name)
        logger.info("agent_tool_started", tool_name=tool_name)

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        tool_name, duration_ms = self._finish(run_id)
        logger.info(
            "agent_tool_completed",
            tool_name=tool_name,
            duration_ms=duration_ms,
            slow=duration_ms >= settings.SLOW_TOOL_THRESHOLD_MS,
            result_type=type(output).__name__,
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        tool_name, duration_ms = self._finish(run_id)
        logger.error(
            "agent_tool_failed",
            tool_name=tool_name,
            duration_ms=duration_ms,
            error_type=type(error).__name__,
        )


def observability_callbacks() -> list[BaseCallbackHandler]:
    return [SOCObservabilityCallback()]
