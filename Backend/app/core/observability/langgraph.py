"""LangGraph node and route lifecycle events."""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Callable
from typing import Any

import structlog

from app.core.observability.context import correlation_context


logger = structlog.get_logger("tsage.langgraph")


def observed_node(
    node_name: str,
    *,
    role: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(function: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(function):
            @functools.wraps(function)
            async def async_wrapper(state: dict[str, Any], *args, **kwargs):
                return await _run_async(
                    function,
                    node_name,
                    role,
                    state,
                    args,
                    kwargs,
                )

            return async_wrapper

        @functools.wraps(function)
        def sync_wrapper(state: dict[str, Any], *args, **kwargs):
            return _run_sync(
                function,
                node_name,
                role,
                state,
                args,
                kwargs,
            )

        return sync_wrapper

    return decorator


def _started(node_name: str, role: str | None, state: dict[str, Any]) -> None:
    logger.info(
        "langgraph_node_started",
        node_name=node_name,
        agent_role=role,
        current_stage=state.get("current_stage"),
    )


def _completed(
    node_name: str,
    role: str | None,
    started: float,
    update: Any,
) -> None:
    logger.info(
        "langgraph_node_completed",
        node_name=node_name,
        agent_role=role,
        duration_ms=round((time.perf_counter() - started) * 1000, 2),
        updated_fields=sorted(update) if isinstance(update, dict) else [],
    )


def _run_sync(function, node_name, role, state, args, kwargs):
    started = time.perf_counter()
    with correlation_context(
        investigation_id=state.get("investigation_id"),
        langgraph_node=node_name,
        agent_role=role,
    ):
        _started(node_name, role, state)
        try:
            update = function(state, *args, **kwargs)
        except Exception as exc:
            logger.exception(
                "langgraph_node_failed",
                node_name=node_name,
                agent_role=role,
                error_type=type(exc).__name__,
                duration_ms=round(
                    (time.perf_counter() - started) * 1000,
                    2,
                ),
            )
            raise
        _completed(node_name, role, started, update)
        return update


async def _run_async(function, node_name, role, state, args, kwargs):
    started = time.perf_counter()
    with correlation_context(
        investigation_id=state.get("investigation_id"),
        langgraph_node=node_name,
        agent_role=role,
    ):
        _started(node_name, role, state)
        try:
            update = await function(state, *args, **kwargs)
        except Exception as exc:
            logger.exception(
                "langgraph_node_failed",
                node_name=node_name,
                agent_role=role,
                error_type=type(exc).__name__,
                duration_ms=round(
                    (time.perf_counter() - started) * 1000,
                    2,
                ),
            )
            raise
        _completed(node_name, role, started, update)
        return update


def observed_route(
    source_node: str,
    route: Callable[[dict[str, Any]], str],
) -> Callable[[dict[str, Any]], str]:
    @functools.wraps(route)
    def wrapper(state: dict[str, Any]) -> str:
        destination = route(state)
        logger.info(
            "langgraph_route_selected",
            source_node=source_node,
            destination_node=destination,
            route_reason_code=str(destination).upper(),
            severity=state.get("severity"),
        )
        return destination

    return wrapper
