"""Shared result handling for the allowlisted SOC Wazuh tools."""

import time
from typing import Any, Callable

import httpx
from opensearchpy import exceptions as opensearch_exc

from app.services.wazuh.exceptions import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhPermissionError,
    WazuhValidationError,
)
from app.services.wazuh.models import ToolError


def success(data: Any) -> dict[str, Any]:
    return {"ok": True, "data": data}


def failure(error: Exception) -> dict[str, Any]:
    if isinstance(error, WazuhAuthError):
        result = ToolError(code="WAZUH_AUTH_FAILED", message=str(error), retryable=False)
    elif isinstance(error, WazuhPermissionError):
        result = ToolError(code="WAZUH_FORBIDDEN", message=str(error), retryable=False)
    elif isinstance(error, WazuhValidationError | ValueError):
        result = ToolError(code="INVALID_TOOL_INPUT", message=str(error), retryable=False)
    elif isinstance(error, (httpx.TimeoutException, opensearch_exc.ConnectionTimeout)):
        result = ToolError(
            code="WAZUH_TIMEOUT",
            message="Wazuh did not respond within the allowed time.",
            retryable=True,
        )
    elif isinstance(error, (httpx.TransportError, opensearch_exc.ConnectionError)):
        result = ToolError(
            code="WAZUH_UNAVAILABLE",
            message="Wazuh is currently unreachable.",
            retryable=True,
        )
    elif isinstance(error, WazuhAPIError):
        retryable = error.status_code is None or error.status_code == 429 or (
            error.status_code is not None and error.status_code >= 500
        )
        code = "WAZUH_UNAVAILABLE" if error.status_code is None else "WAZUH_API_ERROR"
        result = ToolError(code=code, message=str(error), retryable=retryable)
    else:
        result = ToolError(
            code="WAZUH_TOOL_ERROR",
            message="The Wazuh tool could not complete the request.",
            retryable=False,
        )
    return {"ok": False, "error": result.model_dump(mode="json")}


def run(
    fn: Callable[[], Any],
    *,
    max_attempts: int = 2,
    initial_delay: float = 0.2,
) -> dict[str, Any]:
    """Execute a service call with bounded retry; never raise into the agent loop."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1.")

    result: dict[str, Any] | None = None
    for attempt in range(max_attempts):
        try:
            return success(fn())
        except Exception as exc:
            result = failure(exc)
            retryable = bool(result.get("error", {}).get("retryable"))
            if not retryable or attempt == max_attempts - 1:
                return result
            time.sleep(initial_delay * (2**attempt))

    return result or {
        "ok": False,
        "error": {
            "code": "WAZUH_TOOL_ERROR",
            "message": "The Wazuh tool could not complete the request.",
            "retryable": False,
        },
    }
