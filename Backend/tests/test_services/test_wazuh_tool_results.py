"""Unit tests for the SOC tool result envelope and bounded retry.

These helpers sit between the Wazuh services and the agent loop. The contract
under test: every failure becomes a typed envelope rather than an exception,
and only retryable classifications are ever retried.
"""

import httpx
import pytest
from opensearchpy import exceptions as opensearch_exc

from app.services.wazuh.exceptions import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhPermissionError,
    WazuhTimeoutError,
    WazuhValidationError,
)
from app.services.wazuh.tool_results import failure, run, success


def test_success_wraps_the_payload():
    assert success({"agents": []}) == {"ok": True, "data": {"agents": []}}


@pytest.mark.parametrize(
    ("error", "code", "retryable"),
    [
        (WazuhAuthError("bad token"), "WAZUH_AUTH_FAILED", False),
        (WazuhPermissionError("forbidden"), "WAZUH_FORBIDDEN", False),
        (WazuhValidationError("bad input"), "INVALID_TOOL_INPUT", False),
        (ValueError("bad input"), "INVALID_TOOL_INPUT", False),
        (WazuhTimeoutError("slow"), "WAZUH_TIMEOUT", True),
        (httpx.TimeoutException("slow"), "WAZUH_TIMEOUT", True),
        (opensearch_exc.ConnectionTimeout("slow"), "WAZUH_TIMEOUT", True),
        (httpx.ConnectError("down"), "WAZUH_UNAVAILABLE", True),
        (opensearch_exc.ConnectionError("down"), "WAZUH_UNAVAILABLE", True),
        (RuntimeError("surprise"), "WAZUH_TOOL_ERROR", False),
    ],
)
def test_failure_classification(error, code, retryable):
    result = failure(error)

    assert result["ok"] is False
    assert result["error"]["code"] == code
    assert result["error"]["retryable"] is retryable


@pytest.mark.parametrize(
    ("status_code", "code", "retryable"),
    [
        (400, "WAZUH_API_ERROR", False),
        (404, "WAZUH_API_ERROR", False),
        (429, "WAZUH_API_ERROR", True),
        (500, "WAZUH_API_ERROR", True),
        (503, "WAZUH_API_ERROR", True),
        (None, "WAZUH_UNAVAILABLE", True),
    ],
)
def test_api_error_retryability_follows_the_status_code(status_code, code, retryable):
    result = failure(WazuhAPIError("boom", status_code=status_code))

    assert result["error"]["code"] == code
    assert result["error"]["retryable"] is retryable


def test_unexpected_errors_do_not_leak_their_message():
    """Internal detail must not reach the model-facing envelope."""
    result = failure(RuntimeError("postgres://user:secret@host/db"))

    assert "secret" not in result["error"]["message"]
    assert result["error"]["message"] == (
        "The Wazuh tool could not complete the request."
    )


def test_timeout_message_is_generic():
    assert failure(httpx.TimeoutException("connect timed out"))["error"]["message"] == (
        "Wazuh did not respond within the allowed time."
    )


# --- bounded retry --------------------------------------------------------


def test_run_returns_the_first_success_without_retrying():
    calls = []

    def fn():
        calls.append(1)
        return "value"

    assert run(fn) == {"ok": True, "data": "value"}
    assert len(calls) == 1


def test_run_does_not_retry_a_non_retryable_failure():
    calls = []

    def fn():
        calls.append(1)
        raise WazuhPermissionError("forbidden")

    result = run(fn, max_attempts=3, initial_delay=0)

    assert result["error"]["code"] == "WAZUH_FORBIDDEN"
    assert len(calls) == 1, "a non-retryable error must not be retried"


def test_run_retries_a_retryable_failure_then_succeeds(monkeypatch):
    monkeypatch.setattr("app.services.wazuh.tool_results.time.sleep", lambda _: None)
    calls = []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise httpx.ConnectError("down")
        return "recovered"

    assert run(fn, max_attempts=3) == {"ok": True, "data": "recovered"}
    assert len(calls) == 3


def test_run_stops_at_max_attempts_and_returns_the_last_failure(monkeypatch):
    monkeypatch.setattr("app.services.wazuh.tool_results.time.sleep", lambda _: None)
    calls = []

    def fn():
        calls.append(1)
        raise httpx.ConnectError("down")

    result = run(fn, max_attempts=3)

    assert len(calls) == 3
    assert result["ok"] is False
    assert result["error"]["code"] == "WAZUH_UNAVAILABLE"


def test_run_backs_off_exponentially(monkeypatch):
    delays = []
    monkeypatch.setattr(
        "app.services.wazuh.tool_results.time.sleep",
        lambda seconds: delays.append(seconds),
    )

    def fn():
        raise httpx.ConnectError("down")

    run(fn, max_attempts=4, initial_delay=0.1)

    assert delays == pytest.approx([0.1, 0.2, 0.4])


def test_run_never_raises_into_the_agent_loop():
    def fn():
        raise KeyError("unexpected")

    result = run(fn, max_attempts=1)

    assert result["ok"] is False
    assert result["error"]["code"] == "WAZUH_TOOL_ERROR"


def test_run_rejects_a_non_positive_attempt_budget():
    with pytest.raises(ValueError, match="max_attempts must be at least 1"):
        run(lambda: None, max_attempts=0)
