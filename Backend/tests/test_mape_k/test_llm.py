import time
from types import SimpleNamespace

import httpx
import pytest
from pydantic import BaseModel

from openai import RateLimitError

from app.mape_k.llm import (
    LLMErrorCode,
    LLMInvocationError,
    LLMProvider,
    LLMRateLimitedError,
    LLMRateLimiter,
    classify_llm_error,
    is_rate_limit_error,
)


class TinyResult(BaseModel):
    answer: str


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def with_structured_output(self, *_args, **_kwargs):
        client = self

        class Runnable:
            def invoke(self, _messages):
                client.calls += 1
                response = client.responses.pop(0)
                if isinstance(response, Exception):
                    raise response
                return response

        return Runnable()


def _response(*, parsed=None, parsing_error=None, usage=None):
    raw = SimpleNamespace(
        usage_metadata=usage or {},
        response_metadata={},
    )
    return {
        "raw": raw,
        "parsed": parsed,
        "parsing_error": parsing_error,
    }


def test_timeout_and_rate_limit_are_classified_without_secret_text():
    timeout = classify_llm_error(
        TimeoutError("secret provider response"),
        attempt=1,
        duration_ms=15,
    )

    class RateLimited(Exception):
        status_code = 429

    rate_limit = classify_llm_error(
        RateLimited("secret provider response"),
        attempt=2,
        duration_ms=20,
    )

    assert timeout.code == LLMErrorCode.MODEL_TIMEOUT
    assert timeout.retryable is True
    assert rate_limit.code == LLMErrorCode.MODEL_RATE_LIMITED
    assert rate_limit.retryable is True
    assert rate_limit.safe_metadata()["http_status"] == 429
    assert "secret provider response" not in str(timeout)
    assert "secret provider response" not in str(rate_limit)


def _openai_rate_limit_error() -> RateLimitError:
    response = httpx.Response(429, request=httpx.Request("POST", "https://example.com"))
    return RateLimitError("rate limited", response=response, body=None)


def test_is_rate_limit_error_recognizes_raw_openai_error():
    assert is_rate_limit_error(_openai_rate_limit_error()) is True


def test_is_rate_limit_error_recognizes_classified_llm_invocation_error():
    classified = classify_llm_error(
        _openai_rate_limit_error(), attempt=1, duration_ms=5
    )
    assert is_rate_limit_error(classified) is True


def test_is_rate_limit_error_walks_wrapped_exceptions():
    try:
        try:
            raise _openai_rate_limit_error()
        except RateLimitError as exc:
            raise RuntimeError("graph step failed") from exc
    except RuntimeError as wrapped:
        assert is_rate_limit_error(wrapped) is True


def test_is_rate_limit_error_is_false_for_unrelated_errors():
    assert is_rate_limit_error(ValueError("not a rate limit")) is False
    assert is_rate_limit_error(TimeoutError("slow")) is False


def test_invalid_structured_output_is_classified():
    provider = LLMProvider(
        client=FakeClient(
            [_response(parsing_error=ValueError("bad provider payload"))]
        )
    )

    with pytest.raises(LLMInvocationError) as raised:
        provider.invoke_structured(
            TinyResult,
            [{"role": "user", "content": "{}"}],
        )

    assert raised.value.code == LLMErrorCode.MODEL_OUTPUT_INVALID
    assert raised.value.retryable is False


def test_actual_token_usage_is_kept_separate_from_estimates():
    provider = LLMProvider(
        client=FakeClient(
            [
                _response(
                    parsed=TinyResult(answer="ok"),
                    usage={
                        "input_tokens": 12,
                        "output_tokens": 4,
                        "input_token_details": {"cache_read": 3},
                    },
                )
            ]
        )
    )

    result, usage = provider.invoke_structured(
        TinyResult,
        [{"role": "user", "content": "{}"}],
    )

    assert result.answer == "ok"
    assert usage["actual_input_tokens"] == 12
    assert usage["actual_output_tokens"] == 4
    assert usage["cached_input_tokens"] == 3
    assert usage["estimated_input_tokens"] > 0
    assert usage["model_calls"] == 1
    assert usage["retries"] == 0


def test_retryable_timeout_retries_once_then_returns_usage(monkeypatch):
    request = httpx.Request("POST", "https://provider.invalid/chat")
    client = FakeClient(
        [
            httpx.ReadTimeout("timed out", request=request),
            _response(parsed=TinyResult(answer="recovered")),
        ]
    )
    monkeypatch.setattr("app.mape_k.llm.time.sleep", lambda _seconds: None)

    result, usage = LLMProvider(client=client).invoke_structured(
        TinyResult,
        [{"role": "user", "content": "{}"}],
    )

    assert result.answer == "recovered"
    assert client.calls == 2
    assert usage["model_calls"] == 2
    assert usage["retries"] == 1


def _clocked(monkeypatch):
    clock = [0.0]
    sleeps: list[float] = []

    def fake_monotonic():
        return clock[0]

    def fake_sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(time, "monotonic", fake_monotonic)
    monkeypatch.setattr(time, "sleep", fake_sleep)
    return clock, sleeps


def test_llm_rate_limiter_allows_up_to_max_without_sleeping(monkeypatch):
    clock, sleeps = _clocked(monkeypatch)
    limiter = LLMRateLimiter(max_requests=4, period_seconds=60.0, max_wait_seconds=8.0)

    for _ in range(4):
        limiter.acquire()

    assert sleeps == []
    assert len(limiter._timestamps) == 4


def test_llm_rate_limiter_blocks_until_a_slot_frees_up(monkeypatch):
    clock, sleeps = _clocked(monkeypatch)
    limiter = LLMRateLimiter(max_requests=2, period_seconds=60.0, max_wait_seconds=100.0)

    limiter.acquire()  # t=0
    clock[0] = 10.0
    limiter.acquire()  # t=10, window now [0, 10]
    limiter.acquire()  # window full - must wait until t=0's slot expires at t=60

    assert sleeps  # it actually waited
    assert clock[0] >= 60.0


def test_llm_rate_limiter_gives_up_past_the_max_wait_cap(monkeypatch):
    _clocked(monkeypatch)
    limiter = LLMRateLimiter(max_requests=1, period_seconds=60.0, max_wait_seconds=5.0)

    limiter.acquire()
    with pytest.raises(LLMRateLimitedError) as error:
        limiter.acquire()

    assert error.value.wait_seconds > 5.0


def test_get_client_wires_the_shared_rate_limiter(monkeypatch):
    class FakeChatOpenAI:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def invoke(self, *args, **kwargs):
            return "raw-response"

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeChatOpenAI)
    monkeypatch.setattr("app.mape_k.llm.settings.LLM_PROVIDER", "oxy")
    monkeypatch.setattr(
        "app.mape_k.llm.settings.LLM_API_KEY",
        SimpleNamespace(get_secret_value=lambda: "test-key"),
    )

    calls = []
    monkeypatch.setattr(
        "app.mape_k.llm.llm_rate_limiter.acquire",
        lambda: calls.append(1),
    )

    client = LLMProvider().get_client()
    result = client.invoke("hello")

    assert result == "raw-response"
    assert calls == [1]


class FakeSlotCache:
    """Stands in for EphemeralRedis.acquire_rate_slot."""

    def __init__(self, waits):
        self.waits = list(waits)
        self.calls = 0

    def acquire_rate_slot(self, **_kwargs):
        self.calls += 1
        return self.waits.pop(0) if self.waits else 0.0


def test_shared_window_governs_when_redis_answers(monkeypatch):
    _clocked(monkeypatch)
    cache = FakeSlotCache([0.0])
    limiter = LLMRateLimiter(
        max_requests=1,
        period_seconds=60.0,
        max_wait_seconds=8.0,
        cache=cache,
    )

    limiter.acquire()

    assert cache.calls == 1
    # The local deque stays untouched, so a slot is never spent twice.
    assert list(limiter._timestamps) == []


def test_shared_window_waits_then_admits(monkeypatch):
    _clock, sleeps = _clocked(monkeypatch)
    cache = FakeSlotCache([2.0, 0.0])
    limiter = LLMRateLimiter(
        max_requests=1,
        period_seconds=60.0,
        max_wait_seconds=8.0,
        cache=cache,
    )

    limiter.acquire()

    assert sleeps == [2.0]
    assert cache.calls == 2


def test_shared_window_gives_up_past_the_cap(monkeypatch):
    _clocked(monkeypatch)
    limiter = LLMRateLimiter(
        max_requests=1,
        period_seconds=60.0,
        max_wait_seconds=5.0,
        cache=FakeSlotCache([30.0]),
    )

    with pytest.raises(LLMRateLimitedError):
        limiter.acquire()


def test_falls_back_to_local_window_when_redis_is_down(monkeypatch):
    _clocked(monkeypatch)
    # None means "Redis unreachable" - the in-process deque takes over.
    cache = FakeSlotCache([None, None])
    limiter = LLMRateLimiter(
        max_requests=1,
        period_seconds=60.0,
        max_wait_seconds=5.0,
        cache=cache,
    )

    limiter.acquire()

    assert len(limiter._timestamps) == 1
    with pytest.raises(LLMRateLimitedError):
        limiter.acquire()


def test_retryable_failure_falls_over_to_the_secondary_provider(monkeypatch):
    request = httpx.Request("POST", "https://provider.invalid/chat")
    primary = FakeClient(
        [
            httpx.ReadTimeout("timed out", request=request),
            httpx.ReadTimeout("timed out again", request=request),
        ]
    )
    secondary = FakeClient([_response(parsed=TinyResult(answer="from-fallback"))])
    monkeypatch.setattr("app.mape_k.llm.time.sleep", lambda _seconds: None)

    provider = LLMProvider(client=primary)
    monkeypatch.setattr(provider, "get_fallback_client", lambda: secondary)

    result, _usage = provider.invoke_structured(
        TinyResult,
        [{"role": "user", "content": "{}"}],
    )

    assert result.answer == "from-fallback"
    assert primary.calls == 2
    assert secondary.calls == 1


def test_no_fallback_configured_still_raises_the_primary_error(monkeypatch):
    request = httpx.Request("POST", "https://provider.invalid/chat")
    primary = FakeClient(
        [
            httpx.ReadTimeout("timed out", request=request),
            httpx.ReadTimeout("timed out again", request=request),
        ]
    )
    monkeypatch.setattr("app.mape_k.llm.time.sleep", lambda _seconds: None)

    provider = LLMProvider(client=primary)
    monkeypatch.setattr(provider, "get_fallback_client", lambda: None)

    with pytest.raises(LLMInvocationError) as raised:
        provider.invoke_structured(TinyResult, [{"role": "user", "content": "{}"}])

    assert raised.value.code == LLMErrorCode.MODEL_TIMEOUT
