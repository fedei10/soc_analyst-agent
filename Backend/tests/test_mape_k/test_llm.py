from types import SimpleNamespace

import httpx
import pytest
from pydantic import BaseModel

from app.mape_k.llm import (
    LLMErrorCode,
    LLMInvocationError,
    LLMProvider,
    classify_llm_error,
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
