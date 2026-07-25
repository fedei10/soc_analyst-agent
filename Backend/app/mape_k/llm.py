"""Single lazy LLM dependency for MAPE-K Analyze and Plan."""

from __future__ import annotations

import json
import time
from enum import StrEnum
from functools import lru_cache
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError

from app.config import settings


class LLMConfigurationError(RuntimeError):
    pass


class LLMInputLimitError(ValueError):
    pass


class LLMErrorCode(StrEnum):
    MODEL_TIMEOUT = "MODEL_TIMEOUT"
    MODEL_RATE_LIMITED = "MODEL_RATE_LIMITED"
    MODEL_AUTHENTICATION_FAILED = "MODEL_AUTHENTICATION_FAILED"
    MODEL_OUTPUT_INVALID = "MODEL_OUTPUT_INVALID"
    MODEL_CONTEXT_LIMIT_EXCEEDED = "MODEL_CONTEXT_LIMIT_EXCEEDED"
    MODEL_PROVIDER_UNAVAILABLE = "MODEL_PROVIDER_UNAVAILABLE"
    MODEL_REQUEST_FAILED = "MODEL_REQUEST_FAILED"


class LLMInvocationError(RuntimeError):
    def __init__(
        self,
        code: LLMErrorCode,
        *,
        retryable: bool,
        attempt: int,
        duration_ms: int,
        status_code: int | None = None,
    ) -> None:
        super().__init__(f"Model request failed with {code.value}.")
        self.code = code
        self.retryable = retryable
        self.attempt = attempt
        self.duration_ms = duration_ms
        self.status_code = status_code
        self.provider = settings.LLM_PROVIDER
        self.model = settings.LLM_MODEL

    def safe_metadata(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "provider": self.provider,
            "model": self.model,
            "attempt": self.attempt,
            "timeout_seconds": settings.LLM_TIMEOUT_SECONDS,
            "duration_ms": self.duration_ms,
            "retryable": self.retryable,
            "http_status": self.status_code,
        }


def _status_code(exc: Exception) -> int | None:
    value = getattr(exc, "status_code", None)
    if value is None:
        response = getattr(exc, "response", None)
        value = getattr(response, "status_code", None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def classify_llm_error(
    exc: Exception,
    *,
    attempt: int,
    duration_ms: int,
) -> LLMInvocationError:
    status = _status_code(exc)
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)) or "timeout" in name:
        return LLMInvocationError(
            LLMErrorCode.MODEL_TIMEOUT,
            retryable=True,
            attempt=attempt,
            duration_ms=duration_ms,
            status_code=status,
        )
    if status == 429 or "rate" in name:
        return LLMInvocationError(
            LLMErrorCode.MODEL_RATE_LIMITED,
            retryable=True,
            attempt=attempt,
            duration_ms=duration_ms,
            status_code=status,
        )
    if status in {401, 403} or "authentication" in name:
        return LLMInvocationError(
            LLMErrorCode.MODEL_AUTHENTICATION_FAILED,
            retryable=False,
            attempt=attempt,
            duration_ms=duration_ms,
            status_code=status,
        )
    if isinstance(exc, ValidationError) or "parsing" in name:
        return LLMInvocationError(
            LLMErrorCode.MODEL_OUTPUT_INVALID,
            retryable=False,
            attempt=attempt,
            duration_ms=duration_ms,
            status_code=status,
        )
    if status == 413 or "context length" in text or "too many tokens" in text:
        return LLMInvocationError(
            LLMErrorCode.MODEL_CONTEXT_LIMIT_EXCEEDED,
            retryable=False,
            attempt=attempt,
            duration_ms=duration_ms,
            status_code=status,
        )
    if isinstance(exc, (ConnectionError, httpx.ConnectError)) or (
        status is not None and status >= 500
    ):
        return LLMInvocationError(
            LLMErrorCode.MODEL_PROVIDER_UNAVAILABLE,
            retryable=True,
            attempt=attempt,
            duration_ms=duration_ms,
            status_code=status,
        )
    return LLMInvocationError(
        LLMErrorCode.MODEL_REQUEST_FAILED,
        retryable=False,
        attempt=attempt,
        duration_ms=duration_ms,
        status_code=status,
    )


def effective_llm_api_key() -> str:
    return settings.LLM_API_KEY.get_secret_value().strip()


class LLMProvider:
    def __init__(self, client: Any | None = None) -> None:
        self._client = client

    def get_client(self):
        if self._client is None:
            if settings.LLM_PROVIDER.strip().lower() != "oxy":
                raise LLMConfigurationError(
                    "Only the centralized Oxy inference provider is supported."
                )
            api_key = effective_llm_api_key()
            if not api_key:
                raise LLMConfigurationError("The centralized LLM is not configured.")
            from langchain_openai import ChatOpenAI

            self._client = ChatOpenAI(
                api_key=api_key,
                base_url=settings.LLM_BASE_URL,
                model=settings.LLM_MODEL,
                temperature=0,
                timeout=settings.LLM_TIMEOUT_SECONDS,
                max_retries=0,
                tags=["provider:oxy", "workflow:mape-k"],
            )
        return self._client

    def invoke_structured(
        self,
        schema: type[BaseModel],
        messages: list[dict[str, str]],
    ) -> tuple[BaseModel, dict[str, Any]]:
        rendered = json.dumps(messages, default=str)
        estimated_input_tokens = (len(rendered) + 3) // 4
        if estimated_input_tokens > settings.MAPEK_MAX_INPUT_TOKENS:
            raise LLMInputLimitError("MAPE-K LLM input exceeds the configured limit.")
        runnable = self.get_client().with_structured_output(
            schema,
            method="function_calling",
            include_raw=True,
        )
        last_error: LLMInvocationError | None = None
        response: Any = None
        attempts = 2
        started = time.perf_counter()
        for attempt in range(1, attempts + 1):
            call_started = time.perf_counter()
            try:
                response = runnable.invoke(messages)
                break
            except Exception as exc:
                last_error = classify_llm_error(
                    exc,
                    attempt=attempt,
                    duration_ms=int(
                        (time.perf_counter() - call_started) * 1000
                    ),
                )
                if not last_error.retryable or attempt >= attempts:
                    raise last_error from None
                time.sleep(min(0.25 * (2 ** (attempt - 1)), 1.0))
        if response is None:
            assert last_error is not None
            raise last_error

        raw = response.get("raw") if isinstance(response, dict) else None
        parsed = response.get("parsed") if isinstance(response, dict) else response
        parsing_error = (
            response.get("parsing_error") if isinstance(response, dict) else None
        )
        if parsing_error is not None or parsed is None:
            raise LLMInvocationError(
                LLMErrorCode.MODEL_OUTPUT_INVALID,
                retryable=False,
                attempt=(last_error.attempt + 1 if last_error else 1),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        try:
            result = schema.model_validate(parsed)
        except ValidationError:
            raise LLMInvocationError(
                LLMErrorCode.MODEL_OUTPUT_INVALID,
                retryable=False,
                attempt=(last_error.attempt + 1 if last_error else 1),
                duration_ms=int((time.perf_counter() - started) * 1000),
            ) from None

        usage_metadata = getattr(raw, "usage_metadata", None) or {}
        response_metadata = getattr(raw, "response_metadata", None) or {}
        token_usage = response_metadata.get("token_usage") or {}
        actual_input = usage_metadata.get(
            "input_tokens",
            token_usage.get("prompt_tokens"),
        )
        actual_output = usage_metadata.get(
            "output_tokens",
            token_usage.get("completion_tokens"),
        )
        cached_input = (
            usage_metadata.get("input_token_details", {}).get("cache_read")
            or token_usage.get("prompt_tokens_details", {}).get("cached_tokens")
        )
        estimated_output_tokens = (len(result.model_dump_json()) + 3) // 4
        return result, {
            # Compatibility fields remain estimates when provider usage is absent.
            "input_tokens": actual_input or estimated_input_tokens,
            "output_tokens": actual_output or estimated_output_tokens,
            "estimated_input_tokens": estimated_input_tokens,
            "estimated_output_tokens": estimated_output_tokens,
            "actual_input_tokens": actual_input,
            "actual_output_tokens": actual_output,
            "cached_input_tokens": cached_input,
            "model_calls": (last_error.attempt + 1 if last_error else 1),
            "retries": last_error.attempt if last_error else 0,
            "provider": settings.LLM_PROVIDER,
            "model": settings.LLM_MODEL,
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }


@lru_cache(maxsize=1)
def get_llm_provider() -> LLMProvider:
    return LLMProvider()
