"""Single lazy LLM dependency for MAPE-K Analyze and Plan."""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from enum import StrEnum
from functools import lru_cache
from typing import Any

import httpx
from openai import RateLimitError
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


def is_rate_limit_error(exc: BaseException) -> bool:
    """True if exc, or anything it wraps, is a provider 429.

    LangGraph/LangChain often re-raise the original provider error inside
    another exception (e.g. a graph-step failure) - walk __cause__/__context__
    so a rate limit stays recognizable however many layers deep it surfaces.
    """
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, RateLimitError):
            return True
        if (
            isinstance(current, LLMInvocationError)
            and current.code == LLMErrorCode.MODEL_RATE_LIMITED
        ):
            return True
        if _status_code(current) == 429:
            return True
        current = current.__cause__ or current.__context__
    return False


class LLMRateLimitedError(RuntimeError):
    def __init__(self, wait_seconds: float) -> None:
        super().__init__(
            "LLM rate limit budget exhausted; the next free slot is "
            f"{wait_seconds:.1f}s away."
        )
        self.wait_seconds = wait_seconds


class LLMRateLimiter:
    """Sliding-window gate in front of every real LLM call.

    The provider enforces a hard per-minute request cap. When Redis is
    reachable the window lives there, so several gunicorn workers share one
    budget instead of each independently rediscovering the provider's 429s;
    when it is not, the in-process deque keeps a single worker paced.
    Synchronous (threading.Lock + time.sleep) because this codebase has no
    asyncio anywhere - sync FastAPI handlers, sync gateway/LLM calls.
    """

    def __init__(
        self,
        max_requests: int,
        period_seconds: float,
        max_wait_seconds: float,
        *,
        cache: Any | None = None,
        subject: str = "reasoning",
    ) -> None:
        self.max_requests = max_requests
        self.period_seconds = period_seconds
        self.max_wait_seconds = max_wait_seconds
        self.subject = subject
        self._cache = cache
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def _shared_wait(self) -> float | None:
        """Seconds to wait per the cross-worker window, None if unavailable."""

        if self._cache is None:
            return None
        return self._cache.acquire_rate_slot(
            organization_id="llm",
            subject=self.subject,
            limit=self.max_requests,
            window_seconds=self.period_seconds,
        )

    def _local_wait(self) -> float:
        with self._lock:
            now = time.monotonic()
            while (
                self._timestamps
                and now - self._timestamps[0] >= self.period_seconds
            ):
                self._timestamps.popleft()
            if len(self._timestamps) < self.max_requests:
                self._timestamps.append(now)
                return 0.0
            return self.period_seconds - (now - self._timestamps[0])

    def acquire(self) -> None:
        while True:
            # Exactly one window governs a given call: the shared one when
            # Redis answers, the local one otherwise. Consuming both would
            # burn two slots per request and halve the effective budget.
            wait = self._shared_wait()
            if wait is None:
                wait = self._local_wait()
            if wait <= 0:
                return
            if wait > self.max_wait_seconds:
                raise LLMRateLimitedError(wait)
            time.sleep(max(wait, 0.05))


def _reasoning_rate_limiter() -> LLMRateLimiter:
    from app.services.redis.ephemeral import EphemeralRedis

    return LLMRateLimiter(
        max_requests=settings.LLM_RATE_LIMIT_MAX_REQUESTS,
        period_seconds=settings.LLM_RATE_LIMIT_WINDOW_SECONDS,
        max_wait_seconds=settings.LLM_RATE_LIMIT_MAX_WAIT_SECONDS,
        cache=EphemeralRedis(),
        subject="reasoning",
    )


# Conservative margin under the real provider ceiling.
llm_rate_limiter = _reasoning_rate_limiter()

router_rate_limiter = LLMRateLimiter(
    max_requests=settings.LLM_ROUTER_RATE_LIMIT_MAX_REQUESTS,
    period_seconds=settings.LLM_RATE_LIMIT_WINDOW_SECONDS,
    max_wait_seconds=settings.LLM_RATE_LIMIT_MAX_WAIT_SECONDS,
    cache=None,
    subject="router",
)


SUPPORTED_LLM_PROVIDERS = {"oxy", "mistral"}


class LLMTier(StrEnum):
    """Which budget and model a call belongs to.

    REASONING is diagnosis, planning and analyst chat - the calls whose
    quality decides whether the agent is right. ROUTER is intent
    classification and short structured picks, which a small fast model
    answers just as well; keeping them off the reasoning budget is what buys
    the reasoning path room to think.
    """

    REASONING = "reasoning"
    ROUTER = "router"


def effective_llm_api_key() -> str:
    return settings.LLM_API_KEY.get_secret_value().strip()


def _fallback_endpoint() -> dict[str, Any] | None:
    """Secondary provider config, or None when no fallback is configured."""

    api_key = settings.LLM_FALLBACK_API_KEY.get_secret_value().strip()
    provider = settings.LLM_FALLBACK_PROVIDER.strip().lower()
    if not api_key or not provider:
        return None
    return {
        "provider": provider,
        "api_key": api_key,
        "base_url": settings.LLM_FALLBACK_BASE_URL or settings.LLM_BASE_URL,
        "model": settings.LLM_FALLBACK_MODEL or settings.LLM_MODEL,
        "timeout_seconds": settings.LLM_TIMEOUT_SECONDS,
    }


class LLMProvider:
    def __init__(
        self,
        client: Any | None = None,
        *,
        tier: LLMTier = LLMTier.REASONING,
        limiter: LLMRateLimiter | None = None,
    ) -> None:
        self._client = client
        self._fallback_client: Any | None = None
        self.tier = tier
        self.limiter = limiter or (
            router_rate_limiter
            if tier == LLMTier.ROUTER
            else llm_rate_limiter
        )

    def _endpoint(self) -> dict[str, Any]:
        provider = settings.LLM_PROVIDER.strip().lower()
        if provider not in SUPPORTED_LLM_PROVIDERS:
            raise LLMConfigurationError(
                f"Unsupported LLM_PROVIDER '{provider}'. Supported: "
                f"{', '.join(sorted(SUPPORTED_LLM_PROVIDERS))}."
            )
        api_key = effective_llm_api_key()
        if not api_key:
            raise LLMConfigurationError("The centralized LLM is not configured.")
        router = self.tier == LLMTier.ROUTER
        return {
            "provider": provider,
            "api_key": api_key,
            "base_url": settings.LLM_BASE_URL,
            "model": (
                (settings.LLM_ROUTER_MODEL or settings.LLM_MODEL)
                if router
                else settings.LLM_MODEL
            ),
            "timeout_seconds": (
                settings.LLM_ROUTER_TIMEOUT_SECONDS
                if router
                else settings.LLM_TIMEOUT_SECONDS
            ),
        }

    def _build_client(self, endpoint: dict[str, Any], limiter: LLMRateLimiter):
        from langchain_openai import ChatOpenAI

        client = ChatOpenAI(
            api_key=endpoint["api_key"],
            base_url=endpoint["base_url"],
            model=endpoint["model"],
            temperature=0,
            timeout=endpoint["timeout_seconds"],
            max_retries=0,
            tags=[
                f"provider:{endpoint['provider']}",
                f"tier:{self.tier.value}",
                "workflow:mape-k",
            ],
        )
        # Gate every real call through the limiter, not just our own
        # invoke_structured() path. Instance-level patch (not a subclass) so
        # it survives .bind_tools()/.with_structured_output() - both still
        # call through to this same instance's .invoke. object.__setattr__
        # bypasses ChatOpenAI's Pydantic __setattr__, which rejects assigning
        # to anything that isn't a model field.
        original_invoke = client.invoke

        def rate_limited_invoke(*args: Any, **kwargs: Any) -> Any:
            limiter.acquire()
            return original_invoke(*args, **kwargs)

        object.__setattr__(client, "invoke", rate_limited_invoke)
        return client

    def get_client(self):
        if self._client is None:
            self._client = self._build_client(self._endpoint(), self.limiter)
        return self._client

    def get_fallback_client(self):
        """Secondary-provider client, or None when none is configured."""

        if self._fallback_client is None:
            endpoint = _fallback_endpoint()
            if endpoint is None:
                return None
            self._fallback_client = self._build_client(endpoint, self.limiter)
        return self._fallback_client

    def invoke_structured(
        self,
        schema: type[BaseModel],
        messages: list[dict[str, str]],
    ) -> tuple[BaseModel, dict[str, Any]]:
        rendered = json.dumps(messages, default=str)
        estimated_input_tokens = (len(rendered) + 3) // 4
        if estimated_input_tokens > settings.MAPEK_MAX_INPUT_TOKENS:
            raise LLMInputLimitError("MAPE-K LLM input exceeds the configured limit.")
        def structured(client: Any) -> Any:
            return client.with_structured_output(
                schema,
                method="function_calling",
                include_raw=True,
            )

        last_error: LLMInvocationError | None = None
        response: Any = None
        attempts = 2
        started = time.perf_counter()
        runnable = structured(self.get_client())
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
                if not last_error.retryable:
                    raise last_error from None
                if attempt >= attempts:
                    # Primary is out of retries on a retryable failure
                    # (timeout, 429, 5xx). One shot at the secondary provider
                    # turns a hard stage failure into a degraded success.
                    fallback = self.get_fallback_client()
                    if fallback is None:
                        raise last_error from None
                    try:
                        response = structured(fallback).invoke(messages)
                        break
                    except Exception as fallback_exc:
                        raise classify_llm_error(
                            fallback_exc,
                            attempt=attempt + 1,
                            duration_ms=int(
                                (time.perf_counter() - call_started) * 1000
                            ),
                        ) from None
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


@lru_cache(maxsize=len(LLMTier))
def get_llm_provider(tier: LLMTier = LLMTier.REASONING) -> LLMProvider:
    return LLMProvider(tier=tier)
