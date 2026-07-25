"""Single lazy LLM dependency for MAPE-K Analyze and Plan."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from pydantic import BaseModel

from app.config import settings


class LLMConfigurationError(RuntimeError):
    pass


class LLMInputLimitError(ValueError):
    pass


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
                max_retries=1,
                tags=["provider:oxy", "workflow:mape-k"],
            )
        return self._client

    def invoke_structured(
        self,
        schema: type[BaseModel],
        messages: list[dict[str, str]],
    ) -> tuple[BaseModel, dict[str, int]]:
        rendered = json.dumps(messages, default=str)
        estimated_input_tokens = (len(rendered) + 3) // 4
        if estimated_input_tokens > settings.MAPEK_MAX_INPUT_TOKENS:
            raise LLMInputLimitError("MAPE-K LLM input exceeds the configured limit.")
        runnable = self.get_client().with_structured_output(
            schema,
            method="function_calling",
        )
        result = schema.model_validate(runnable.invoke(messages))
        output_tokens = (len(result.model_dump_json()) + 3) // 4
        return result, {
            "input_tokens": estimated_input_tokens,
            "output_tokens": output_tokens,
        }


@lru_cache(maxsize=1)
def get_llm_provider() -> LLMProvider:
    return LLMProvider()
