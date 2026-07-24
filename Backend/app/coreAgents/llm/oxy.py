"""Oxy models exposed through its OpenAI-compatible endpoint."""

from langchain_openai import ChatOpenAI
from langchain_core.rate_limiters import InMemoryRateLimiter

from app.config import settings


rate_limiter = InMemoryRateLimiter(
    requests_per_second=0.075,
    check_every_n_seconds=0.1,
    max_bucket_size=1,
)

llm = ChatOpenAI(
    api_key=settings.OXYY_API_KEY,
    base_url=settings.OXYY_BASE_URL,
    model=settings.OXYY_AGENT_MODEL,
    temperature=0.5,
    timeout=30,
    max_retries=1,
    rate_limiter=rate_limiter,
    tags=["provider:oxy", "purpose:agent"],
)

structured_llm = ChatOpenAI(
    api_key=settings.OXYY_API_KEY,
    base_url=settings.OXYY_BASE_URL,
    model=settings.OXYY_STRUCTURED_MODEL,
    temperature=0,
    timeout=30,
    max_retries=1,
    rate_limiter=rate_limiter,
    tags=["provider:oxy", "purpose:structured"],
)
