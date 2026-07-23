"""Oxy models exposed through its OpenAI-compatible endpoint."""

from langchain_openai import ChatOpenAI

from app.config import settings


llm = ChatOpenAI(
    api_key=settings.OXYY_API_KEY,
    base_url=settings.OXYY_BASE_URL,
    model=settings.OXYY_AGENT_MODEL,
    temperature=0.5,
    timeout=30,
    max_retries=1,
    tags=["provider:oxy", "purpose:agent"],
)

structured_llm = ChatOpenAI(
    api_key=settings.OXYY_API_KEY,
    base_url=settings.OXYY_BASE_URL,
    model=settings.OXYY_STRUCTURED_MODEL,
    temperature=0,
    timeout=30,
    max_retries=1,
    tags=["provider:oxy", "purpose:structured"],
)
