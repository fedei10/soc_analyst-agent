"""Native LangChain models for Cerebras inference."""

from langchain_cerebras import ChatCerebras

from app.config import settings


llm = ChatCerebras(
    api_key=settings.CEREBRAS_API_KEY,
    model=settings.CEREBRAS_AGENT_MODEL,
    temperature=0.5,
    timeout=30,
    max_retries=0,
    tags=["provider:cerebras", "purpose:agent"],
)

structured_llm = ChatCerebras(
    api_key=settings.CEREBRAS_API_KEY,
    model=settings.CEREBRAS_STRUCTURED_MODEL,
    temperature=0,
    timeout=30,
    max_retries=0,
    tags=["provider:cerebras", "purpose:structured"],
)
