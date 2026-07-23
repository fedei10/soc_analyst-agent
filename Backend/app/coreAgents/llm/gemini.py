"""Native LangChain models for Google Gemini."""

from langchain_google_genai import ChatGoogleGenerativeAI

from app.config import settings


llm = ChatGoogleGenerativeAI(
    api_key=settings.GOOGLE_API_KEY,
    model=settings.GEMINI_AGENT_MODEL,
    temperature=0.5,
    max_tokens=8192,
    request_timeout=30,
    retries=1,
    tags=["provider:gemini", "purpose:agent"],
)

structured_llm = ChatGoogleGenerativeAI(
    api_key=settings.GOOGLE_API_KEY,
    model=settings.GEMINI_STRUCTURED_MODEL,
    temperature=0,
    max_tokens=8192,
    request_timeout=30,
    retries=1,
    tags=["provider:gemini", "purpose:structured"],
)
