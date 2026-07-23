from langchain_groq import ChatGroq

from app.config import settings

llm = ChatGroq(
    api_key=settings.GROQ_API_KEY,
    model=settings.GROQ_AGENT_MODEL,
    temperature=0.5,
    max_tokens=None,
    timeout=30,
    max_retries=2,
    tags=["provider:groq", "purpose:agent"],
)

# Formatting is a separate, tool-free pass so graph routing only sees output
# validated against the Pydantic schema.
structured_llm = ChatGroq(
    api_key=settings.GROQ_API_KEY,
    model=settings.GROQ_STRUCTURED_MODEL,
    temperature=0,
    max_tokens=None,
    timeout=30,
    max_retries=2,
    tags=["provider:groq", "purpose:structured"],
)
