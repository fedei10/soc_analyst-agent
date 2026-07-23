from langchain_groq import ChatGroq

from app.config import settings

llm = ChatGroq(
    api_key=settings.GROQ_API_KEY,
    model="qwen/qwen3.6-27b",
    temperature=0.5,
    max_tokens=None,
    timeout=30,
    max_retries=2,
)