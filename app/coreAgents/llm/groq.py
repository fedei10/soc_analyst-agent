from langchain_groq import ChatGroq




llm = ChatGroq(
    model="qwen/qwen3.6-27b",
    temperature=0.2,
    max_tokens=None,
    timeout=30,
    max_retries=2,
)