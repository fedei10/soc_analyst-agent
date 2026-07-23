"""Set deterministic env BEFORE app.config is imported (env vars beat .env)."""
import os

os.environ.setdefault("GROQ_API_KEY", "test")
os.environ.setdefault("OXYY_API_KEY", "test")
os.environ.setdefault("CEREBRAS_API_KEY", "test")
os.environ["SOC_READ_API_KEYS"] = "test-read-key"
os.environ["SOC_WRITE_API_KEYS"] = "test-write-key"
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
