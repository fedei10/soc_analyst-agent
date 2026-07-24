# app/config.py
import logging
from functools import lru_cache
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.langsmith import configure_langsmith


logger = logging.getLogger("tsage.config")


class Settings(BaseSettings):
    # API Keys
    GROQ_API_KEY: SecretStr = SecretStr("")
    GROQ_AGENT_MODEL: str = "qwen/qwen3.6-27b"
    GROQ_STRUCTURED_MODEL: str = "openai/gpt-oss-20b"
    OXYY_API_KEY: SecretStr = SecretStr("")
    OXYY_BASE_URL: str = "https://api.oxyy.ai/v1"
    OXYY_AGENT_MODEL: str = "codestral-2508"
    OXYY_STRUCTURED_MODEL: str = "gemma-4-31b-it"
    CEREBRAS_API_KEY: SecretStr = SecretStr("")
    CEREBRAS_AGENT_MODEL: str = "gemma-4-31b"
    CEREBRAS_STRUCTURED_MODEL: str = "gpt-oss-120b"
    GOOGLE_API_KEY: SecretStr = SecretStr("")
    GEMINI_AGENT_MODEL: str = "gemini-2.5-flash"
    GEMINI_STRUCTURED_MODEL: str = "gemini-2.5-flash"

    # Clerk authenticates every application API request. The secret and
    # optional PEM JWT key are server-only and must never be exposed through a
    # NEXT_PUBLIC_* variable.
    CLERK_SECRET_KEY: SecretStr = SecretStr("")
    CLERK_JWT_KEY: SecretStr = SecretStr("")
    CLERK_AUTHORIZED_PARTIES: str = "http://localhost:3000"
    # Comma-separated Clerk user IDs allowed to execute approved responses.
    # Empty means no user can execute, while approval remains a separate step.
    CLERK_EXECUTOR_USER_IDS: str = ""

    # LangSmith tracing
    LANGSMITH_API_KEY: SecretStr = SecretStr("")
    LANGSMITH_TRACING: bool = False
    LANGSMITH_PROJECT: str = "tsage"
    LANGSMITH_ENDPOINT: str | None = None

    # Wazuh (reached through SSH tunnel to PC1, so localhost)
    WAZUH_INDEXER_HOST: str = "127.0.0.1"
    WAZUH_INDEXER_PORT: int = 9200
    WAZUH_INDEXER_USER: str = "admin"
    WAZUH_INDEXER_PASSWORD: SecretStr = SecretStr("")
    WAZUH_ARCHIVE_INDEX: str = "wazuh-archives-*"
    WAZUH_BASE_URL: str = "https://127.0.0.1:55000"
    WAZUH_USERNAME: str = "wazuh-wui"
    WAZUH_PASSWORD: SecretStr = SecretStr("")
    WAZUH_RESPONDER_USERNAME: str = ""
    WAZUH_RESPONDER_PASSWORD: SecretStr = SecretStr("")
    # ponytail: verify_ssl=false is lab-only; flip to true once root-ca.pem is copied from PC1
    WAZUH_VERIFY_SSL: bool = False
    WAZUH_CA_CERT: str | None = None
    WAZUH_TIMEOUT: int = 15
    WAZUH_DEFAULT_LIMIT: int = 100
    WAZUH_MAX_LIMIT: int = 500
    # Safety rails: reads only by default; active-response needs BOTH flags flipped.
    WAZUH_READ_ONLY: bool = True
    WAZUH_ALLOW_DANGEROUS_TOOLS: bool = False

    # Durable investigations and LangGraph checkpoints. Leave empty for the
    # in-memory development fallback.
    DATABASE_URL: SecretStr = SecretStr("")
    DATABASE_AUTO_CREATE: bool = False
    DATABASE_REQUIRED: bool = False

    # Redis is deliberately ephemeral. PostgreSQL remains the source of truth
    # for conversations, graph checkpoints, reports, approvals, and audits.
    REDIS_URL: SecretStr = SecretStr("")
    REDIS_REQUIRED: bool = False
    REDIS_CONTEXT_TTL_SECONDS: int = 300
    REDIS_TOOL_TTL_SECONDS: int = 30
    REDIS_ACTIVITY_TTL_SECONDS: int = 86400
    REDIS_LOCK_TTL_SECONDS: int = 60
    REDIS_IDEMPOTENCY_TTL_SECONDS: int = 86400
    REDIS_ACTIVITY_MAX_EVENTS: int = 1000

    # Durable retention. Reports, approvals, actions, and curated memories are
    # intentionally excluded from automated deletion.
    RETENTION_MESSAGES_DAYS: int = 90
    RETENTION_TOOL_PAYLOAD_DAYS: int = 30
    RETENTION_CHECKPOINT_DAYS: int = 30
    RETENTION_INVESTIGATION_DAYS: int = 365

    # Local API-host diagnostics and self-healing. Diagnostics are read-only
    # named commands. Remediation still requires the response flags above,
    # explicit human approval, and an allowlisted target.
    SYSTEM_DIAGNOSTICS_ENABLED: bool = False
    SELF_HEALING_ENABLED: bool = False
    SELF_HEALING_SERVICE_ALLOWLIST: str = ""
    SYSTEM_COMMAND_TIMEOUT: int = 10

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
        env_file_encoding="utf-8",
        extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
if configure_langsmith(settings):
    logger.info("LangSmith tracing enabled for project '%s'.", settings.LANGSMITH_PROJECT)
