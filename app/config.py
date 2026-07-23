# app/config.py
import logging
from functools import lru_cache
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.langsmith import configure_langsmith


logger = logging.getLogger("tsage.config")


class Settings(BaseSettings):
    # API Keys
    GROQ_API_KEY: SecretStr
    OXYY_API_KEY: SecretStr
    CEREBRAS_API_KEY: SecretStr

    # Bearer tokens for THIS API, comma-separated. Same model as the Wazuh MCP
    # server: read tokens go to SOC L1/L2 agents, write tokens stay human-held
    # (L3 response actions). Empty = endpoints answer 503 until configured.
    SOC_READ_API_KEYS: SecretStr = SecretStr("")
    SOC_WRITE_API_KEYS: SecretStr = SecretStr("")

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

    # Redis example
    #REDIS_HOST: str = "localhost"
    #REDIS_PORT: int = 6379
    #REDIS_PASSWORD: SecretStr | None = None

    # PostgreSQL example
    #POSTGRES_HOST: str = "localhost"
    #POSTGRES_PORT: int = 5432
    #POSTGRES_USER: str | None = None
    #POSTGRES_PASSWORD: SecretStr | None = None
    #POSTGRES_DB: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",          
        env_file_encoding="utf-8",
        extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
if configure_langsmith(settings):
    logger.info("LangSmith tracing enabled for project '%s'.", settings.LANGSMITH_PROJECT)
