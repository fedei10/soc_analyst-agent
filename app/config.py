# app/config.py

from functools import lru_cache
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # API Keys
    GROQ_API_KEY: SecretStr
    OXYY_API_KEY: SecretStr

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