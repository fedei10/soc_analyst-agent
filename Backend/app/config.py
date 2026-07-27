# app/config.py
import logging
from functools import lru_cache
from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.langsmith import configure_langsmith


logger = logging.getLogger("tsage.config")


class Settings(BaseSettings):
    # Application observability. Payload/content logging is opt-in because SOC
    # data commonly contains credentials, commands, and personal information.
    ENVIRONMENT: str = "development"
    SERVICE_NAME: str = "tsage-soc-api"
    SERVICE_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_INCLUDE_CALLSITE: bool = False
    LOG_REQUEST_BODY: bool = False
    LOG_RESPONSE_BODY: bool = False
    LOG_TOOL_PAYLOADS: bool = False
    LOG_MODEL_CONTENT: bool = False
    OTEL_ENABLED: bool = False
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    OTEL_EXPORTER_OTLP_INSECURE: bool = True
    OTEL_TRACE_SAMPLE_RATIO: float = 1.0
    SLOW_REQUEST_THRESHOLD_MS: int = 1000
    SLOW_TOOL_THRESHOLD_MS: int = 2000
    SLOW_MODEL_THRESHOLD_MS: int = 10000

    # Single MAPE-K reasoning provider. Only Analyze and Plan may use it.
    LLM_PROVIDER: str = "oxy"
    LLM_API_KEY: SecretStr = SecretStr("")
    LLM_BASE_URL: str = "https://api.oxyy.ai/v1"
    LLM_MODEL: str = "gpt-oss-120b"
    LLM_TIMEOUT_SECONDS: int = 30
    MAPEK_ANALYSIS_CONFIDENCE_THRESHOLD: float = 0.75
    MAPEK_MAX_ANALYSIS_ATTEMPTS: int = 2
    MAPEK_MAX_PLANNING_RETRIES: int = 1
    MAPEK_MAX_INPUT_TOKENS: int = 8000
    MAPEK_MAX_TOOL_CALLS_PER_STAGE: int = 4
    MAPEK_CORRELATION_WINDOW_SECONDS: int = 600
    MAPEK_SSH_BRUTE_FORCE_MIN_FAILURES: int = 5
    MAPEK_SSH_BRUTE_FORCE_MIN_EVENTS: int = 3
    MAPEK_SSH_BRUTE_FORCE_WINDOW_SECONDS: int = 300
    MAPEK_SSH_PASSWORD_SPRAY_MIN_USERS: int = 5
    MAPEK_SSH_PASSWORD_SPRAY_MIN_FAILURES: int = 10
    MAPEK_SSH_PASSWORD_SPRAY_WINDOW_SECONDS: int = 300
    MAPEK_SSH_SUCCESS_AFTER_FAILURE_WINDOW_SECONDS: int = 900
    MAPEK_APPROVAL_TTL_SECONDS: int = 1800
    MAPEK_REQUIRE_PLAN_HASH_APPROVAL: bool = True
    MAPEK_POLICY_VERSION: str = "1.0"
    MAPEK_ACTION_CATALOGUE_VERSION: str = "1.0"
    MAPEK_CHECKPOINTER_BACKEND: str = "auto"
    MAPEK_ALLOW_INMEMORY_CHECKPOINTER: bool = True
    MAPEK_EXECUTION_MODE: str = "disabled"
    MAPEK_DRY_RUN: bool = True
    MAPEK_REAL_EXECUTION_ENABLED: bool = False
    MAPEK_VERIFICATION_OBSERVATION_SECONDS: int = 60
    MAPEK_REQUIRE_MANAGEMENT_PROBE: bool = False
    MAPEK_MAX_EXECUTION_RETRIES: int = 1
    MAPEK_EXECUTION_LOCK_TTL_SECONDS: int = 300
    MAPEK_TEMPORARY_BLOCK_TTL_SECONDS: int = 900
    MAPEK_PROTECTED_IPS: str = ""
    MAPEK_APPROVED_ADMIN_IPS: str = ""
    MAPEK_PROTECTED_ACCOUNTS: str = "root,wazuh"
    MAPEK_PROTECTED_PROCESSES: str = "sshd,wazuh-agentd"
    MAPEK_PROTECTED_SERVICES: str = "sshd,wazuh-agent"
    MAPEK_PROTECTED_PORTS: str = "22,55000,9200"
    MAPEK_MAINTENANCE_WINDOW_ACTIVE: bool = False

    # Clerk authenticates every application API request. The secret and
    # optional PEM JWT key are server-only and must never be exposed through a
    # NEXT_PUBLIC_* variable.
    CLERK_SECRET_KEY: SecretStr = SecretStr("")
    CLERK_JWT_KEY: SecretStr = SecretStr("")
    CLERK_AUTHORIZED_PARTIES: str = "http://localhost:3000"
    # Comma-separated Clerk user IDs allowed to execute approved responses.
    # Empty means no user can execute, while approval remains a separate step.
    CLERK_EXECUTOR_USER_IDS: str = ""
    CLERK_SOC_L2_USER_IDS: str = ""
    CLERK_SOC_L3_USER_IDS: str = ""
    CLERK_SECURITY_ADMIN_USER_IDS: str = ""
    CLERK_AUDITOR_USER_IDS: str = ""

    # LangSmith tracing
    LANGSMITH_API_KEY: SecretStr = SecretStr("")
    LANGSMITH_TRACING: bool = False
    LANGSMITH_PROJECT: str = "tsage"
    LANGSMITH_ENDPOINT: str | None = None
    LANGSMITH_HIDE_INPUTS: bool = True
    LANGSMITH_HIDE_OUTPUTS: bool = True
    LANGSMITH_INCLUDE_RAW_ALERTS: bool = False
    LANGSMITH_INCLUDE_FULL_LOG: bool = False
    LANGSMITH_INCLUDE_FULL_INVENTORY: bool = False
    REVISION_ID: str = "development"

    # Wazuh (reached through SSH tunnel to PC1, so localhost)
    WAZUH_INDEXER_HOST: str = "127.0.0.1"
    WAZUH_INDEXER_PORT: int = 9200
    WAZUH_INDEXER_USER: str = "admin"
    WAZUH_INDEXER_PASSWORD: SecretStr = SecretStr("")
    WAZUH_ARCHIVE_INDEX: str = "wazuh-archives-*"
    WAZUH_BASE_URL: str = "https://127.0.0.1:55000"
    # Browsable Wazuh Dashboard (Kibana-style UI), for "Open in Wazuh" links.
    # Distinct from WAZUH_BASE_URL (manager API) and the indexer port; empty
    # hides the links.
    WAZUH_DASHBOARD_URL: str = ""
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
    WAZUH_AGENT_RESPONSE_MODE: str = "compact"
    WAZUH_NORMALIZATION_ENABLED: bool = True
    WAZUH_RAW_EVIDENCE_ENABLED: bool = True
    ALERT_AGGREGATION_WINDOW_SECONDS: int = 300
    AUTH_AGGREGATION_WINDOW_SECONDS: int = 600
    VULNERABILITY_AGGREGATION_WINDOW_SECONDS: int = 86400
    COMPLIANCE_AGGREGATION_WINDOW_SECONDS: int = 86400
    MAX_FINDINGS_PER_AGENT_RESPONSE: int = 10
    MAX_EVIDENCE_REFS_PER_FINDING: int = 20
    MAX_NORMALIZED_ALERTS_PER_RESPONSE: int = 50
    WAZUH_INGESTION_INTERVAL_SECONDS: int = 20
    WAZUH_INGESTION_PAGE_SIZE: int = 500
    WAZUH_INGESTION_MAX_PAGES_PER_RUN: int = 20
    WAZUH_INGESTION_OVERLAP_SECONDS: int = 60
    WAZUH_INGESTION_LEASE_TTL_SECONDS: int = 300
    WAZUH_CONNECTION_PROFILE_ID: str = "default"
    WAZUH_INGESTION_ORGANIZATION_ID: str = "system"

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

    # Telegram connector: push alert notifications, and a command worker that
    # answers /alerts, /status, /ask, etc. through the same SOCAssistant used
    # by the web chat. Bot-token auth only; the bot can never approve or
    # execute a response action, since those commands are not in its catalog.
    TELEGRAM_BOT_TOKEN: SecretStr = SecretStr("")
    TELEGRAM_CHAT_ID: str = ""
    TELEGRAM_ALLOWED_CHAT_IDS: str = ""
    TELEGRAM_MIN_FINDING_SEVERITY: str = "high"
    TELEGRAM_NOTIFY_APPROVALS: bool = True
    TELEGRAM_TIMEOUT_SECONDS: int = 10
    TELEGRAM_POLL_TIMEOUT_SECONDS: int = 30

    @field_validator("TELEGRAM_MIN_FINDING_SEVERITY")
    @classmethod
    def validate_telegram_min_severity(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        }:
            raise ValueError(
                "TELEGRAM_MIN_FINDING_SEVERITY must be informational, low, "
                "medium, high, or critical."
            )
        return normalized

    @field_validator("MAPEK_EXECUTION_MODE")
    @classmethod
    def validate_mapek_execution_mode(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"disabled", "enabled"}:
            raise ValueError(
                "MAPEK_EXECUTION_MODE must be disabled or enabled."
            )
        return normalized

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
