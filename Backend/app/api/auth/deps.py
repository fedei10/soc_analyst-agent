"""
Bearer-token auth with two scopes (same model as the Wazuh MCP server):

  wazuh:read  -> safe read-only endpoints. Tokens for SOC L1/L2 agents.
  wazuh:write -> state-changing response actions. Tokens stay human-held,
                 which is how "human approval" is enforced: an agent that
                 only holds a read token cannot execute a response.

Which subset of read endpoints an L1 vs L2 agent may call is decided where
the agent's tools are registered (coreAgents), not here — the API only
distinguishes read from write.
"""
import secrets

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from app.config import settings

_bearer = HTTPBearer(auto_error=False)


def _keys(raw: SecretStr) -> list[str]:
    return [k.strip() for k in raw.get_secret_value().split(",") if k.strip()]


def _matches(token: str, keys: list[str]) -> bool:
    return any(secrets.compare_digest(token, k) for k in keys)


def _token(credentials: HTTPAuthorizationCredentials | None) -> str:
    if not _keys(settings.SOC_READ_API_KEYS) and not _keys(settings.SOC_WRITE_API_KEYS):
        raise HTTPException(
            503, "API auth is not configured — set SOC_READ_API_KEYS/SOC_WRITE_API_KEYS in .env."
        )
    if credentials is None:
        raise HTTPException(
            401, "Missing bearer token.", headers={"WWW-Authenticate": "Bearer"}
        )
    return credentials.credentials


def require_read(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> str:
    """Accepts read or write tokens (write implies read)."""
    token = _token(credentials)
    if _matches(token, _keys(settings.SOC_READ_API_KEYS) + _keys(settings.SOC_WRITE_API_KEYS)):
        return "wazuh:read"
    raise HTTPException(401, "Invalid bearer token.", headers={"WWW-Authenticate": "Bearer"})


def require_write(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> str:
    """Accepts write tokens only — response actions need a human-held token."""
    token = _token(credentials)
    if _matches(token, _keys(settings.SOC_WRITE_API_KEYS)):
        return "wazuh:write"
    if _matches(token, _keys(settings.SOC_READ_API_KEYS)):
        raise HTTPException(
            403, "This token has the wazuh:read scope; response actions need wazuh:write."
        )
    raise HTTPException(401, "Invalid bearer token.", headers={"WWW-Authenticate": "Bearer"})
