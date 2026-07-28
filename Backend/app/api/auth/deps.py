"""Clerk session authentication for personal TSAGE accounts."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import structlog
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings
from app.core.observability.context import bind_context


logger = structlog.get_logger("tsage.auth")

_bearer = HTTPBearer(auto_error=False)


# Single-tenant install: every signed-in user holds every role, and all data
# lives under one scope. Authentication still applies - authorization does
# not. Restoring tiers means putting the user-id allowlists back in
# _principal_from_payload and the membership checks back in require_approve
# and require_execute; nothing else reads roles directly.
ALL_ROLES: tuple[str, ...] = (
    "auditor",
    "security_admin",
    "soc_l1",
    "soc_l2",
    "soc_l3",
)


@dataclass(frozen=True)
class AuthPrincipal:
    user_id: str
    session_id: str | None
    scope_id: str
    roles: tuple[str, ...] = ALL_ROLES


def _secret(value) -> str | None:
    raw = value.get_secret_value().strip()
    return raw or None


def _authorized_parties() -> list[str]:
    return [
        value.strip().rstrip("/")
        for value in settings.CLERK_AUTHORIZED_PARTIES.split(",")
        if value.strip()
    ]


@lru_cache(maxsize=1)
def _clerk_types():
    try:
        from clerk_backend_api import (
            AuthenticateRequestOptions,
            authenticate_request,
        )
    except ImportError as exc:
        raise HTTPException(
            503,
            "Clerk authentication is unavailable; install clerk-backend-api.",
        ) from exc
    return authenticate_request, AuthenticateRequestOptions


def authenticate_clerk_request(request: Request):
    """Verify a Clerk session token and return the SDK request state."""

    secret_key = _secret(settings.CLERK_SECRET_KEY)
    jwt_key = _secret(settings.CLERK_JWT_KEY)
    if not secret_key and not jwt_key:
        raise HTTPException(
            503,
            "Clerk authentication is not configured.",
        )

    authenticate_request, options_type = _clerk_types()
    return authenticate_request(
        request,
        options_type(
            secret_key=secret_key,
            jwt_key=jwt_key,
            authorized_parties=_authorized_parties(),
            accepts_token=["session_token"],
        ),
    )


def _principal_from_payload(payload: dict[str, Any]) -> AuthPrincipal:
    user_id = str(payload.get("sub") or "").strip()
    if not user_id:
        raise HTTPException(401, "Clerk session token has no subject.")
    return AuthPrincipal(
        user_id=user_id,
        session_id=str(payload.get("sid") or "").strip() or None,
        # One scope for the whole install, and the same one the ingestion
        # worker writes alerts and findings under - a per-user scope hid
        # that shared telemetry from the analyst reading it.
        scope_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
        roles=ALL_ROLES,
    )


def _sync_principal(principal: AuthPrincipal) -> None:
    """Project verified Clerk identity into PostgreSQL when it is enabled."""

    from app.db.session import database_url

    if not database_url():
        return
    try:
        from app.db.repositories.identity import get_identity_repository

        repository = get_identity_repository()
        repository.upsert_user(user_id=principal.user_id)
    except Exception as exc:
        if settings.DATABASE_REQUIRED:
            raise HTTPException(
                503,
                "Identity persistence is unavailable.",
            ) from exc
        logger.warning(
            "identity_projection_skipped",
            user_id=principal.user_id,
            error_type=type(exc).__name__,
        )


async def require_principal(
    request: Request,
    _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> AuthPrincipal:
    state = authenticate_clerk_request(request)
    if not bool(
        getattr(state, "is_signed_in", False)
        or getattr(state, "is_authenticated", False)
    ):
        reason = getattr(state, "reason", None)
        reason_text = getattr(reason, "name", None) or "Invalid Clerk session token."
        raise HTTPException(
            401,
            str(reason_text),
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = getattr(state, "payload", None)
    if not isinstance(payload, dict):
        raise HTTPException(401, "Clerk session token has no claims.")
    principal = _principal_from_payload(payload)
    request.state.principal = principal
    bind_context(
        user_id=principal.user_id,
        organization_id=principal.scope_id,
    )
    _sync_principal(principal)
    return principal


async def require_authenticated(
    principal: AuthPrincipal = Depends(require_principal),
) -> AuthPrincipal:
    return principal


# Every gate is now "be signed in". Kept as separate names so the call sites
# still say which privilege they need, and so restoring a tier is a change
# here rather than across every endpoint.
require_read = require_authenticated
require_investigate = require_authenticated
require_approve = require_authenticated
require_execute = require_authenticated
require_write = require_authenticated
