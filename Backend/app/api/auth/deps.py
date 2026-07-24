"""Clerk authentication and organization permission dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import logging
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings


logger = logging.getLogger("tsage.auth")
SOC_READ = "org:soc:read"
INVESTIGATIONS_CREATE = "org:investigations:create"
RESPONSES_APPROVE = "org:responses:approve"
RESPONSES_EXECUTE = "org:responses:execute"

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthPrincipal:
    user_id: str
    session_id: str | None
    organization_id: str
    organization_role: str | None
    permissions: frozenset[str]

    def has_permission(self, permission: str) -> bool:
        return (
            self.organization_role == "org:admin"
            or permission in self.permissions
        )


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


def _permission_values(payload: dict[str, Any]) -> frozenset[str]:
    raw = payload.get("org_permissions") or []
    if isinstance(raw, str):
        raw = raw.replace(",", " ").split()
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(str(item) for item in raw if item)


def _principal_from_payload(payload: dict[str, Any]) -> AuthPrincipal:
    user_id = str(payload.get("sub") or "").strip()
    organization_id = str(payload.get("org_id") or "").strip()
    if not user_id:
        raise HTTPException(401, "Clerk session token has no subject.")
    if settings.CLERK_REQUIRE_ORGANIZATION and not organization_id:
        raise HTTPException(403, "Select a Clerk organization to use TSAGE.")
    return AuthPrincipal(
        user_id=user_id,
        session_id=str(payload.get("sid") or "").strip() or None,
        organization_id=organization_id,
        organization_role=str(payload.get("org_role") or "").strip() or None,
        permissions=_permission_values(payload),
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
        repository.upsert_membership(
            organization_id=principal.organization_id,
            user_id=principal.user_id,
            role=principal.organization_role or "org:member",
            permissions=sorted(principal.permissions),
        )
    except Exception as exc:
        if settings.DATABASE_REQUIRED:
            raise HTTPException(
                503,
                "Identity persistence is unavailable.",
            ) from exc
        logger.warning(
            "Clerk identity projection skipped user=%s org=%s error=%s",
            principal.user_id,
            principal.organization_id,
            type(exc).__name__,
        )


def require_principal(
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
    _sync_principal(principal)
    return principal


def require_permission(permission: str) -> Callable[..., AuthPrincipal]:
    def dependency(
        principal: AuthPrincipal = Depends(require_principal),
    ) -> AuthPrincipal:
        if not principal.has_permission(permission):
            raise HTTPException(
                403,
                f"Clerk organization permission required: {permission}.",
            )
        return principal

    dependency.__name__ = f"require_{permission.replace(':', '_')}"
    return dependency


require_read = require_permission(SOC_READ)
require_investigate = require_permission(INVESTIGATIONS_CREATE)
require_approve = require_permission(RESPONSES_APPROVE)
require_write = require_permission(RESPONSES_EXECUTE)
