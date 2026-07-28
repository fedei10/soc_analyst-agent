import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api.auth import deps
from app.config import settings


def _state(
    *,
    user_id: str = "user_test",
):
    return SimpleNamespace(
        is_signed_in=True,
        payload={"sub": user_id, "sid": "sess_test"},
        reason=None,
    )


def _principal(monkeypatch, state):
    monkeypatch.setattr(deps, "authenticate_clerk_request", lambda _: state)
    request = Request({"type": "http", "headers": []})
    return asyncio.run(deps.require_principal(request, None))


def test_every_gate_admits_any_authenticated_user(monkeypatch):
    """Single-tenant install: signing in is the only authorization tier."""

    principal = _principal(monkeypatch, _state())

    for gate in (
        deps.require_read,
        deps.require_investigate,
        deps.require_approve,
        deps.require_execute,
        deps.require_write,
    ):
        assert asyncio.run(gate(principal)) == principal
    assert set(principal.roles) == set(deps.ALL_ROLES)


def test_scope_is_shared_rather_than_per_user(monkeypatch):
    """Two users land in one scope, so neither hides data from the other."""

    first = _principal(monkeypatch, _state(user_id="user_one"))
    second = _principal(monkeypatch, _state(user_id="user_two"))

    assert first.user_id != second.user_id
    assert first.scope_id == second.scope_id
    # The same scope the ingestion worker writes alerts and findings under.
    assert first.scope_id == settings.WAZUH_INGESTION_ORGANIZATION_ID


def test_subject_is_required(monkeypatch):
    with pytest.raises(HTTPException) as error:
        _principal(monkeypatch, _state(user_id=""))
    assert error.value.status_code == 401
    assert "subject" in str(error.value.detail).lower()
