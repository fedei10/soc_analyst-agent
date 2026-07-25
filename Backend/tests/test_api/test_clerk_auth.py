import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api.auth import deps


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


def test_authenticated_l1_user_cannot_approve(monkeypatch):
    principal = _principal(monkeypatch, _state())

    assert asyncio.run(deps.require_read(principal)) == principal
    assert asyncio.run(deps.require_investigate(principal)) == principal
    with pytest.raises(HTTPException) as error:
        asyncio.run(deps.require_approve(principal))
    assert error.value.status_code == 403


def test_approval_does_not_grant_response_execution(monkeypatch):
    principal = _principal(monkeypatch, _state(user_id="user_analyst"))

    assert asyncio.run(deps.require_approve(principal)) == principal
    with pytest.raises(HTTPException) as error:
        asyncio.run(deps.require_execute(principal))
    assert error.value.status_code == 403


def test_allowlisted_responder_can_execute(monkeypatch):
    principal = _principal(monkeypatch, _state(user_id="user_responder"))

    assert asyncio.run(deps.require_execute(principal)) == principal
    assert asyncio.run(deps.require_write(principal)) == principal


def test_user_id_is_the_private_data_scope(monkeypatch):
    principal = _principal(monkeypatch, _state(user_id="user_personal"))

    assert principal.scope_id == "user_personal"


def test_subject_is_required(monkeypatch):
    with pytest.raises(HTTPException) as error:
        _principal(monkeypatch, _state(user_id=""))
    assert error.value.status_code == 401
    assert "subject" in str(error.value.detail).lower()
