from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api.auth import deps


def _state(
    *,
    role: str = "org:soc_analyst",
    permissions: list[str] | None = None,
    org_id: str | None = "org_test",
):
    payload = {
        "sub": "user_test",
        "sid": "sess_test",
        "org_role": role,
        "org_permissions": permissions or [],
    }
    if org_id is not None:
        payload["org_id"] = org_id
    return SimpleNamespace(is_signed_in=True, payload=payload, reason=None)


def _principal(monkeypatch, state):
    monkeypatch.setattr(deps, "authenticate_clerk_request", lambda _: state)
    request = Request({"type": "http", "headers": []})
    return deps.require_principal(request, None)


def test_analyst_permissions_are_enforced(monkeypatch):
    principal = _principal(
        monkeypatch,
        _state(
            permissions=[
                deps.SOC_READ,
                deps.INVESTIGATIONS_CREATE,
            ]
        ),
    )

    assert deps.require_read(principal) == principal
    with pytest.raises(HTTPException) as approve:
        deps.require_approve(principal)
    assert approve.value.status_code == 403
    with pytest.raises(HTTPException) as execute:
        deps.require_write(principal)
    assert execute.value.status_code == 403


def test_admin_role_can_use_all_soc_permissions(monkeypatch):
    principal = _principal(monkeypatch, _state(role="org:admin"))

    assert deps.require_read(principal) == principal
    assert deps.require_approve(principal) == principal
    assert deps.require_write(principal) == principal


def test_active_organization_is_required(monkeypatch):
    with pytest.raises(HTTPException) as error:
        _principal(
            monkeypatch,
            _state(
                permissions=[deps.SOC_READ],
                org_id=None,
            ),
        )
    assert error.value.status_code == 403
    assert "organization" in str(error.value.detail).lower()
