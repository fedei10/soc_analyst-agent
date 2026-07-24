"""Set deterministic env BEFORE app.config is imported (env vars beat .env)."""
import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("GROQ_API_KEY", "test")
os.environ.setdefault("OXYY_API_KEY", "test")
os.environ.setdefault("CEREBRAS_API_KEY", "test")
os.environ.setdefault("GOOGLE_API_KEY", "test")
os.environ["CLERK_SECRET_KEY"] = "sk_test_unit"
os.environ["CLERK_AUTHORIZED_PARTIES"] = "http://testserver"
os.environ["CLERK_EXECUTOR_USER_IDS"] = "user_responder"
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["DATABASE_URL"] = ""
os.environ["DATABASE_REQUIRED"] = "false"
os.environ["DATABASE_AUTO_CREATE"] = "false"
os.environ["REDIS_URL"] = ""
os.environ["REDIS_REQUIRED"] = "false"


@pytest.fixture(autouse=True)
def fake_clerk_session(monkeypatch):
    """Keep API tests offline while exercising Clerk user authentication."""
    from app.api.auth import deps

    def authenticate(request):
        authorization = request.headers.get("authorization", "")
        token = authorization.removeprefix("Bearer ").strip()
        if token == "test-write-key":
            return SimpleNamespace(
                is_signed_in=True,
                reason=None,
                payload={
                    "sub": "user_responder",
                    "sid": "sess_responder",
                },
            )
        if token == "test-read-key":
            return SimpleNamespace(
                is_signed_in=True,
                reason=None,
                payload={
                    "sub": "user_analyst",
                    "sid": "sess_analyst",
                },
            )
        return SimpleNamespace(
            is_signed_in=False,
            reason=SimpleNamespace(name="invalid_token"),
            payload={},
        )

    monkeypatch.setattr(deps, "authenticate_clerk_request", authenticate)
