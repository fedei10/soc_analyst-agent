from app.core.observability.redaction import sanitize
from app.coreAgents.orchestration.conversation_runner import (
    conversation_config,
)


def test_redaction_removes_nested_credentials_and_bearer_tokens():
    value = sanitize(
        {
            "Authorization": "Bearer abc.def.ghi",
            "nested": {
                "database_url": "postgresql://user:password@db/tsage",
                "message": "token=super-secret",
            },
        }
    )

    assert value["Authorization"] == "[REDACTED]"
    assert value["nested"]["database_url"] == "[REDACTED]"
    assert "super-secret" not in value["nested"]["message"]


def test_conversation_config_contains_safe_correlation_metadata():
    config = conversation_config(
        "conversation-1",
        organization_id="user-1",
        user_id="user-1",
    )

    assert config["configurable"]["thread_id"] == "user-1:conversation-1"
    assert config["run_name"] == "soc-chat-conversation"
    assert config["metadata"]["conversation_id"] == "conversation-1"
    assert config["metadata"]["user_id"] == "user-1"
    assert len(config["metadata"]["run_id"]) == 32
    assert config["metadata"]["trace_id"] is None
    assert config["callbacks"]
