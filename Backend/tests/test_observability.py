from app.core.observability.redaction import sanitize
from app.mape_k.graph import investigation_config


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


def test_workflow_config_contains_safe_correlation_metadata():
    config = investigation_config("INV-1")

    assert config["configurable"]["thread_id"] == "INV-1"
    assert config["run_name"] == "mapek-security-investigation"
    assert config["metadata"] == {
        "investigation_id": "INV-1",
        "workflow": "mape-k",
    }
