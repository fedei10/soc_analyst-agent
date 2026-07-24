from types import SimpleNamespace

from app.coreAgents.orchestration.agent_runner import (
    _format_transcript,
    invoke_validated_agent,
)
from app.coreAgents.orchestration.schemas import L1Result


class StructuredFakeAgent:
    def invoke(self, input_data):
        return {
            "messages": input_data["messages"],
            "structured_response": {
                "summary": "Validated triage",
                "classification": "benign",
                "severity": "low",
                "confidence": 0.9,
                "evidence_refs": ["alert:alert-1"],
            },
        }


def test_runner_accepts_provider_structured_response_without_formatter():
    response, validated = invoke_validated_agent(
        StructuredFakeAgent(),
        messages=[{"role": "user", "content": "triage alert"}],
        result_model=L1Result,
    )

    assert response["structured_response"]["severity"] == "low"
    assert isinstance(validated, L1Result)
    assert validated.summary == "Validated triage"


def test_transcript_serializes_tool_calls_for_formatter():
    transcript = _format_transcript(
        [
            SimpleNamespace(
                type="ai",
                content="Checking Wazuh.",
                name=None,
                tool_calls=[{"name": "get_alert_by_id", "args": {}}],
            )
        ]
    )

    assert "get_alert_by_id" in transcript
    assert "Checking Wazuh." in transcript


def test_transcript_bounds_large_tool_results():
    transcript = _format_transcript([
        SimpleNamespace(
            type="tool",
            content='{"alerts": [' + ",".join(
                f'{{"alert_id": "alert-{index}"}}'
                for index in range(100)
            ) + "]}",
            name="get_related_alerts",
            tool_calls=None,
        )
    ])

    assert len(transcript) < 7000
    assert "alert-0" in transcript
    assert "_truncated_items" in transcript
