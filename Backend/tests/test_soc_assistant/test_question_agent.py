from app.soc_assistant.question_agent import SOCQuestionAgent
from app.soc_assistant.schemas import QuestionAnswer


class FakeLLM:
    def invoke_structured(self, schema, messages):
        assert schema is QuestionAnswer
        assert "INV-ALLOWED" in messages[-1]["content"]
        return (
            QuestionAnswer(
                answer="The investigation is waiting for approval.",
                references=["INV-ALLOWED", "INV-FABRICATED"],
            ),
            {"input_tokens": 20, "output_tokens": 8},
        )


def test_question_agent_filters_unsupported_references():
    answer, usage = SOCQuestionAgent(llm=FakeLLM()).answer(
        question="What is happening?",
        context={
            "references": {"investigation": "INV-ALLOWED"},
            "investigation": {
                "status": "awaiting_approval",
                "current_stage": "human_approval",
            },
        },
        history=[{"role": "user", "content": "Check the investigation."}],
    )

    assert answer.references == ["INV-ALLOWED"]
    assert usage["output_tokens"] == 8
