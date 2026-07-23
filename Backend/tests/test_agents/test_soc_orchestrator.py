from app.coreAgents.Agents.soc_orchestrator_agent import route_soc_request
from app.coreAgents.orchestration.schemas import OrchestratorDecision


class FakeRouter:
    def __init__(self, decision):
        self.decision = decision
        self.input = None

    def invoke(self, input_data):
        self.input = input_data
        return self.decision


def test_router_returns_validated_specialist_decision():
    router = FakeRouter(
        {
            "selected_agent": "l2",
            "reason": "The request requires alert correlation.",
        }
    )

    decision = route_soc_request(
        [{"role": "user", "content": "Correlate related alerts."}],
        router_model=router,
    )

    assert isinstance(decision, OrchestratorDecision)
    assert decision.selected_agent == "l2"
    assert "Correlate related alerts." in router.input[1]["content"]
