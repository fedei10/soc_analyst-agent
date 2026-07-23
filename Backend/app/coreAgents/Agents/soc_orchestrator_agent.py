"""Structured router for conversational SOC requests."""

import json

from app.coreAgents.llm.model_pool import (
    ROUTER_PROVIDER_ORDER,
    get_structured_model,
)
from app.coreAgents.orchestration.schemas import OrchestratorDecision
from app.coreAgents.tools.python_functions.yaml_loader import load_prompt_template


router = get_structured_model(
    OrchestratorDecision,
    ROUTER_PROVIDER_ORDER,
)


def route_soc_request(
    messages: list[dict],
    *,
    router_model=None,
) -> OrchestratorDecision:
    """Choose one specialist without changing or executing the user's task."""
    model = router_model or router
    decision = model.invoke(
        [
            {
                "role": "system",
                "content": load_prompt_template(
                    "soc_orchestrator_system_prompt"
                ),
            },
            {
                "role": "user",
                "content": json.dumps(messages, default=str),
            },
        ]
    )
    return OrchestratorDecision.model_validate(decision)
