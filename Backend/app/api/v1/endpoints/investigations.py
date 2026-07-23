"""Investigation workflow and read-only SOC agent chat endpoints."""

import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.auth.deps import require_read, require_write
from app.api.v1.schemas.investigation import (
    AgentChatRequest,
    ApprovalDecisionInput,
    InvestigationCreate,
    OrchestratorChatRequest,
)
from app.coreAgents.orchestration.agent_runner import invoke_validated_agent
from app.coreAgents.orchestration.conversation_runner import (
    run_soc_conversation,
    stream_soc_conversation,
)
from app.coreAgents.orchestration.investigation_service import (
    InvestigationNotFoundError,
    get_investigation_service,
)
from app.coreAgents.orchestration.schemas import L1Result, L2Result, L3Result


read = APIRouter(dependencies=[Depends(require_read)])
write = APIRouter(dependencies=[Depends(require_write)])
logger = logging.getLogger("tsage.orchestration")


def get_investigation_graph():
    return get_investigation_service().graph


def _snapshot(investigation_id: str) -> dict[str, Any]:
    try:
        return get_investigation_service().snapshot(investigation_id)
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")


def _initial_state(
    investigation_id: str,
    request: InvestigationCreate,
) -> dict[str, Any]:
    return get_investigation_service().initial_state(
        investigation_id,
        alert_id=request.alert_id,
        agent_id=request.agent_id,
    )


@read.post("/investigations", status_code=201, tags=["investigations"])
def create_investigation(request: InvestigationCreate):
    snapshot = get_investigation_service().start(
        alert_id=request.alert_id,
        agent_id=request.agent_id,
        initiated_by="api",
    )
    return {"data": snapshot}


@read.get(
    "/investigations/{investigation_id}",
    tags=["investigations"],
)
def get_investigation(investigation_id: str):
    return {"data": _snapshot(investigation_id)}


@write.post(
    "/investigations/{investigation_id}/approval",
    tags=["investigations"],
)
def decide_investigation(
    investigation_id: str,
    request: ApprovalDecisionInput,
):
    before = _snapshot(investigation_id)
    if "human_approval" not in before["pending_nodes"]:
        raise HTTPException(
            409,
            "Investigation is not waiting for human approval.",
        )

    snapshot = get_investigation_service().resume(
        investigation_id,
        request.model_dump(mode="json", exclude_none=True),
    )
    return {"data": snapshot}


@read.get(
    "/investigations/{investigation_id}/report",
    tags=["investigations"],
)
def get_investigation_report(investigation_id: str):
    state = _snapshot(investigation_id)
    if state["final_report"] is None:
        raise HTTPException(409, "Investigation report is not ready.")
    return {"data": state["final_report"]}


def _agent_for_tier(tier: str):
    if tier == "l1":
        from app.coreAgents.Agents.soc_level1_agent import agent
        result_model = L1Result
    elif tier == "l2":
        from app.coreAgents.Agents.soc_level2_agent import agent
        result_model = L2Result
    else:
        from app.coreAgents.Agents.soc_level3_agent import agent
        result_model = L3Result
    return agent, result_model


def _structured_data(value):
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return value
    raise ValueError("Agent did not return validated structured output.")


def _tool_names(result: dict) -> list[str]:
    names: list[str] = []
    for message in result.get("messages", []):
        for call in getattr(message, "tool_calls", []) or []:
            name = call.get("name")
            if name and name not in names:
                names.append(name)
    return names


@read.post("/soc/chat", tags=["agents"])
def chat_with_soc_agent(request: AgentChatRequest):
    messages = [
        item.model_dump(mode="json")
        for item in request.history
    ]
    messages.append({"role": "user", "content": request.message})

    try:
        agent, result_model = _agent_for_tier(request.tier)
        result, validated = invoke_validated_agent(
            agent,
            messages=messages,
            result_model=result_model,
        )
        structured = _structured_data(validated)
    except Exception as exc:
        raise HTTPException(
            503,
            "SOC agent is unavailable. Check the LLM and Wazuh connections.",
        ) from exc

    return {
        "data": {
            "tier": request.tier,
            "response": structured,
            "tools_used": _tool_names(result),
            "assistant_message": json.dumps(structured, indent=2),
        }
    }


@read.post("/soc/orchestrator/chat", tags=["agents"])
def chat_with_soc_orchestrator(request: OrchestratorChatRequest):
    conversation_id = request.conversation_id or uuid.uuid4().hex
    try:
        result = run_soc_conversation(
            message=request.message,
            conversation_id=conversation_id,
        )
    except Exception as exc:
        logger.exception("SOC conversation failed.")
        raise HTTPException(
            503,
            "SOC conversation is unavailable. Check the LLM and Wazuh connections.",
        ) from exc
    return {"data": result}


def _sse(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"


@read.post("/soc/orchestrator/chat/stream", tags=["agents"])
def stream_with_soc_orchestrator(request: OrchestratorChatRequest):
    conversation_id = request.conversation_id or uuid.uuid4().hex

    def events():
        for event, payload in stream_soc_conversation(
            message=request.message,
            conversation_id=conversation_id,
        ):
            yield _sse(event, payload)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
