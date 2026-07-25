"""Investigation workflow and read-only SOC agent chat endpoints."""

import json
import hashlib
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.api.auth.deps import (
    AuthPrincipal,
    require_approve,
    require_execute,
    require_investigate,
    require_read,
)
from app.api.v1.schemas.investigation import (
    AgentChatRequest,
    ApprovalDecisionInput,
    InvestigationCreate,
    ResponseExecutionInput,
)
from app.coreAgents.orchestration.investigation_service import (
    InvestigationNotFoundError,
    get_investigation_service,
)
from app.db.repositories.investigations import ResponseExecutionConflictError
from app.db.session import database_url
from app.services.redis.ephemeral import EphemeralRedis
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway
from app.soc_assistant.catalog import public_catalog
from app.soc_assistant.schemas import AssistantRequest
from app.soc_assistant.service import SOCAssistant


read = APIRouter(dependencies=[Depends(require_read)])
write = APIRouter(dependencies=[Depends(require_approve)])
logger = structlog.get_logger("tsage.orchestration")
ReadPrincipal = Annotated[AuthPrincipal, Depends(require_read)]
InvestigatorPrincipal = Annotated[
    AuthPrincipal,
    Depends(require_investigate),
]
ApproverPrincipal = Annotated[AuthPrincipal, Depends(require_approve)]
ExecutorPrincipal = Annotated[AuthPrincipal, Depends(require_execute)]
AssistantGateway = Annotated[WazuhGateway, Depends(get_wazuh_gateway)]
activity_store = EphemeralRedis()


def _public_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _public_data(item)
            for key, item in value.items()
            if key != "organization_id"
        }
    if isinstance(value, list):
        return [_public_data(item) for item in value]
    return value


def _enforce_rate_limit(
    principal: AuthPrincipal,
    *,
    operation: str,
    limit: int,
) -> None:
    result = activity_store.check_rate_limit(
        organization_id=principal.scope_id,
        subject=f"{principal.user_id}:{operation}",
        limit=limit,
        window_seconds=60,
    )
    if not result.allowed:
        raise HTTPException(
            429,
            "SOC request rate limit exceeded. Retry in one minute.",
        )


def get_investigation_graph():
    return get_investigation_service().graph


def _snapshot(
    investigation_id: str,
    *,
    organization_id: str,
) -> dict[str, Any]:
    try:
        return get_investigation_service().snapshot(
            investigation_id,
            organization_id=organization_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")


def _publish_activity(snapshot: dict[str, Any]) -> None:
    organization_id = str(snapshot.get("organization_id") or "")
    investigation_id = str(snapshot.get("investigation_id") or "")
    if not organization_id or not investigation_id:
        return
    for item in snapshot.get("audit_events", []):
        if not isinstance(item, dict):
            continue
        fingerprint = hashlib.sha256(
            json.dumps(item, sort_keys=True, default=str).encode()
        ).hexdigest()
        claim = activity_store.claim_idempotency(
            organization_id=organization_id,
            operation_key=f"activity:{investigation_id}:{fingerprint}",
        )
        if not claim.claimed:
            continue
        event_name = str(item.get("event") or "activity")
        activity_store.append_activity(
            organization_id=organization_id,
            investigation_id=investigation_id,
            event=event_name,
            payload=item,
        )
        alias = {
            "approval_required": "awaiting_approval",
            "approval_requested": "awaiting_approval",
            "investigation_completed": "report_ready",
            "knowledge_updated": "report_ready",
        }.get(event_name)
        if alias:
            activity_store.append_activity(
                organization_id=organization_id,
                investigation_id=investigation_id,
                event=alias,
                payload=item,
            )


def _conversation_repository():
    if not database_url():
        raise HTTPException(503, "PostgreSQL conversation history is disabled.")
    from app.db.repositories.conversations import get_conversation_repository

    return get_conversation_repository()


def _initial_state(
    investigation_id: str,
    request: InvestigationCreate,
) -> dict[str, Any]:
    return get_investigation_service().initial_state(
        investigation_id,
        alert_id=request.alert_id,
        agent_id=request.agent_id,
    )


@read.post(
    "/investigations",
    status_code=201,
    tags=["investigations"],
    dependencies=[Depends(require_investigate)],
)
def create_investigation(
    request: InvestigationCreate,
    principal: InvestigatorPrincipal,
):
    _enforce_rate_limit(
        principal,
        operation="create-investigation",
        limit=10,
    )
    snapshot = get_investigation_service().start(
        alert_id=request.alert_id,
        agent_id=request.agent_id,
        initiated_by=principal.user_id,
        organization_id=principal.scope_id,
        owner_user_id=principal.user_id,
    )
    _publish_activity(snapshot)
    return {"data": _public_data(snapshot)}


def _history_item(snapshot: dict[str, Any]) -> dict[str, Any]:
    audit_events = snapshot.get("audit_events", [])
    timestamps = [
        str(item["timestamp"])
        for item in audit_events
        if isinstance(item, dict) and item.get("timestamp")
    ]
    return {
        key: snapshot.get(key)
        for key in (
            "investigation_id",
            "alert_id",
            "agent_id",
            "status",
            "current_stage",
            "severity",
            "confidence",
            "initiated_by",
            "initiation_reason",
        )
    } | {
        "completed_tiers": [
            tier
            for tier in ("l1", "l2", "l3")
            if isinstance(snapshot.get(f"{tier}_result"), dict)
        ],
        "created_at": timestamps[0] if timestamps else None,
        "updated_at": timestamps[-1] if timestamps else None,
    }


@read.get("/investigations", tags=["investigations"])
def list_investigations(
    principal: ReadPrincipal,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(
        default=None,
        pattern=(
            "^(created|running|awaiting_approval|approved|rejected|"
            "completed|escalated|failed)$"
        ),
    ),
):
    service = get_investigation_service()
    items = service.list_history(
        limit=limit,
        offset=offset,
        status=status,
        organization_id=principal.scope_id,
    )
    return {
        "data": {
            "items": [_history_item(item) for item in items],
            "count": len(items),
            "total": service.history_count(
                status=status,
                organization_id=principal.scope_id,
            ),
            "limit": limit,
            "offset": offset,
        }
    }


@read.get(
    "/investigations/{investigation_id}",
    tags=["investigations"],
)
def get_investigation(
    investigation_id: str,
    principal: ReadPrincipal,
):
    return {
        "data": _public_data(
            _snapshot(
                investigation_id,
                organization_id=principal.scope_id,
            )
        )
    }


@write.post(
    "/investigations/{investigation_id}/approval",
    tags=["investigations"],
)
def decide_investigation(
    investigation_id: str,
    request: ApprovalDecisionInput,
    principal: ApproverPrincipal,
):
    before = _snapshot(
        investigation_id,
        organization_id=principal.scope_id,
    )
    if "human_approval" not in before["pending_nodes"]:
        raise HTTPException(
            409,
            "Investigation is not waiting for human approval.",
        )

    snapshot = get_investigation_service().resume(
        investigation_id,
        {
            **request.model_dump(mode="json", exclude_none=True),
            "approved_by": principal.user_id,
            "approver_roles": list(principal.roles),
        },
        organization_id=principal.scope_id,
    )
    _publish_activity(snapshot)
    return {"data": _public_data(snapshot)}


@write.post(
    "/investigations/{investigation_id}/execute",
    tags=["investigations"],
    dependencies=[Depends(require_execute)],
)
def execute_investigation_response(
    investigation_id: str,
    request: ResponseExecutionInput,
    principal: ExecutorPrincipal,
):
    try:
        snapshot = get_investigation_service().execute_approved(
            investigation_id,
            approval_id=request.approval_id,
            executed_by=principal.user_id,
            organization_id=principal.scope_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")
    except ResponseExecutionConflictError as exc:
        raise HTTPException(409, str(exc))
    _publish_activity(snapshot)
    return {"data": _public_data(snapshot)}


@read.get(
    "/investigations/{investigation_id}/report",
    tags=["investigations"],
)
def get_investigation_report(
    investigation_id: str,
    principal: ReadPrincipal,
):
    try:
        report = get_investigation_service().report(
            investigation_id,
            organization_id=principal.scope_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")
    if report is None:
        raise HTTPException(409, "Investigation report is not ready.")
    return {"data": _public_data(report)}


@read.get(
    "/investigations/{investigation_id}/tier-reports",
    tags=["investigations"],
)
def get_investigation_tier_reports(
    investigation_id: str,
    principal: ReadPrincipal,
):
    try:
        items = get_investigation_service().tier_reports(
            investigation_id,
            organization_id=principal.scope_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")
    return {
        "data": {
            "items": _public_data(items),
            "count": len(items),
        }
    }


@read.get(
    "/investigations/{investigation_id}/agent-runs",
    tags=["investigations"],
)
def get_investigation_agent_runs(
    investigation_id: str,
    principal: ReadPrincipal,
):
    try:
        items = get_investigation_service().agent_runs(
            investigation_id,
            organization_id=principal.scope_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")
    return {
        "data": {
            "items": _public_data(items),
            "count": len(items),
        }
    }


@read.get(
    "/investigations/{investigation_id}/audit",
    tags=["investigations"],
)
def get_investigation_audit(
    investigation_id: str,
    principal: ReadPrincipal,
):
    try:
        items = get_investigation_service().audit_history(
            investigation_id,
            organization_id=principal.scope_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")
    return {
        "data": {
            "items": _public_data(items),
            "count": len(items),
        }
    }


@read.get(
    "/investigations/{investigation_id}/approvals",
    tags=["investigations"],
)
def get_investigation_approvals(
    investigation_id: str,
    principal: ReadPrincipal,
):
    try:
        items = get_investigation_service().approval_history(
            investigation_id,
            organization_id=principal.scope_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")
    return {
        "data": {
            "items": _public_data(items),
            "count": len(items),
        }
    }


@read.get(
    "/investigations/{investigation_id}/actions",
    tags=["investigations"],
)
def get_investigation_actions(
    investigation_id: str,
    principal: ReadPrincipal,
):
    try:
        items = get_investigation_service().response_actions(
            investigation_id,
            organization_id=principal.scope_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")
    return {
        "data": {
            "items": _public_data(items),
            "count": len(items),
        }
    }


@read.get(
    "/investigations/{investigation_id}/events",
    tags=["investigations"],
)
def stream_investigation_activity(
    investigation_id: str,
    principal: ReadPrincipal,
    after_id: str | None = Query(default=None, max_length=128),
):
    _snapshot(
        investigation_id,
        organization_id=principal.scope_id,
    )

    def events():
        redis_events = activity_store.read_activity(
            organization_id=principal.scope_id,
            investigation_id=investigation_id,
            after_id=after_id,
            limit=500,
        )
        if redis_events:
            for item in redis_events:
                yield _sse(
                    str(item["event"]),
                    _public_data({
                        "id": item["id"],
                        "timestamp": item.get("timestamp"),
                        **(item.get("payload") or {}),
                    }),
                )
            return

        for item in get_investigation_service().audit_history(
            investigation_id,
            organization_id=principal.scope_id,
        ):
            yield _sse(
                str(item.get("event") or "activity"),
                _public_data(item),
            )

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@read.get("/soc/conversations", tags=["agents"])
def list_conversations(
    principal: ReadPrincipal,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    items = _conversation_repository().list_conversations(
        organization_id=principal.scope_id,
        owner_user_id=principal.user_id,
        limit=limit,
        offset=offset,
    )
    return {
        "data": {
            "items": _public_data(items),
            "count": len(items),
            "limit": limit,
            "offset": offset,
        }
    }


@read.get(
    "/soc/conversations/{conversation_id}/messages",
    tags=["agents"],
)
def list_conversation_messages(
    conversation_id: str,
    principal: ReadPrincipal,
    limit: int = Query(default=100, ge=1, le=200),
):
    repository = _conversation_repository()
    conversation = repository.get_conversation(
        conversation_id,
        organization_id=principal.scope_id,
    )
    if conversation is None:
        raise HTTPException(404, "Conversation not found.")
    if conversation["owner_user_id"] != principal.user_id:
        raise HTTPException(404, "Conversation not found.")
    items = repository.list_messages(
        conversation_id,
        organization_id=principal.scope_id,
        limit=limit,
    )
    return {
        "data": {
            "items": _public_data(items),
            "count": len(items),
        }
    }


@read.post(
    "/soc/chat",
    tags=["agents"],
    dependencies=[Depends(require_investigate)],
)
def chat_with_soc_agent(
    request: AgentChatRequest,
    principal: InvestigatorPrincipal,
):
    raise HTTPException(
        410,
        "SOC agent chat was retired. Start a controlled MAPE-K investigation.",
    )


@read.post(
    "/soc/orchestrator/chat",
    tags=["assistant"],
    dependencies=[Depends(require_investigate)],
)
def chat_with_soc_orchestrator(
    request: AssistantRequest,
    principal: InvestigatorPrincipal,
    gateway: AssistantGateway,
):
    _enforce_rate_limit(principal, operation="soc-assistant", limit=30)
    try:
        result = SOCAssistant(gateway=gateway).respond(
            message=request.message,
            conversation_id=request.conversation_id,
            organization_id=principal.scope_id,
            user_id=principal.user_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except Exception as exc:
        logger.exception(
            "soc_assistant_failed",
            error_type=type(exc).__name__,
        )
        raise HTTPException(
            503,
            "The requested SOC capability could not be completed.",
        ) from exc
    return {"data": _public_data(result.model_dump(mode="json"))}


@read.get("/soc/assistant/commands", tags=["assistant"])
def get_soc_assistant_commands(_: ReadPrincipal):
    commands = public_catalog()
    return {"data": {"items": commands, "count": len(commands)}}


def _sse(event: str, payload: dict[str, Any]) -> str:
    public_payload = _public_data(payload)
    return (
        f"event: {event}\n"
        f"data: {json.dumps(public_payload, default=str)}\n\n"
    )


@read.post(
    "/soc/orchestrator/chat/stream",
    tags=["assistant"],
    dependencies=[Depends(require_investigate)],
)
def stream_with_soc_orchestrator(
    request: AssistantRequest,
    principal: InvestigatorPrincipal,
    gateway: AssistantGateway,
):
    _enforce_rate_limit(principal, operation="soc-assistant-stream", limit=30)

    def events():
        yield _sse(
            "activity",
            {
                "id": "activity-routing",
                "tool": "intent_router",
                "label": "Routing the request to a bounded SOC capability",
                "status": "running",
            },
        )
        try:
            assistant = SOCAssistant(gateway=gateway)
            routed = assistant.route(request.message)
            intent, _ = routed
            yield _sse(
                "activity",
                {
                    "id": "activity-selected",
                    "tool": "intent_router",
                    "label": f"Selected {intent.command.value} capability",
                    "status": "completed",
                },
            )
            yield _sse(
                "activity",
                assistant.running_activity(intent.command).model_dump(
                    mode="json"
                ),
            )
            result = assistant.respond(
                message=request.message,
                conversation_id=request.conversation_id,
                organization_id=principal.scope_id,
                user_id=principal.user_id,
                routed=routed,
            )
        except Exception as exc:
            yield _sse(
                "error",
                {
                    "code": type(exc).__name__,
                    "message": str(exc)[:500],
                },
            )
            return
        for activity in result.activities:
            yield _sse("activity", activity.model_dump(mode="json"))
        yield _sse("token", {"content": result.assistant_message})
        yield _sse("final", result.model_dump(mode="json"))

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
