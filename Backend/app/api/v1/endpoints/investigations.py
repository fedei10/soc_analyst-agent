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
    CommandExplainInput,
    ExecutionInput,
    InvestigationStartInput,
)
from app.config import settings
from app.orchestration.investigation_service import (
    InvestigationNotFoundError,
    get_investigation_service,
)
from app.db.repositories.investigations import (
    ResponseExecutionConflictError,
)
from app.db.repositories.findings import (
    FindingRepository,
    get_finding_repository,
)
from app.db.session import database_url
from app.services.redis.ephemeral import EphemeralRedis
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway
from app.soc_assistant.catalog import public_catalog
from app.soc_assistant.command_explainer import (
    MAX_COMMAND_LENGTH,
    explain_command,
)
from app.soc_assistant.handoff import build_shift_handoff
from app.services.telegram.notifier import get_telegram_notifier
from app.soc_assistant.overview import build_soc_overview, build_soc_platform
from app.soc_assistant.references import (
    InvestigationReferenceError,
    resolve_investigation_reference,
)
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
FindingRepo = Annotated[FindingRepository, Depends(get_finding_repository)]
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


@read.post(
    "/investigations",
    tags=["investigations"],
    status_code=202,
    dependencies=[Depends(require_investigate)],
)
def queue_investigation(
    request: InvestigationStartInput,
    principal: InvestigatorPrincipal,
    gateway: AssistantGateway,
):
    service = get_investigation_service()
    try:
        resolved = resolve_investigation_reference(
            request.alert_id,
            agent_id=request.agent_id,
            organization_id=principal.scope_id,
            gateway=gateway,
            investigations=service,
        )
    except InvestigationReferenceError as exc:
        raise HTTPException(400, exc.payload()) from exc
    if resolved.existing_investigation is not None:
        snapshot = resolved.existing_investigation
    else:
        snapshot = service.enqueue(
            alert_id=resolved.alert_id,
            finding_id=resolved.finding_id,
            agent_id=resolved.agent_id,
            initiated_by=principal.user_id,
            initiation_reason=request.reason or "Queued through the API.",
            organization_id=principal.scope_id,
            owner_user_id=principal.user_id,
        )
    return {"data": _public_data(snapshot)}


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

    snapshot = get_investigation_service().submit_approval(
        investigation_id,
        approval_id=request.approval_id,
        decision=request.decision,
        comment=request.comment,
        actor_user_id=principal.user_id,
        actor_roles=principal.roles,
        organization_id=principal.scope_id,
    )
    _publish_activity(snapshot)
    return {"data": _public_data(snapshot)}


@read.get("/investigations/{investigation_id}", tags=["investigations"])
def get_investigation(investigation_id: str, principal: ReadPrincipal):
    return {
        "data": _public_data(
            _snapshot(investigation_id, organization_id=principal.scope_id)
        )
    }


@write.post("/investigations/{investigation_id}/execute", tags=["investigations"])
def execute_investigation(
    investigation_id: str,
    request: ExecutionInput,
    principal: ExecutorPrincipal,
):
    """Resume an approved plan at the execution-authorization interrupt.

    Approval alone only records the decision; the graph parks at
    execution_authorization until this claim arrives, so without this route an
    approved plan never runs.
    """
    try:
        snapshot = get_investigation_service().execute_approved(
            investigation_id,
            approval_id=request.approval_id,
            executed_by=principal.user_id,
            executor_roles=principal.roles,
            organization_id=principal.scope_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(404, f"Investigation {investigation_id} not found.")
    except ResponseExecutionConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    _publish_activity(snapshot)
    return {"data": _public_data(snapshot)}


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


@read.get("/soc/overview", tags=["assistant"])
def get_soc_overview(
    principal: ReadPrincipal,
    gateway: AssistantGateway,
    finding_repository: FindingRepo,
    hours: int = Query(default=24, ge=1, le=168),
):
    service = get_investigation_service()
    snapshots = service.list_history(
        limit=100,
        organization_id=principal.scope_id,
    )
    findings = finding_repository.list(
        organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
        limit=100,
    )
    try:
        alert_summary = gateway.alert_summary(hours=hours)
    except Exception as exc:
        logger.warning(
            "soc_overview_wazuh_unavailable",
            error_type=type(exc).__name__,
        )
        alert_summary = None
    overview = build_soc_overview(
        investigations=snapshots,
        investigation_total=service.history_count(
            organization_id=principal.scope_id,
        ),
        findings=findings,
        alert_summary=alert_summary,
        window_hours=hours,
    )
    return {"data": _public_data(overview.model_dump(mode="json"))}


@read.get("/soc/handoff", tags=["assistant"])
def get_shift_handoff(
    principal: ReadPrincipal,
    gateway: AssistantGateway,
    finding_repository: FindingRepo,
    hours: int = Query(default=8, ge=1, le=48),
):
    service = get_investigation_service()
    snapshots = service.list_history(
        limit=50,
        organization_id=principal.scope_id,
    )
    findings = finding_repository.list(
        organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
        limit=50,
    )
    try:
        alert_summary = gateway.alert_summary(hours=hours)
    except Exception as exc:
        logger.warning(
            "soc_handoff_wazuh_unavailable",
            error_type=type(exc).__name__,
        )
        alert_summary = None
    try:
        handoff = build_shift_handoff(
            investigations=snapshots,
            findings=findings,
            alert_summary=alert_summary,
            window_hours=hours,
        )
    except Exception as exc:
        logger.warning(
            "soc_handoff_generation_failed",
            error_type=type(exc).__name__,
        )
        raise HTTPException(
            503,
            "The handoff writer is unavailable. Try again shortly.",
        )
    return {"data": handoff}


@read.post("/soc/explain-command", tags=["assistant"])
def post_explain_command(
    request: CommandExplainInput,
    principal: ReadPrincipal,
):
    try:
        explanation, usage = explain_command(
            request.command[:MAX_COMMAND_LENGTH],
        )
    except Exception as exc:
        logger.warning(
            "soc_command_explainer_failed",
            error_type=type(exc).__name__,
        )
        raise HTTPException(
            503,
            "The command explainer is unavailable. Try again shortly.",
        )
    return {
        "data": {
            **explanation.model_dump(mode="json"),
            "token_usage": {
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
            },
        }
    }


@read.post(
    "/soc/telegram/test",
    tags=["assistant"],
    dependencies=[Depends(require_investigate)],
)
def post_telegram_test(_: InvestigatorPrincipal):
    notifier = get_telegram_notifier()
    if not notifier.configured:
        raise HTTPException(
            409,
            "Telegram is not configured. Set TELEGRAM_BOT_TOKEN and "
            "TELEGRAM_CHAT_ID.",
        )
    sent = notifier.send(
        "TSAGE SOC connector test: if you can read this, alert push is working."
    )
    if not sent:
        raise HTTPException(502, "Telegram rejected the test message.")
    return {"data": {"sent": True}}


@read.get("/soc/platform", tags=["assistant"])
def get_soc_platform(principal: ReadPrincipal):
    snapshots = get_investigation_service().list_history(
        limit=100,
        organization_id=principal.scope_id,
    )
    assignments = [
        {
            "role": "soc_assistant",
            "provider": settings.LLM_PROVIDER,
            "model": settings.LLM_MODEL,
        },
        {
            "role": "intent_router",
            "provider": settings.LLM_PROVIDER,
            "model": settings.LLM_ROUTER_MODEL or settings.LLM_MODEL,
        },
        {
            "role": "mape_k_analyze_and_plan",
            "provider": settings.LLM_PROVIDER,
            "model": settings.LLM_MODEL,
        },
    ]
    platform = build_soc_platform(
        investigations=snapshots,
        model_assignments=assignments,
        response_policy={
            "wazuh_read_only": settings.WAZUH_READ_ONLY,
            "dangerous_tools_enabled": settings.WAZUH_ALLOW_DANGEROUS_TOOLS,
            "dry_run": settings.MAPEK_DRY_RUN,
            "real_execution_enabled": settings.MAPEK_REAL_EXECUTION_ENABLED,
            "self_healing_enabled": settings.SELF_HEALING_ENABLED,
            "human_approval_required": True,
            "max_tool_calls_per_stage": settings.MAPEK_MAX_TOOL_CALLS_PER_STAGE,
        },
        retention={
            "messages_days": settings.RETENTION_MESSAGES_DAYS,
            "tool_payload_days": settings.RETENTION_TOOL_PAYLOAD_DAYS,
            "checkpoint_days": settings.RETENTION_CHECKPOINT_DAYS,
            "investigation_days": settings.RETENTION_INVESTIGATION_DAYS,
            "reports": "indefinite",
            "approvals": "indefinite",
            "actions": "indefinite",
        },
        wazuh_dashboard_url=settings.WAZUH_DASHBOARD_URL.strip() or None,
    )
    return {"data": _public_data(platform.model_dump(mode="json"))}


def _sse(event: str, payload: dict[str, Any]) -> str:
    public_payload = _public_data(payload)
    return (
        f"event: {event}\n"
        f"data: {json.dumps(public_payload, default=str)}\n\n"
    )


def _assistant_stream_error(_error: Exception) -> dict[str, str]:
    """Stable public SSE error; exception details stay in server logs."""

    return {
        "code": "SOC_ASSISTANT_UNAVAILABLE",
        "message": (
            "The SOC assistant could not complete the request. "
            "Retry or use /health to check live data services."
        ),
    }


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
            logger.exception(
                "soc_assistant_stream_failed",
                error_type=type(exc).__name__,
            )
            yield _sse(
                "error",
                _assistant_stream_error(exc),
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
