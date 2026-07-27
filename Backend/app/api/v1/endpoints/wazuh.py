"""
Wazuh REST surface for the SOC agents.

Scopes (enforced in app/api/auth/deps.py):
  - every read endpoint requires wazuh:read  (SOC L1/L2 agent tokens)
  - response actions require wazuh:write     (human-held tokens, SOC L3)

Which subset of read endpoints a caller may use is decided by token scopes,
not here.

Response envelope: {"data": ...}. Collections pass Wazuh's own shape through
({"affected_items": [...], "total_affected_items": N}); indexer-backed routes
mirror the same shape. Single resources return the object directly.
"""
from enum import Enum
from typing import Annotated, Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from app.api.auth.deps import AuthPrincipal, require_read, require_write
from app.api.v1.schemas.wazuh import ActiveResponseRequest, RestartAgentRequest
from app.services.wazuh.dependencies import get_wazuh_gateway, get_wazuh_responder
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.ingestion import (
    AlertIngestionService,
    IngestionAlreadyRunningError,
)
from app.services.wazuh.responder_client import WazuhResponderClient

logger = structlog.get_logger("tsage.api")

read = APIRouter(dependencies=[Depends(require_read)])
write = APIRouter(dependencies=[Depends(require_write)], tags=["response"])

# Path params are validated to a safe charset so they can never traverse into
# a different Wazuh API path.
AgentId = Annotated[str, Path(pattern=r"^\d+$", description="Zero-padded Wazuh agent id, e.g. 001")]
SafeName = Annotated[str, Path(pattern=r"^[\w.-]+$", max_length=128)]

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]
Hours = Annotated[int, Query(ge=1, le=168, description="Look-back window")]
Text = Annotated[str | None, Query(max_length=200, description="Free-text search")]
GatewayDep = Annotated[WazuhGateway, Depends(get_wazuh_gateway)]
ResponderDep = Annotated[WazuhResponderClient, Depends(get_wazuh_responder)]


async def require_direct_response_mode() -> None:
    raise HTTPException(
        409,
        "Direct Wazuh response actions are retired. Use the formal "
        "investigation approval and execution workflow.",
    )


def _wz(gateway: WazuhGateway, path: str, **params: Any) -> dict[str, Any]:
    """GET a Wazuh server API path and unwrap its data object."""
    clean = {k: v for k, v in params.items() if v is not None}
    return {"data": gateway.server_get(path, params=clean or None).get("data", {})}


def _items(items: list[dict[str, Any]], total: int) -> dict[str, Any]:
    return {"data": {"affected_items": items, "total_affected_items": total}}


# -------------------------
# Alerts (indexer) — L1 triage, L2 investigation
# -------------------------

@read.get("/alerts", tags=["alerts"])
def list_alerts(
    gateway: GatewayDep,
    min_level: Annotated[int, Query(ge=0, le=16)] = 0,
    hours: Hours = 24,
    limit: Limit = 20,
    agent_id: Annotated[str | None, Query(pattern=r"^\d+$")] = None,
    rule_id: Annotated[str | None, Query(pattern=r"^\d+$")] = None,
    q: Text = None,
):
    """Recent alerts, newest first. Filter by level, agent, rule, or free text."""
    result = gateway.search_alerts(
        min_level=min_level, hours=hours, limit=limit,
        agent_id=agent_id, rule_id=rule_id, text=q,
    )
    return _items([item.model_dump(mode="json") for item in result.alerts], result.total)


@read.get("/alerts/summary", tags=["alerts"])
def alert_summary(gateway: GatewayDep, hours: Hours = 24):
    """Alert counts by level / agent / rule group — the L1 triage overview."""
    return {"data": gateway.alert_summary(hours=hours)}


@read.post("/alerts/check", tags=["alerts"])
def check_new_alerts(gateway: GatewayDep):
    """Run one durable Monitor cycle and return deterministic new-alert counts."""

    try:
        result = AlertIngestionService(gateway=gateway).ingest()
    except IngestionAlreadyRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"data": result.model_dump(mode="json")}


@read.get("/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: SafeName, gateway: GatewayDep):
    """Full alert document by indexer id (L2 investigation)."""
    alert = gateway.get_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(404, f"Alert {alert_id} not found.")
    return {"data": alert.model_dump(mode="json")}


# -------------------------
# Agents — L1 status, L2 endpoint evidence
# -------------------------

@read.get("/agents", tags=["agents"])
def list_agents(
    gateway: GatewayDep,
    status: Annotated[
        Literal["active", "pending", "never_connected", "disconnected"] | None, Query()
    ] = None,
    limit: Limit = 20,
    offset: Offset = 0,
    q: Text = None,
):
    """Registered agents with connection status."""
    return _wz(
        gateway,
        "/agents",
        select="id,name,ip,status,version,os.name,lastKeepAlive",
        status=status, limit=limit, offset=offset, search=q,
    )


@read.get("/agents/summary", tags=["agents"])
def agents_summary(gateway: GatewayDep):
    """Agent counts by connection status and by OS."""
    return {"data": {
        "status": gateway.server_get("/agents/summary/status").get("data", {}),
        "os": gateway.server_get("/agents/summary/os").get("data", {}),
    }}


@read.get("/agents/outdated", tags=["agents"])
def outdated_agents(gateway: GatewayDep, limit: Limit = 20, offset: Offset = 0):
    """Agents running an older version than the manager."""
    return _wz(gateway, "/agents/outdated", limit=limit, offset=offset)


@read.get("/agents/{agent_id}", tags=["agents"])
def get_agent(agent_id: AgentId, gateway: GatewayDep):
    data = gateway.server_get("/agents", params={"agents_list": agent_id}).get("data", {})
    if not data.get("affected_items"):
        raise HTTPException(404, f"Agent {agent_id} not found.")
    return {"data": data["affected_items"][0]}


class InventoryComponent(str, Enum):
    processes = "processes"
    ports = "ports"
    packages = "packages"
    os = "os"
    network = "network"
    hotfixes = "hotfixes"


@read.get("/agents/{agent_id}/inventory/{component}", tags=["agents"])
def agent_inventory(
    agent_id: AgentId,
    component: InventoryComponent,
    gateway: GatewayDep,
    limit: Limit = 20,
    offset: Offset = 0,
    q: Text = None,
):
    """Syscollector inventory: processes, ports, packages, os, network, hotfixes (L2)."""
    syscollector = {"network": "netiface"}.get(component.value, component.value)
    return _wz(gateway, f"/syscollector/{agent_id}/{syscollector}", limit=limit, offset=offset, search=q)


@read.get("/agents/{agent_id}/stats", tags=["agents"])
def agent_stats(agent_id: AgentId, gateway: GatewayDep):
    """Agent daemon statistics."""
    return _wz(gateway, f"/agents/{agent_id}/daemons/stats")


@read.get("/agents/{agent_id}/config/{component}/{configuration}", tags=["agents"])
def agent_config(
    agent_id: AgentId,
    component: Annotated[str, Path(pattern=r"^[a-z_-]+$", max_length=64)],
    configuration: Annotated[str, Path(pattern=r"^[a-z_-]+$", max_length=64)],
    gateway: GatewayDep,
):
    """Active configuration of one agent component (e.g. agent/client, logcollector/localfile)."""
    return _wz(gateway, f"/agents/{agent_id}/config/{component}/{configuration}")


@read.get("/agents/{agent_id}/fim", tags=["agents"])
def agent_fim(
    agent_id: AgentId, gateway: GatewayDep,
    limit: Limit = 20, offset: Offset = 0, q: Text = None,
):
    """File integrity monitoring findings for the agent (L2)."""
    return _wz(gateway, f"/syscheck/{agent_id}", limit=limit, offset=offset, search=q)


@read.get("/agents/{agent_id}/rootcheck", tags=["agents"])
def agent_rootcheck(agent_id: AgentId, gateway: GatewayDep, limit: Limit = 20, offset: Offset = 0):
    """Rootcheck (rootkit/policy) findings for the agent (L2)."""
    return _wz(gateway, f"/rootcheck/{agent_id}", limit=limit, offset=offset)


@read.get("/agents/{agent_id}/sca", tags=["agents"])
def agent_sca_policies(agent_id: AgentId, gateway: GatewayDep, limit: Limit = 20, offset: Offset = 0):
    """Security Configuration Assessment policies and scores (L2)."""
    return _wz(gateway, f"/sca/{agent_id}", limit=limit, offset=offset)


@read.get("/agents/{agent_id}/sca/{policy_id}/checks", tags=["agents"])
def agent_sca_checks(
    agent_id: AgentId,
    policy_id: SafeName,
    gateway: GatewayDep,
    result: Annotated[Literal["passed", "failed", "not_applicable"] | None, Query()] = None,
    limit: Limit = 20,
    offset: Offset = 0,
):
    """Individual SCA checks for one policy; filter result=failed for gaps."""
    return _wz(gateway, f"/sca/{agent_id}/checks/{policy_id}", result=result, limit=limit, offset=offset)


# -------------------------
# Groups
# -------------------------

@read.get("/groups", tags=["groups"])
def list_groups(gateway: GatewayDep, limit: Limit = 20, offset: Offset = 0):
    return _wz(gateway, "/groups", limit=limit, offset=offset)


@read.get("/groups/{group_id}/agents", tags=["groups"])
def group_agents(group_id: SafeName, gateway: GatewayDep, limit: Limit = 20, offset: Offset = 0):
    return _wz(gateway, f"/groups/{group_id}/agents", limit=limit, offset=offset)


@read.get("/groups/{group_id}/config", tags=["groups"])
def group_config(group_id: SafeName, gateway: GatewayDep):
    return _wz(gateway, f"/groups/{group_id}/configuration")


@read.get("/groups/{group_id}/files", tags=["groups"])
def group_files(group_id: SafeName, gateway: GatewayDep, limit: Limit = 20, offset: Offset = 0):
    return _wz(gateway, f"/groups/{group_id}/files", limit=limit, offset=offset)


@read.get("/groups/{group_id}/files/{filename}", tags=["groups"])
def group_file_content(group_id: SafeName, filename: SafeName, gateway: GatewayDep):
    """Raw content of one group configuration file (L2)."""
    content = gateway.server_get_raw(f"/groups/{group_id}/files/{filename}", params={"raw": "true"})
    return {"data": {"filename": filename, "content": content}}


# -------------------------
# Cluster & manager — L1 health, L2 log investigation, L3 config review
# -------------------------

@read.get("/cluster/status", tags=["cluster"])
def cluster_status(gateway: GatewayDep):
    return _wz(gateway, "/cluster/status")


@read.get("/cluster/nodes", tags=["cluster"])
def cluster_nodes(gateway: GatewayDep, limit: Limit = 20, offset: Offset = 0):
    return _wz(gateway, "/cluster/nodes", limit=limit, offset=offset)


@read.get("/cluster/healthcheck", tags=["cluster"])
def cluster_healthcheck(gateway: GatewayDep):
    return _wz(gateway, "/cluster/healthcheck")


@read.get("/manager/info", tags=["manager"])
def manager_info(gateway: GatewayDep):
    """Wazuh API/manager version info (wazuh_get_api_info)."""
    return _wz(gateway, "/")


@read.get("/manager/configuration", tags=["manager"])
def manager_configuration(
    gateway: GatewayDep,
    section: Annotated[str | None, Query(pattern=r"^[a-z_-]+$", max_length=64)] = None,
    field: Annotated[str | None, Query(pattern=r"^[a-z_-]+$", max_length=64)] = None,
):
    """Manager ossec.conf (L3 detection engineering)."""
    return _wz(gateway, "/manager/configuration", section=section, field=field)


@read.get("/manager/logs", tags=["manager"])
def manager_logs(
    gateway: GatewayDep,
    level: Annotated[Literal["critical", "error", "warning", "info", "debug"] | None, Query()] = None,
    q: Text = None,
    limit: Limit = 20,
    offset: Offset = 0,
):
    """Manager log entries; level=error gives the error-log view (L2)."""
    return _wz(gateway, "/manager/logs", level=level, search=q, limit=limit, offset=offset)


@read.get("/manager/logs/summary", tags=["manager"])
def manager_logs_summary(gateway: GatewayDep):
    return _wz(gateway, "/manager/logs/summary")


# -------------------------
# MITRE ATT&CK reference — L1 basic lookup, L2 mapping
# -------------------------

class MitreCategory(str, Enum):
    techniques = "techniques"
    tactics = "tactics"
    groups = "groups"
    software = "software"
    mitigations = "mitigations"
    references = "references"


@read.get("/mitre/{category}", tags=["mitre"])
def mitre(
    category: MitreCategory, gateway: GatewayDep,
    q: Text = None, limit: Limit = 20, offset: Offset = 0,
):
    """MITRE ATT&CK data as shipped with Wazuh."""
    return _wz(gateway, f"/mitre/{category.value}", search=q, limit=limit, offset=offset)


# -------------------------
# Rules & decoders — L3 detection engineering (read-only)
# -------------------------

@read.get("/rules", tags=["rules"])
def list_rules(
    gateway: GatewayDep,
    q: Text = None,
    level: Annotated[str | None, Query(pattern=r"^\d+(-\d+)?$", description="Level or range, e.g. 12 or 10-16")] = None,
    group: Annotated[str | None, Query(pattern=r"^[\w.-]+$", max_length=64)] = None,
    limit: Limit = 20,
    offset: Offset = 0,
):
    return _wz(gateway, "/rules", search=q, level=level, group=group, limit=limit, offset=offset)


@read.get("/rules/files", tags=["rules"])
def rule_files(gateway: GatewayDep, q: Text = None, limit: Limit = 20, offset: Offset = 0):
    return _wz(gateway, "/rules/files", search=q, limit=limit, offset=offset)


@read.get("/rules/files/{filename}", tags=["rules"])
def rule_file_content(filename: SafeName, gateway: GatewayDep):
    return _wz(gateway, f"/rules/files/{filename}")


@read.get("/rules/{rule_id}", tags=["rules"])
def get_rule(rule_id: Annotated[int, Path(ge=0)], gateway: GatewayDep):
    data = gateway.server_get("/rules", params={"rule_ids": str(rule_id), "limit": 1}).get("data", {})
    if not data.get("affected_items"):
        raise HTTPException(404, f"Rule {rule_id} not found.")
    return {"data": data["affected_items"][0]}


@read.get("/decoders", tags=["rules"])
def list_decoders(gateway: GatewayDep, q: Text = None, limit: Limit = 20, offset: Offset = 0):
    return _wz(gateway, "/decoders", search=q, limit=limit, offset=offset)


# -------------------------
# Tasks & vulnerabilities
# -------------------------

@read.get("/tasks", tags=["tasks"])
def tasks_status(gateway: GatewayDep, limit: Limit = 20, offset: Offset = 0):
    return _wz(gateway, "/tasks/status", limit=limit, offset=offset)


Severity = Literal["Low", "Medium", "High", "Critical"]


@read.get("/vulnerabilities", tags=["vulnerabilities"])
def list_vulnerabilities(
    gateway: GatewayDep,
    severity: Annotated[Severity | None, Query()] = None,
    agent_id: Annotated[str | None, Query(pattern=r"^\d+$")] = None,
    limit: Limit = 20,
):
    """Vulnerability state (indexer, Wazuh 4.8+). severity=Critical for L1 triage."""
    items, total = gateway.search_vulnerabilities(severity=severity, agent_id=agent_id, limit=limit)
    return _items(items, total)


@read.get("/vulnerabilities/summary", tags=["vulnerabilities"])
def vulnerabilities_summary(gateway: GatewayDep):
    return {"data": gateway.vulnerability_summary()}


@read.get("/vulnerabilities/prioritized", tags=["vulnerabilities"])
def prioritized_vulnerabilities(
    gateway: GatewayDep,
    severity: Annotated[Severity | None, Query()] = None,
    agent_id: Annotated[str | None, Query(pattern=r"^\d+$")] = None,
    limit: Limit = 50,
):
    """CVEs re-ranked by real exploitability (CISA KEV + EPSS), not CVSS alone."""
    from app.services.wazuh.triage.vuln_priority import (
        rank_detected_vulnerabilities,
    )

    items, total = gateway.search_vulnerabilities(
        severity=severity, agent_id=agent_id, limit=limit
    )
    ranked = rank_detected_vulnerabilities(items)
    return {"data": {"items": ranked, "count": len(ranked), "total": total}}


# -------------------------
# Retired direct response routes retained only for a stable rejection contract.
# -------------------------

@write.post(
    "/agents/{agent_id}/active-response",
    status_code=202,
    dependencies=[Depends(require_direct_response_mode)],
)
def run_active_response(
    body: ActiveResponseRequest,
    agent_id: AgentId,
    request: Request,
    responder: ResponderDep,
):
    """
    Compatibility route that always rejects workflow-bypassing execution.

    Normal operation must use the formal investigation approval workflow.
    """
    principal: AuthPrincipal = request.state.principal
    logger.info(
        "response_action_executed",
        action_type="wazuh_active_response",
        command_name=body.command,
        agent_id=agent_id,
        actor_user_id=principal.user_id,
    )
    responder.run_active_response(
        agent_id=agent_id,
        command=body.command,
        arguments=body.arguments,
        alert=body.alert,
    )
    return {"data": {
        "agent_id": agent_id,
        "command": body.command,
        "status": "queued",
        "approved_by": principal.user_id,
    }}


@write.put(
    "/agents/{agent_id}/restart",
    status_code=202,
    dependencies=[Depends(require_direct_response_mode)],
)
def restart_agent(
    body: RestartAgentRequest,
    agent_id: AgentId,
    request: Request,
    responder: ResponderDep,
):
    """Compatibility route that always rejects workflow-bypassing execution."""
    principal: AuthPrincipal = request.state.principal
    logger.info(
        "response_action_executed",
        action_type="wazuh_agent_restart",
        agent_id=agent_id,
        actor_user_id=principal.user_id,
    )
    responder.restart_agent(agent_id)
    return {
        "data": {
            "agent_id": agent_id,
            "status": "restart_queued",
            "approved_by": principal.user_id,
        }
    }
