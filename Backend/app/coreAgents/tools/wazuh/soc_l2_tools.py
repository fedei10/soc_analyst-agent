"""Bounded deterministic investigation and hunting tools for SOC L2."""

from datetime import datetime
from typing import Any

from langchain_core.tools import StructuredTool

from app.coreAgents.tools.wazuh._common import run
from app.coreAgents.tools.wazuh.schemas import (
    ArchivedLogSearchInput,
    AuthenticationTimelineInput,
    EndpointForensicsInput,
    RelatedAlertsInput,
    SuccessfulLoginInput,
)
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.models import AlertSearchResult
from app.services.wazuh.normalization.serializers import (
    compact_alert_search_result,
)


FORENSIC_FIELDS = {
    "processes": (
        "pid",
        "ppid",
        "name",
        "cmd",
        "argvs",
        "state",
        "user_name",
        "euser",
        "start_time",
    ),
    "ports": (
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "protocol",
        "state",
        "process",
        "pid",
    ),
    "network": (
        "name",
        "type",
        "state",
        "mac",
        "address",
        "netmask",
        "broadcast",
        "gateway",
        "dhcp",
    ),
    "fim_findings": (
        "file",
        "path",
        "name",
        "event",
        "date",
        "mtime",
        "sha256",
        "md5",
        "size",
        "perm",
        "uname",
    ),
    "sca_findings": (
        "policy_id",
        "name",
        "description",
        "result",
        "status",
        "check",
        "title",
        "remediation",
    ),
    "rootcheck_findings": (
        "status",
        "event",
        "oldDay",
        "readDay",
    ),
    "vulnerabilities": (
        "id",
        "cve",
        "title",
        "severity",
        "package",
        "name",
        "version",
        "published",
        "condition",
    ),
}


def _compact_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return value[:240]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_compact_scalar(item) for item in value[:5]]
    if isinstance(value, dict):
        return {
            str(key): _compact_scalar(item)
            for key, item in list(value.items())[:8]
        }
    return str(value)[:240]


def _project_records(
    records: list[dict[str, Any]],
    category: str,
) -> list[dict[str, Any]]:
    fields = FORENSIC_FIELDS[category]
    projected = []
    for record in records[:3]:
        item = {
            field: _compact_scalar(record[field])
            for field in fields
            if record.get(field) is not None
        }
        if not item:
            item = {
                str(key): _compact_scalar(value)
                for key, value in list(record.items())[:6]
            }
        projected.append(item)
    return projected


def _compact_forensics(data: dict[str, Any]) -> dict[str, Any]:
    inventories = {}
    for component, inventory in data.get("inventories", {}).items():
        if component not in {"processes", "ports", "network"}:
            continue
        inventories[component] = {
            "total": inventory.get("total", 0),
            "returned": inventory.get("returned", 0),
            "truncated": inventory.get("truncated", False),
            "sample": _project_records(
                inventory.get("items", []),
                component,
            ),
        }

    detection = data.get("detection_evidence") or {}
    return {
        "agent_id": data.get("agent_id"),
        "agent": data.get("agent"),
        "inventories": inventories,
        "detection_evidence": {
            "fim_total": detection.get("fim_total", 0),
            "sca_total": detection.get("sca_total", 0),
            "rootcheck_total": detection.get("rootcheck_total", 0),
            "truncated": detection.get("truncated", False),
            "fim_sample": _project_records(
                detection.get("fim_findings", []),
                "fim_findings",
            ),
            "sca_sample": _project_records(
                detection.get("sca_findings", []),
                "sca_findings",
            ),
            "rootcheck_sample": _project_records(
                detection.get("rootcheck_findings", []),
                "rootcheck_findings",
            ),
        },
        "vulnerability_total": data.get("vulnerability_total", 0),
        "vulnerability_sample": _project_records(
            data.get("vulnerabilities", []),
            "vulnerabilities",
        ),
        "truncated": data.get("truncated", False),
        "source_errors": data.get("source_errors", []),
        "telemetry_limitations": data.get("telemetry_limitations", []),
    }


def build_l2_tools(gateway: WazuhGateway | None = None) -> list[StructuredTool]:
    def current_gateway() -> WazuhGateway:
        return gateway or get_wazuh_gateway()

    def get_related_alerts(alert_id: str, hours: int = 24, limit: int = 25) -> dict:
        return run(lambda: compact_alert_search_result(
            current_gateway().get_related_alerts(
                alert_id=alert_id, hours=hours, limit=limit
            )
        ))

    def build_authentication_timeline(
        source_ip=None,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 25,
        center_time: datetime | None = None,
        window_minutes: int = 30,
    ) -> dict:
        def fetch() -> dict:
            timeline = current_gateway().build_authentication_timeline(
                source_ip=str(source_ip) if source_ip else None,
                target_user=target_user,
                agent_id=agent_id,
                hours=hours,
                limit=limit,
                center_time=center_time,
                window_minutes=window_minutes,
            )
            return compact_alert_search_result(AlertSearchResult(
                total=timeline.total,
                returned=timeline.returned,
                truncated=timeline.truncated,
                alerts=timeline.events,
            ))

        return run(fetch)

    def check_successful_login_after_failures(
        source_ip=None,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 50,
        center_time: datetime | None = None,
        window_minutes: int = 30,
    ) -> dict:
        return run(lambda: current_gateway().check_successful_login_after_failures(
            source_ip=str(source_ip) if source_ip else None,
            target_user=target_user,
            agent_id=agent_id,
            hours=hours,
            limit=limit,
            center_time=center_time,
            window_minutes=window_minutes,
        ).model_dump(mode="json"))

    def hunt_archived_security_logs(
        text: str,
        hours: int = 24,
        limit: int = 50,
        agent_id: str | None = None,
    ) -> dict:
        def fetch() -> dict:
            result = current_gateway().search_archived_logs(
                text=text,
                hours=hours,
                limit=limit,
                agent_id=agent_id,
            )
            return {
                "archive_status": result.archive_status,
                "query_scope": result.query_scope,
                **compact_alert_search_result(AlertSearchResult(
                    total=result.total,
                    returned=result.returned,
                    truncated=result.truncated,
                    alerts=[item.normalized for item in result.events],
                )),
            }

        return run(fetch)

    def get_endpoint_forensics(
        agent_id: str,
        limit: int = 10,
    ) -> dict:
        def fetch() -> dict:
            result = current_gateway().get_endpoint_forensics(
                agent_id=agent_id,
                limit=limit,
            )
            return _compact_forensics(result.model_dump(mode="json"))

        return run(fetch)

    return [
        StructuredTool.from_function(
            func=get_related_alerts,
            name="get_related_alerts",
            description=(
                "Read-only investigation around an exact alert ID. Uses bounded source, agent, "
                "or rule context internally; it does not accept OpenSearch queries. The result "
                "states whether evidence was truncated."
            ),
            args_schema=RelatedAlertsInput,
        ),
        StructuredTool.from_function(
            func=build_authentication_timeline,
            name="build_authentication_timeline",
            description=(
                "Read-only chronological authentication evidence for a validated source IP "
                "or Wazuh agent, optionally narrowed by user and exact time window. Use for "
                "login investigations; do not use for unrelated alert types."
            ),
            args_schema=AuthenticationTimelineInput,
        ),
        StructuredTool.from_function(
            func=check_successful_login_after_failures,
            name="check_successful_login_after_failures",
            description=(
                "Required read-only check before claiming whether access followed "
                "authentication failures. Search broadly by source IP and agent; omit "
                "target_user when checking whether the same source succeeded as another "
                "account. Returns explicit query scope, completion, evidence IDs, and "
                "truncation state. A negative result means no success in returned alerts, "
                "not proof that access never occurred."
            ),
            args_schema=SuccessfulLoginInput,
        ),
        StructuredTool.from_function(
            func=hunt_archived_security_logs,
            name="hunt_archived_security_logs",
            description=(
                "Read-only bounded hunt across Wazuh archived security logs "
                "for one indicator or behavior string, optionally scoped to "
                "an agent. It accepts no OpenSearch DSL and reports archive "
                "availability and truncation explicitly."
            ),
            args_schema=ArchivedLogSearchInput,
        ),
        StructuredTool.from_function(
            func=get_endpoint_forensics,
            name="get_endpoint_forensics",
            description=(
                "Read-only bounded L2 endpoint snapshot combining Wazuh agent "
                "status, processes, ports, network interfaces, FIM, SCA, "
                "rootcheck, and vulnerabilities. It reports unavailable "
                "sources and telemetry limitations instead of inventing data."
            ),
            args_schema=EndpointForensicsInput,
        ),
    ]
