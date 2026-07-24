"""Deeper read-only detection and threat-hunting tools for SOC L3."""

from langchain_core.tools import StructuredTool

from app.coreAgents.tools.wazuh._common import run
from app.coreAgents.tools.wazuh.schemas import (
    DetectionEvidenceInput,
    IOCHuntInput,
    RuleMitreContextInput,
)
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway


def build_l3_tools(gateway: WazuhGateway | None = None) -> list[StructuredTool]:
    def current_gateway() -> WazuhGateway:
        return gateway or get_wazuh_gateway()

    def get_rule_and_mitre_context(rule_id: str) -> dict:
        def fetch() -> dict:
            context = current_gateway().get_rule_and_mitre_context(rule_id)
            return {
                "found": context is not None,
                "context": context.model_dump(mode="json") if context else None,
            }

        return run(fetch)

    def get_detection_evidence(agent_id: str, limit: int = 100) -> dict:
        return run(lambda: current_gateway().get_detection_evidence(
            agent_id=agent_id, limit=limit
        ).model_dump(mode="json"))

    def hunt_ioc_across_telemetry(
        indicator: str,
        indicator_type: str,
        hours: int = 24,
        limit: int = 10,
        agent_id: str | None = None,
    ) -> dict:
        def fetch() -> dict:
            result = current_gateway().hunt_ioc_telemetry(
                indicator=indicator,
                indicator_type=indicator_type,
                hours=hours,
                limit=limit,
                agent_id=agent_id,
            )
            alerts = result.alerts
            archives = result.archived_logs
            alert_sample = (
                [
                    {
                        "evidence_ref": f"alert:{item.alert_id}",
                        "timestamp": item.timestamp.isoformat(),
                        "agent_id": item.agent_id,
                        "rule_id": item.rule_id,
                        "rule_level": item.rule_level,
                        "description": item.description[:300],
                        "source_ip": item.source_ip,
                        "target_user": item.target_user,
                        "mitre_ids": item.mitre_ids,
                        "event_outcome": item.event_outcome,
                    }
                    for item in alerts.alerts[:5]
                ]
                if alerts is not None
                else []
            )
            archive_sample = (
                [
                    {
                        "evidence_ref": f"archive:{item.alert_id}",
                        "timestamp": item.normalized.timestamp.isoformat(),
                        "agent_id": item.normalized.agent_id,
                        "description": item.normalized.description[:300],
                        "source_ip": item.normalized.source_ip,
                        "target_user": item.normalized.target_user,
                        "event_outcome": item.normalized.event_outcome,
                    }
                    for item in archives.events[:5]
                ]
                if archives is not None
                else []
            )
            return {
                "indicator": result.indicator,
                "indicator_type": result.indicator_type,
                "alerts": {
                    "total": alerts.total if alerts is not None else None,
                    "returned": alerts.returned if alerts is not None else None,
                    "truncated": (
                        alerts.truncated if alerts is not None else None
                    ),
                    "sample": alert_sample,
                },
                "archives": {
                    "status": (
                        archives.archive_status
                        if archives is not None
                        else "unknown"
                    ),
                    "total": archives.total if archives is not None else None,
                    "returned": (
                        archives.returned if archives is not None else None
                    ),
                    "truncated": (
                        archives.truncated if archives is not None else None
                    ),
                    "sample": archive_sample,
                },
                "source_errors": result.source_errors,
                "intelligence_scope": result.intelligence_scope,
                "external_intelligence_status": (
                    result.external_intelligence_status
                ),
                "limitations": [
                    (
                        "No external threat-intelligence reputation or "
                        "malware feed is configured."
                    ),
                    "No result is not proof that the indicator is benign.",
                ],
            }

        return run(fetch)

    return [
        StructuredTool.from_function(
            func=get_rule_and_mitre_context,
            name="get_rule_and_mitre_context",
            description=(
                "Read-only Wazuh rule and MITRE context for one numeric rule ID already seen "
                "in evidence. Use to validate, not force, an ATT&CK mapping."
            ),
            args_schema=RuleMitreContextInput,
        ),
        StructuredTool.from_function(
            func=get_detection_evidence,
            name="get_detection_evidence",
            description=(
                "Read-only bounded FIM, SCA, and rootcheck evidence for one numeric agent "
                "ID. Use when validating endpoint findings or detection gaps; results may "
                "be truncated."
            ),
            args_schema=DetectionEvidenceInput,
        ),
        StructuredTool.from_function(
            func=hunt_ioc_across_telemetry,
            name="hunt_ioc_across_telemetry",
            description=(
                "Read-only bounded hunt for one validated IOC across local "
                "Wazuh alerts and archives. Returns evidence references, "
                "coverage, truncation, and an explicit external-intelligence "
                "status; it does not accept query DSL."
            ),
            args_schema=IOCHuntInput,
        ),
    ]
