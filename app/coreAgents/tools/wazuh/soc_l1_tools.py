"""Three bounded, read-only tools for SOC L1 triage."""

from langchain_core.tools import StructuredTool

from app.coreAgents.tools.wazuh._common import run
from app.coreAgents.tools.wazuh.schemas import (
    AgentSummaryInput,
    AlertByIdInput,
    HighSeverityAlertsInput,
)
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway


def build_l1_tools(gateway: WazuhGateway | None = None) -> list[StructuredTool]:
    def current_gateway() -> WazuhGateway:
        return gateway or get_wazuh_gateway()

    def get_high_severity_alerts(
        min_level: int = 10, hours: int = 24, limit: int = 50
    ) -> dict:
        return run(lambda: current_gateway().get_high_severity_alerts(
            min_level=min_level, hours=hours, limit=limit
        ).model_dump(mode="json"))

    def get_alert_by_id(alert_id: str) -> dict:
        def fetch() -> dict:
            alert = current_gateway().get_alert_by_id(alert_id)
            return {
                "found": alert is not None,
                "alert": alert.model_dump(mode="json") if alert else None,
            }

        return run(fetch)

    def get_agent_summary(agent_id: str) -> dict:
        def fetch() -> dict:
            agent = current_gateway().get_agent_summary(agent_id)
            return {
                "found": agent is not None,
                "agent": agent.model_dump(mode="json") if agent else None,
            }

        return run(fetch)

    return [
        StructuredTool.from_function(
            func=get_high_severity_alerts,
            name="get_high_severity_alerts",
            description=(
                "Read-only initial triage. Retrieve normalized alerts at or above a bounded "
                "severity for up to seven days. Do not use for a known alert ID. The result "
                "states whether matching evidence was truncated."
            ),
            args_schema=HighSeverityAlertsInput,
        ),
        StructuredTool.from_function(
            func=get_alert_by_id,
            name="get_alert_by_id",
            description=(
                "Read-only lookup for one exact Wazuh indexer alert ID already present in "
                "evidence. Do not guess IDs or use this for broad searches."
            ),
            args_schema=AlertByIdInput,
        ),
        StructuredTool.from_function(
            func=get_agent_summary,
            name="get_agent_summary",
            description=(
                "Read-only endpoint context for one numeric Wazuh agent ID found in alert "
                "evidence. Returns status, host, version, and OS summary."
            ),
            args_schema=AgentSummaryInput,
        ),
    ]
