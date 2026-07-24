"""Three additional deterministic investigation tools for SOC L2."""

from datetime import datetime

from langchain_core.tools import StructuredTool

from app.coreAgents.tools.wazuh._common import run
from app.coreAgents.tools.wazuh.schemas import (
    AuthenticationTimelineInput,
    RelatedAlertsInput,
    SuccessfulLoginInput,
)
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway


def build_l2_tools(gateway: WazuhGateway | None = None) -> list[StructuredTool]:
    def current_gateway() -> WazuhGateway:
        return gateway or get_wazuh_gateway()

    def get_related_alerts(alert_id: str, hours: int = 24, limit: int = 100) -> dict:
        return run(lambda: current_gateway().get_related_alerts(
            alert_id=alert_id, hours=hours, limit=limit
        ).model_dump(mode="json"))

    def build_authentication_timeline(
        source_ip=None,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 100,
        center_time: datetime | None = None,
        window_minutes: int = 30,
    ) -> dict:
        return run(lambda: current_gateway().build_authentication_timeline(
            source_ip=str(source_ip) if source_ip else None,
            target_user=target_user,
            agent_id=agent_id,
            hours=hours,
            limit=limit,
            center_time=center_time,
            window_minutes=window_minutes,
        ).model_dump(mode="json"))

    def check_successful_login_after_failures(
        source_ip=None,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 200,
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
    ]
