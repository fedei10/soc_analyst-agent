"""Security and service-health verification after restricted execution."""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.mape_k.schemas import IncidentWorkflowState, VerificationResult
from app.services.wazuh.gateway import WazuhGateway


class ResponseVerifier:
    def __init__(
        self,
        gateway: WazuhGateway | None = None,
        *,
        settings_obj: Any = settings,
    ) -> None:
        self.gateway = gateway or WazuhGateway()
        self.settings = settings_obj

    def run(self, state: IncidentWorkflowState) -> VerificationResult:
        failed_execution = any(
            result.status in {"failed", "timed_out"}
            for result in state.execution_results
        )
        if failed_execution:
            return VerificationResult(
                security_checks_passed=False,
                health_checks_passed=False,
                checks=[{"check": "execution_result", "passed": False}],
                dry_run=self.settings.MAPEK_DRY_RUN,
            )
        if self.settings.MAPEK_DRY_RUN or not self.settings.MAPEK_REAL_EXECUTION_ENABLED:
            return VerificationResult(
                security_checks_passed=True,
                health_checks_passed=True,
                checks=[
                    {
                        "check": "ssh_attempts_stopped",
                        "passed": True,
                        "simulated": True,
                    },
                    {
                        "check": "wazuh_agent_connected",
                        "passed": True,
                        "simulated": True,
                    },
                    {
                        "check": "legitimate_ssh_reachable",
                        "passed": True,
                        "simulated": True,
                    },
                ],
                dry_run=True,
            )

        checks: list[dict[str, Any]] = []
        related = self.gateway.get_related_alerts(
            alert_id=state.alert_id,
            hours=1,
            limit=25,
        )
        source_ip = (
            state.diagnosis.affected_entities.get("source_ip")
            if state.diagnosis
            else None
        )
        new_failures = [
            item
            for item in related.alerts
            if item.source_ip == source_ip and item.event_outcome == "failure"
        ]
        checks.append(
            {
                "check": "ssh_attempts_stopped",
                "passed": not new_failures,
                "observed_failures": len(new_failures),
            }
        )
        agent = (
            self.gateway.get_agent_summary(str(state.agent_id))
            if state.agent_id
            else None
        )
        agent_connected = bool(agent and str(agent.status).lower() == "active")
        checks.append(
            {"check": "wazuh_agent_connected", "passed": agent_connected}
        )
        ports = (
            self.gateway.get_agent_inventory(
                agent_id=str(state.agent_id),
                component="ports",
                limit=50,
            )
            if state.agent_id
            else None
        )
        ssh_reachable = bool(
            ports
            and any(
                int(item.get("local_port", item.get("port", 0))) == 22
                for item in ports.items
            )
        )
        checks.append(
            {"check": "legitimate_ssh_reachable", "passed": ssh_reachable}
        )
        return VerificationResult(
            security_checks_passed=not new_failures,
            health_checks_passed=agent_connected and ssh_reachable,
            checks=checks,
        )

