"""Registered security and service-health verification after execution."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import settings
from app.mape_k.registries import (
    VerificationCheckRegistration,
    VERIFICATION_CHECK_REGISTRY,
)
from app.mape_k.schemas import (
    IncidentWorkflowState,
    VerificationOutcome,
    VerificationResult,
)
from app.services.wazuh.gateway import WazuhGateway


_SUCCESSFUL_EXECUTION_STATUSES = {"accepted", "applied", "executed", "no_op"}
_FAILED_EXECUTION_STATUSES = {
    "failed",
    "failed_retryable",
    "failed_terminal",
    "timed_out",
    "cancelled",
}
_CHECK_PASSED = "passed"
_CHECK_FAILED = "failed"
_CHECK_NOT_VERIFIED = "not_verified"


def verification_observation_ready_at(
    execution_results: list[Any],
    *,
    observation_seconds: int,
) -> datetime | None:
    """Return the server-derived deadline for post-action verification."""

    completed: list[datetime] = []
    for item in execution_results:
        status = (
            item.get("status")
            if isinstance(item, dict)
            else getattr(item, "status", None)
        )
        if status not in _SUCCESSFUL_EXECUTION_STATUSES:
            continue
        completed_at = (
            item.get("completed_at")
            if isinstance(item, dict)
            else getattr(item, "completed_at", None)
        )
        if isinstance(completed_at, str):
            try:
                completed_at = datetime.fromisoformat(
                    completed_at.replace("Z", "+00:00")
                )
            except ValueError:
                continue
        if isinstance(completed_at, datetime):
            if completed_at.tzinfo is None:
                completed_at = completed_at.replace(tzinfo=UTC)
            completed.append(completed_at.astimezone(UTC))
    if not completed:
        return None
    return max(completed) + timedelta(seconds=max(observation_seconds, 0))


class ResponseVerifier:
    def __init__(
        self,
        gateway: WazuhGateway | None = None,
        *,
        settings_obj: Any = settings,
    ) -> None:
        self.gateway = gateway or WazuhGateway()
        self.settings = settings_obj
        self._related_alerts: list[Any] | None = None
        self._related_alerts_truncated = False

    @staticmethod
    def _observation_start(state: IncidentWorkflowState) -> datetime | None:
        completed = [
            result.completed_at
            for result in state.execution_results
            if result.status in _SUCCESSFUL_EXECUTION_STATUSES
        ]
        return max(completed) if completed else None

    def observation_ready_at(
        self,
        state: IncidentWorkflowState,
    ) -> datetime | None:
        return verification_observation_ready_at(
            list(state.execution_results),
            observation_seconds=int(
                self.settings.MAPEK_VERIFICATION_OBSERVATION_SECONDS
            ),
        )

    @staticmethod
    def _check_result(
        registration: VerificationCheckRegistration,
        *,
        outcome: str,
        **details: Any,
    ) -> dict[str, Any]:
        return {
            "check": registration.name,
            "category": registration.category,
            "required": registration.required,
            "outcome": outcome,
            **details,
        }

    def _load_post_execution_alerts(
        self,
        state: IncidentWorkflowState,
        observation_start: datetime,
    ) -> list[Any]:
        if self._related_alerts is None:
            search_alerts = getattr(self.gateway, "search_alerts", None)
            supports_exact_window = bool(
                callable(search_alerts)
                and "start_time" in inspect.signature(search_alerts).parameters
            )
            if supports_exact_window:
                end_time = max(
                    datetime.now(UTC),
                    observation_start + timedelta(microseconds=1),
                )
                related = search_alerts(
                    min_level=0,
                    hours=1,
                    limit=100,
                    agent_id=state.agent_id,
                    authentication_only=False,
                    oldest_first=True,
                    start_time=observation_start,
                    end_time=end_time,
                )
            else:
                related = self.gateway.get_related_alerts(
                    alert_id=state.alert_id,
                    hours=1,
                    limit=100,
                )
            self._related_alerts_truncated = bool(related.truncated)
            self._related_alerts = [
                item
                for item in related.alerts
                if item.timestamp > observation_start
            ]
        return self._related_alerts

    @staticmethod
    def _is_ssh_authentication_alert(item: Any) -> bool:
        groups = {str(group).lower() for group in getattr(item, "rule_groups", [])}
        description = str(getattr(item, "description", "") or "").lower()
        decoder = str(getattr(item, "decoder_name", "") or "").lower()
        return bool(
            "authentication_failures" in groups
            or "sshd" in decoder
            or "ssh" in description
            or "failed password" in description
        )

    def _verify_ssh_attempts_stopped(
        self,
        registration: VerificationCheckRegistration,
        state: IncidentWorkflowState,
        observation_start: datetime,
    ) -> dict[str, Any]:
        source_ip = (
            state.diagnosis.affected_entities.get("source_ip")
            if state.diagnosis
            else None
        )
        failures = [
            item
            for item in self._load_post_execution_alerts(state, observation_start)
            if item.source_ip == source_ip
            and item.event_outcome == "failure"
            and (not state.agent_id or item.agent_id == state.agent_id)
            and self._is_ssh_authentication_alert(item)
        ]
        return self._check_result(
            registration,
            outcome=(
                _CHECK_FAILED
                if failures
                else (
                    _CHECK_NOT_VERIFIED
                    if self._related_alerts_truncated
                    else _CHECK_PASSED
                )
            ),
            observation_start=observation_start.isoformat(),
            observed_failures=len(failures),
            evidence_alert_ids=[item.alert_id for item in failures[:10]],
            truncated=self._related_alerts_truncated,
        )

    def _verify_no_new_critical_alerts(
        self,
        registration: VerificationCheckRegistration,
        state: IncidentWorkflowState,
        observation_start: datetime,
    ) -> dict[str, Any]:
        critical = [
            item
            for item in self._load_post_execution_alerts(state, observation_start)
            if item.rule_level >= 12
            and (not state.agent_id or item.agent_id == state.agent_id)
        ]
        return self._check_result(
            registration,
            outcome=(
                _CHECK_FAILED
                if critical
                else (
                    _CHECK_NOT_VERIFIED
                    if self._related_alerts_truncated
                    else _CHECK_PASSED
                )
            ),
            observation_start=observation_start.isoformat(),
            observed_critical_alerts=len(critical),
            evidence_alert_ids=[item.alert_id for item in critical[:10]],
            truncated=self._related_alerts_truncated,
        )

    def _verify_no_new_auth_success_for_user(
        self,
        registration: VerificationCheckRegistration,
        state: IncidentWorkflowState,
        observation_start: datetime,
    ) -> dict[str, Any]:
        """No account disabled by this plan authenticated successfully after.

        A disable that leaves the account usable is a failed containment, so
        a single post-execution success is a hard failure rather than noise.
        """

        plan = state.remediation_plan
        targets = {
            action.target
            for action in (plan.actions if plan else [])
            if action.target
        }
        if not targets:
            return self._check_result(
                registration,
                outcome=_CHECK_NOT_VERIFIED,
                reason="no_account_target_in_plan",
            )
        successes = [
            item
            for item in self._load_post_execution_alerts(state, observation_start)
            if item.target_user in targets
            and item.event_outcome == "success"
            and (not state.agent_id or item.agent_id == state.agent_id)
        ]
        return self._check_result(
            registration,
            outcome=(
                _CHECK_FAILED
                if successes
                else (
                    _CHECK_NOT_VERIFIED
                    if self._related_alerts_truncated
                    else _CHECK_PASSED
                )
            ),
            observation_start=observation_start.isoformat(),
            accounts=sorted(targets),
            observed_successes=len(successes),
            evidence_alert_ids=[item.alert_id for item in successes[:10]],
            truncated=self._related_alerts_truncated,
        )

    def _verify_wazuh_agent_connected(
        self,
        registration: VerificationCheckRegistration,
        state: IncidentWorkflowState,
        _observation_start: datetime,
    ) -> dict[str, Any]:
        agent = (
            self.gateway.get_agent_summary(str(state.agent_id))
            if state.agent_id
            else None
        )
        connected = bool(agent and str(agent.status).lower() == "active")
        return self._check_result(
            registration,
            outcome=_CHECK_PASSED if connected else _CHECK_FAILED,
            agent_id=state.agent_id,
            observed_status=getattr(agent, "status", None),
        )

    @staticmethod
    def _port_number(item: dict[str, Any]) -> int | None:
        value = item.get("local_port", item.get("port"))
        if isinstance(value, dict):
            value = value.get("port")
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _verify_ssh_port_listening(
        self,
        registration: VerificationCheckRegistration,
        state: IncidentWorkflowState,
        _observation_start: datetime,
    ) -> dict[str, Any]:
        ports = (
            self.gateway.get_agent_inventory(
                agent_id=str(state.agent_id),
                component="ports",
                limit=100,
            )
            if state.agent_id
            else None
        )
        listening = bool(
            ports
            and any(self._port_number(item) == 22 for item in ports.items)
        )
        return self._check_result(
            registration,
            outcome=_CHECK_PASSED if listening else _CHECK_FAILED,
            agent_id=state.agent_id,
            local_port=22,
        )

    def _verify_management_ssh_reachable(
        self,
        registration: VerificationCheckRegistration,
        state: IncidentWorkflowState,
        _observation_start: datetime,
    ) -> dict[str, Any]:
        required = bool(self.settings.MAPEK_REQUIRE_MANAGEMENT_PROBE)
        effective = VerificationCheckRegistration(
            name=registration.name,
            category=registration.category,
            handler_name=registration.handler_name,
            required=required,
        )
        probe = getattr(self.gateway, "probe_management_ssh", None)
        if not callable(probe):
            return self._check_result(
                effective,
                outcome=_CHECK_NOT_VERIFIED,
                reason="management_probe_not_configured",
            )
        reachable = bool(probe(agent_id=str(state.agent_id)))
        return self._check_result(
            effective,
            outcome=_CHECK_PASSED if reachable else _CHECK_FAILED,
            agent_id=state.agent_id,
        )

    def run(self, state: IncidentWorkflowState) -> VerificationResult:
        failed_execution = any(
            result.status in _FAILED_EXECUTION_STATUSES
            for result in state.execution_results
        )
        if failed_execution:
            return VerificationResult(
                outcome=VerificationOutcome.FAILED,
                security_checks_passed=False,
                health_checks_passed=False,
                checks=[
                    {
                        "check": "execution_result",
                        "category": "execution",
                        "required": True,
                        "outcome": _CHECK_FAILED,
                    }
                ],
                dry_run=False,
            )

        plan = state.remediation_plan
        if plan is None:
            return VerificationResult(
                outcome=VerificationOutcome.NOT_VERIFIED,
                security_checks_passed=False,
                health_checks_passed=False,
                checks=[],
                dry_run=False,
            )

        declared_checks = [*plan.security_checks, *plan.health_checks]
        registrations = [
            VERIFICATION_CHECK_REGISTRY.require(name)
            for name in declared_checks
        ]
        if self.settings.MAPEK_DRY_RUN or not self.settings.MAPEK_REAL_EXECUTION_ENABLED:
            return VerificationResult(
                outcome=VerificationOutcome.SIMULATED,
                security_checks_passed=False,
                health_checks_passed=False,
                checks=[
                    self._check_result(
                        registration,
                        outcome="simulated",
                    )
                    for registration in registrations
                ],
                dry_run=True,
            )

        observation_start = self._observation_start(state)
        if observation_start is None:
            return VerificationResult(
                outcome=VerificationOutcome.NOT_VERIFIED,
                security_checks_passed=False,
                health_checks_passed=False,
                checks=[
                    {
                        "check": "successful_execution",
                        "category": "execution",
                        "required": True,
                        "outcome": _CHECK_NOT_VERIFIED,
                        "reason": "no_successful_execution_result",
                    }
                ],
                dry_run=False,
            )

        elapsed = (datetime.now(UTC) - observation_start).total_seconds()
        required_observation = max(
            int(self.settings.MAPEK_VERIFICATION_OBSERVATION_SECONDS),
            0,
        )
        if elapsed < required_observation:
            return VerificationResult(
                outcome=VerificationOutcome.NOT_VERIFIED,
                security_checks_passed=False,
                health_checks_passed=False,
                checks=[
                    {
                        "check": "observation_window",
                        "category": "security",
                        "required": True,
                        "outcome": _CHECK_NOT_VERIFIED,
                        "observation_start": observation_start.isoformat(),
                        "required_seconds": required_observation,
                        "elapsed_seconds": max(elapsed, 0),
                    }
                ],
                dry_run=False,
            )

        self._related_alerts = None
        self._related_alerts_truncated = False
        checks = [
            getattr(self, registration.handler_name)(
                registration,
                state,
                observation_start,
            )
            for registration in registrations
        ]
        required_checks = [item for item in checks if item["required"]]
        security = [
            item for item in required_checks if item["category"] == "security"
        ]
        health = [
            item for item in required_checks if item["category"] == "health"
        ]
        security_passed = bool(security) and all(
            item["outcome"] == _CHECK_PASSED for item in security
        )
        health_passed = bool(health) and all(
            item["outcome"] == _CHECK_PASSED for item in health
        )
        failed = any(item["outcome"] == _CHECK_FAILED for item in required_checks)
        unverified = any(
            item["outcome"] == _CHECK_NOT_VERIFIED for item in required_checks
        )
        if failed:
            outcome = VerificationOutcome.FAILED
        elif unverified:
            outcome = VerificationOutcome.PARTIAL
        elif security_passed and health_passed:
            outcome = VerificationOutcome.PASSED
        else:
            outcome = VerificationOutcome.NOT_VERIFIED
        return VerificationResult(
            outcome=outcome,
            security_checks_passed=security_passed,
            health_checks_passed=health_passed,
            checks=checks,
            dry_run=False,
        )
