"""Bounded incident diagnosis with deterministic mappings before LLM fallback."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from app.config import settings
from app.mape_k.llm import LLMConfigurationError, LLMProvider, get_llm_provider
from app.mape_k.schemas import (
    Diagnosis,
    IncidentWorkflowState,
    SSHDetectionPolicy,
)
from app.services.redis.ephemeral import EphemeralRedis


SSH_FAILURE_EVENT_TYPES = {
    "ssh_login_failure",
    "ssh_invalid_user_attempt",
    "ssh_brute_force",
    "ssh_password_spraying",
}


class IncidentAnalyzer:
    def __init__(
        self,
        llm: LLMProvider | None = None,
        cache: EphemeralRedis | None = None,
        ssh_policy: SSHDetectionPolicy | None = None,
    ) -> None:
        self.llm = llm or get_llm_provider()
        self.cache = cache or EphemeralRedis()
        self.ssh_policy = ssh_policy or SSHDetectionPolicy(
            brute_force_min_failures=settings.MAPEK_SSH_BRUTE_FORCE_MIN_FAILURES,
            brute_force_min_events=settings.MAPEK_SSH_BRUTE_FORCE_MIN_EVENTS,
            brute_force_window_seconds=settings.MAPEK_SSH_BRUTE_FORCE_WINDOW_SECONDS,
            password_spray_min_users=settings.MAPEK_SSH_PASSWORD_SPRAY_MIN_USERS,
            password_spray_min_failures=(
                settings.MAPEK_SSH_PASSWORD_SPRAY_MIN_FAILURES
            ),
            password_spray_window_seconds=(
                settings.MAPEK_SSH_PASSWORD_SPRAY_WINDOW_SECONDS
            ),
            success_after_failure_window_seconds=(
                settings.MAPEK_SSH_SUCCESS_AFTER_FAILURE_WINDOW_SECONDS
            ),
        )

    @staticmethod
    def _validate_evidence(diagnosis: Diagnosis, state: IncidentWorkflowState) -> None:
        known = {item.evidence_id for item in state.evidence}
        unknown = set(diagnosis.evidence_ids) - known
        if unknown:
            raise ValueError(f"Diagnosis references unknown evidence: {sorted(unknown)}")

    @staticmethod
    def _asset(alert: Any) -> str | None:
        return alert.hostname or alert.agent_name or alert.agent_id

    @staticmethod
    def _window_matches(
        alerts: list[Any],
        *,
        attempt_counts: dict[str, int],
        window_seconds: int,
        minimum_attempts: int,
        minimum_events: int,
        minimum_users: int = 0,
    ) -> bool:
        ordered = sorted(alerts, key=lambda alert: alert.timestamp)
        for index, first in enumerate(ordered):
            window = [
                alert
                for alert in ordered[index:]
                if (alert.timestamp - first.timestamp).total_seconds()
                <= window_seconds
            ]
            users = {alert.target_user for alert in window if alert.target_user}
            attempts = sum(
                attempt_counts.get(alert.alert_id, 1) for alert in window
            )
            if (
                attempts >= minimum_attempts
                and len(window) >= minimum_events
                and len(users) >= minimum_users
            ):
                return True
        return False

    def _ssh_diagnosis(self, state: IncidentWorkflowState) -> Diagnosis | None:
        authentication = state.authentication_evidence
        if authentication is None:
            return None
        ssh_alerts = [
            alert
            for alert in state.normalized_alerts
            if alert.event_type in SSH_FAILURE_EVENT_TYPES
            or alert.event_type == "ssh_login_success"
        ]
        if not ssh_alerts:
            return None
        failures = [alert for alert in ssh_alerts if alert.outcome == "failure"]
        successes = [alert for alert in ssh_alerts if alert.outcome == "success"]
        source_ips = list(
            dict.fromkeys(alert.source_ip for alert in ssh_alerts if alert.source_ip)
        )
        users = list(
            dict.fromkeys(alert.target_user for alert in ssh_alerts if alert.target_user)
        )
        assets = list(
            dict.fromkeys(
                self._asset(alert)
                for alert in ssh_alerts
                if self._asset(alert)
            )
        )
        relevant_ids = {
            f"wazuh:alert:{alert.alert_id}" for alert in ssh_alerts
        }
        evidence_ids = [
            item.evidence_id
            for item in state.evidence
            if item.source_ref in relevant_ids
        ]
        if not evidence_ids:
            return None
        attempt_counts = {
            str(record.get("source_ref", "")).removeprefix("wazuh:alert:"): max(
                1,
                int(record.get("event_count") or 1),
            )
            for record in state.evidence_records
            if isinstance(record, dict)
        }

        spray_groups: dict[tuple[str | None, str | None], list[Any]] = defaultdict(
            list
        )
        brute_force_groups: dict[
            tuple[str | None, str | None, str | None], list[Any]
        ] = defaultdict(list)
        for alert in failures:
            asset = self._asset(alert)
            spray_groups[(alert.source_ip, asset)].append(alert)
            brute_force_groups[
                (alert.source_ip, asset, alert.target_user)
            ].append(alert)

        password_spray = any(
            self._window_matches(
                group,
                attempt_counts=attempt_counts,
                window_seconds=self.ssh_policy.password_spray_window_seconds,
                minimum_attempts=self.ssh_policy.password_spray_min_failures,
                minimum_events=self.ssh_policy.password_spray_min_users,
                minimum_users=self.ssh_policy.password_spray_min_users,
            )
            for group in spray_groups.values()
        )
        brute_force = any(
            self._window_matches(
                group,
                attempt_counts=attempt_counts,
                window_seconds=self.ssh_policy.brute_force_window_seconds,
                minimum_attempts=self.ssh_policy.brute_force_min_failures,
                minimum_events=self.ssh_policy.brute_force_min_events,
            )
            for group in brute_force_groups.values()
        )

        if authentication.successful_login_after_failures is True:
            incident_type = "ssh_success_after_failures"
            summary = (
                "A successful SSH authentication was observed after failed "
                "attempts within the configured time window."
            )
            root_cause = (
                "The observed authentication sequence changed from failure to "
                "success; the evidence does not by itself prove account compromise."
            )
            techniques = ["T1110"]
            confidence = 0.94
            needs_more_evidence = authentication.truncated or not source_ips
        elif password_spray:
            incident_type = "ssh_password_spraying"
            summary = (
                "SSH failures from one observed source targeted enough distinct "
                "users to meet the configured password-spraying threshold."
            )
            root_cause = (
                "One observed source attempted SSH authentication across multiple "
                "target accounts within the configured time window."
            )
            techniques = ["T1110.003"]
            confidence = 0.96
            needs_more_evidence = authentication.truncated or not source_ips
        elif brute_force:
            incident_type = "ssh_brute_force"
            summary = (
                "Repeated SSH authentication failures met the configured "
                "brute-force thresholds."
            )
            root_cause = (
                "Repeated failures against the same observed SSH target met the "
                "configured password-guessing threshold."
            )
            techniques = ["T1110.001"]
            confidence = 0.96
            needs_more_evidence = authentication.truncated or not source_ips
        elif any(
            alert.event_type == "ssh_invalid_user_attempt" for alert in failures
        ):
            incident_type = "ssh_invalid_user_attempt"
            summary = "An SSH authentication attempt targeted an invalid user."
            root_cause = (
                "The SSH service rejected an authentication attempt for a user "
                "that the observed log identified as invalid."
            )
            techniques = []
            confidence = 0.68
            needs_more_evidence = True
        elif failures:
            incident_type = "ssh_login_failure"
            summary = (
                "SSH authentication failures were observed, but configured "
                "brute-force and password-spraying thresholds were not met."
            )
            root_cause = (
                "The available evidence confirms unsuccessful SSH authentication "
                "only; intent and cause remain undetermined."
            )
            techniques = []
            confidence = 0.62
            needs_more_evidence = True
        elif successes:
            incident_type = "ssh_login_success"
            summary = "A successful SSH authentication was observed."
            root_cause = (
                "The available evidence confirms a successful SSH login but does "
                "not establish whether it was authorized."
            )
            techniques = []
            confidence = 0.7
            needs_more_evidence = True
        else:
            return None

        return Diagnosis(
            incident_type=incident_type,
            summary=summary,
            root_cause=root_cause,
            attack_techniques=techniques,
            affected_assets=assets,
            affected_entities={
                "source_ip": source_ips[0] if source_ips else None,
                "source_ips": source_ips,
                "destination_port": 22,
                "users": users,
                "source_is_internal": authentication.source_is_internal,
                "source_is_approved_admin": (
                    authentication.source_is_approved_admin
                ),
            },
            evidence_ids=evidence_ids,
            confidence=confidence,
            needs_more_evidence=needs_more_evidence,
            deterministic=True,
        )

    def run(
        self,
        state: IncidentWorkflowState,
    ) -> tuple[Diagnosis, dict[str, Any]]:
        cache_key = (
            f"{state.incident_fingerprint}:{state.evidence_version}:"
            f"{self.ssh_policy.model_dump_json()}:diagnosis-v2"
        )
        cached = self.cache.get_json(
            namespace="mapek-analysis",
            organization_id=state.organization_id,
            cache_key=cache_key,
        )
        if cached:
            diagnosis = Diagnosis.model_validate(cached)
            self._validate_evidence(diagnosis, state)
            return diagnosis, {"input_tokens": 0, "output_tokens": 0}

        deterministic = self._ssh_diagnosis(state)
        if deterministic is not None:
            self._validate_evidence(deterministic, state)
            self.cache.set_json(
                namespace="mapek-analysis",
                organization_id=state.organization_id,
                cache_key=cache_key,
                value=deterministic.model_dump(mode="json"),
                ttl_seconds=settings.REDIS_CONTEXT_TTL_SECONDS,
            )
            return deterministic, {"input_tokens": 0, "output_tokens": 0}

        selected_evidence = [
            {
                "evidence_id": item.evidence_id,
                "source_type": item.source_type,
                "summary": item.summary,
            }
            for item in state.evidence[:20]
        ]
        prompt_payload: dict[str, Any] = {
            "schema_version": "1.0",
            "incident_id": state.incident_id,
            "incident_fingerprint": state.incident_fingerprint,
            "findings": state.findings[:3],
            "deterministic_facts": (
                [state.authentication_evidence.model_dump(mode="json")]
                if state.authentication_evidence
                else []
            ),
            "evidence": selected_evidence,
            "evidence_truncated": len(state.evidence) > len(selected_evidence),
            "asset_context": {
                "agent_id": state.agent_id,
            },
            "questions": [
                "What incident type best fits the supplied evidence?",
                "Which facts are confirmed by the supplied evidence IDs?",
                "Which hypotheses remain unconfirmed?",
                "What additional evidence is needed?",
            ],
        }
        messages = [
            {
                "role": "system",
                "content": (
                    "Diagnose the incident using only supplied evidence IDs. "
                    "Do not invent evidence or remediation actions."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    prompt_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        ]
        try:
            result, usage = self.llm.invoke_structured(Diagnosis, messages)
            diagnosis = Diagnosis.model_validate(result)
            self._validate_evidence(diagnosis, state)
        except LLMConfigurationError:
            first = state.evidence[:1]
            diagnosis = Diagnosis(
                incident_type="unknown",
                summary="No deterministic diagnosis matched and semantic analysis is unavailable.",
                root_cause="Insufficient evidence for an automated diagnosis.",
                evidence_ids=[item.evidence_id for item in first],
                confidence=0.0,
                needs_more_evidence=True,
            )
            usage = {"input_tokens": 0, "output_tokens": 0}
        return diagnosis, usage
