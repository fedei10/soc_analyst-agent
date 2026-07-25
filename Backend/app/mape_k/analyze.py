"""Bounded incident diagnosis with deterministic mappings before LLM fallback."""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.mape_k.llm import LLMConfigurationError, LLMProvider, get_llm_provider
from app.mape_k.schemas import Diagnosis, IncidentWorkflowState
from app.services.redis.ephemeral import EphemeralRedis


class IncidentAnalyzer:
    def __init__(
        self,
        llm: LLMProvider | None = None,
        cache: EphemeralRedis | None = None,
    ) -> None:
        self.llm = llm or get_llm_provider()
        self.cache = cache or EphemeralRedis()

    @staticmethod
    def _validate_evidence(diagnosis: Diagnosis, state: IncidentWorkflowState) -> None:
        known = {item.evidence_id for item in state.evidence}
        unknown = set(diagnosis.evidence_ids) - known
        if unknown:
            raise ValueError(f"Diagnosis references unknown evidence: {sorted(unknown)}")

    def _ssh_diagnosis(self, state: IncidentWorkflowState) -> Diagnosis | None:
        ssh_alerts = [
            alert
            for alert in state.normalized_alerts
            if alert.event_type in {"ssh_brute_force", "ssh_login_failure"}
            and alert.outcome == "failure"
        ]
        if not ssh_alerts:
            return None
        source_ips = list(
            dict.fromkeys(alert.source_ip for alert in ssh_alerts if alert.source_ip)
        )
        if not source_ips:
            return None
        users = list(
            dict.fromkeys(alert.target_user for alert in ssh_alerts if alert.target_user)
        )
        assets = list(
            dict.fromkeys(
                alert.hostname or alert.agent_name or alert.agent_id
                for alert in ssh_alerts
                if alert.hostname or alert.agent_name or alert.agent_id
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
        return Diagnosis(
            incident_type="ssh_brute_force",
            summary="Repeated failed SSH authentication attempts were correlated.",
            root_cause="Password guessing against SSH from a remote source IP.",
            attack_techniques=["T1110.001"],
            affected_assets=assets,
            affected_entities={
                "source_ip": source_ips[0],
                "source_ips": source_ips,
                "destination_port": 22,
                "users": users,
            },
            evidence_ids=evidence_ids,
            confidence=0.96 if len(ssh_alerts) > 1 else 0.86,
            needs_more_evidence=False,
            deterministic=True,
        )

    def run(self, state: IncidentWorkflowState) -> tuple[Diagnosis, dict[str, int]]:
        cache_key = (
            f"{state.incident_fingerprint}:{state.evidence_version}:diagnosis"
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
        messages = [
            {
                "role": "system",
                "content": (
                    "Diagnose the incident using only supplied evidence IDs. "
                    "Do not invent evidence or remediation actions."
                ),
            },
            {"role": "user", "content": str(selected_evidence)},
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

