"""Deterministic-first, LLM-fallback triage verdicts with an evidence-hallucination guard."""

from __future__ import annotations

from app.mape_k.llm import LLMConfigurationError, LLMProvider, get_llm_provider
from app.services.wazuh.normalization.schemas import SecurityFinding
from app.services.wazuh.triage.schemas import EnrichmentResult, TriageVerdict


# event_type -> deterministic verdict label. Anything not listed falls back to the LLM.
DETERMINISTIC_VERDICTS: dict[str, str] = {
    "ssh_brute_force": "malicious",
    "ssh_login_failure": "suspicious",
    "vulnerable_package": "suspicious",
    "compliance_control_failed": "suspicious",
    "file_created": "suspicious",
    "file_modified": "suspicious",
    "file_deleted": "suspicious",
    "generic_alert": "inconclusive",
}


class TriageAnalyzer:
    def __init__(self, llm: LLMProvider | None = None) -> None:
        self.llm = llm or get_llm_provider()

    @staticmethod
    def _validate_evidence(verdict: TriageVerdict, finding: SecurityFinding) -> None:
        known = set(finding.evidence_refs)
        unknown = set(verdict.evidence_refs) - known
        if unknown:
            raise ValueError(f"Verdict references unknown evidence: {sorted(unknown)}")

    def _deterministic(
        self,
        finding: SecurityFinding,
        enrichment: list[EnrichmentResult],
    ) -> TriageVerdict | None:
        label = DETERMINISTIC_VERDICTS.get(finding.event_type)
        if label is None:
            return None

        false_positive_indicators: list[str] = []
        confidence = finding.confidence
        if any(item.allowlisted for item in enrichment):
            label = "benign"
            confidence = 0.95
            false_positive_indicators.append(
                "Source is on the approved administrative IP allowlist."
            )

        missing_evidence: list[str] = []
        if finding.event_type == "generic_alert":
            missing_evidence.append(
                "Alert used generic normalization; decoder-specific fields were unavailable."
            )
        if finding.event_type == "ssh_brute_force" and not finding.target_users:
            missing_evidence.append("No target username was captured for this finding.")

        return TriageVerdict(
            verdict=label,
            confidence=confidence,
            severity=finding.severity,
            summary=finding.summary,
            evidence_refs=finding.evidence_refs,
            false_positive_indicators=false_positive_indicators,
            escalation_recommended=(
                label == "malicious" and finding.severity in {"high", "critical"}
            ),
            missing_evidence=missing_evidence,
            deterministic=True,
            reason_code=finding.event_type.upper(),
        )

    def run(
        self,
        finding: SecurityFinding,
        enrichment: list[EnrichmentResult],
    ) -> TriageVerdict:
        deterministic = self._deterministic(finding, enrichment)
        if deterministic is not None:
            self._validate_evidence(deterministic, finding)
            return deterministic

        messages = [
            {
                "role": "system",
                "content": (
                    "Triage this security finding using only its supplied evidence "
                    "references. Choose benign, suspicious, malicious, or "
                    "inconclusive. Do not invent evidence or assets."
                ),
            },
            {
                "role": "user",
                "content": str(
                    {
                        "finding": finding.model_dump(mode="json"),
                        "enrichment": [item.model_dump(mode="json") for item in enrichment],
                    }
                ),
            },
        ]
        try:
            result, _usage = self.llm.invoke_structured(TriageVerdict, messages)
            verdict = TriageVerdict.model_validate(result)
            self._validate_evidence(verdict, finding)
        except LLMConfigurationError:
            verdict = TriageVerdict(
                verdict="inconclusive",
                confidence=0.0,
                severity=finding.severity,
                summary=finding.summary,
                evidence_refs=finding.evidence_refs,
                escalation_recommended=finding.investigation_recommended,
                missing_evidence=[
                    "Semantic triage is unavailable and no deterministic rule matched.",
                ],
                deterministic=False,
                reason_code="LLM_UNAVAILABLE",
            )
        return verdict
