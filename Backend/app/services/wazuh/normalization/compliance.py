"""Security Configuration Assessment normalization."""

from typing import Any

from app.services.wazuh.normalization.base import AlertNormalizer
from app.services.wazuh.normalization.field_extractors import combined_text, number, text
from app.services.wazuh.normalization.schemas import ComplianceDetails


class ComplianceNormalizer(AlertNormalizer):
    priority = 35
    category = "compliance"
    attack_family = "security_posture"

    def matches(self, raw: dict[str, Any]) -> bool:
        value = combined_text(raw)
        return "sca" in value or "security configuration assessment" in value

    def normalize(self, raw: dict[str, Any]):
        status = text(raw, "data.sca.check.result", "data.sca.result", "data.status")
        lowered = (status or combined_text(raw)).lower()
        failed = any(marker in lowered for marker in ("fail", "non-compliant", "not passed"))
        event_type = "compliance_control_failed" if failed else "compliance_control_status"
        control = text(raw, "data.sca.check.id", "data.sca.control.id")
        benchmark = text(raw, "data.sca.policy", "data.sca.policy_id")
        details = ComplianceDetails(
            benchmark=benchmark,
            control_id=control,
            control_title=text(raw, "data.sca.check.title", "data.sca.control.title"),
            previous_status=text(raw, "data.sca.previous_result"),
            current_status=status,
            score=number(raw, "data.sca.score"),
        ).model_dump(mode="json", exclude_none=True)
        return self.build(
            raw,
            event_type=event_type,
            summary=f"Compliance control {control or 'unknown'} status is {status or 'unknown'}.",
            outcome="failure" if failed else "unknown",
            attack_details=details,
        )
