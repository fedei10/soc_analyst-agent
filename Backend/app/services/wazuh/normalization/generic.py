"""Safe fallback for otherwise unknown Wazuh alerts."""

from typing import Any

from app.services.wazuh.normalization.base import AlertNormalizer, outcome_from_text
from app.services.wazuh.normalization.field_extractors import combined_text, text


class GenericNormalizer(AlertNormalizer):
    priority = 1000

    def matches(self, raw: dict[str, Any]) -> bool:
        return True

    def normalize(self, raw: dict[str, Any]):
        description = text(raw, "rule.description", "description") or "Unclassified Wazuh alert"
        return self.build(
            raw,
            event_type="generic_alert",
            summary=f"Wazuh alert: {description}.",
            outcome=outcome_from_text(combined_text(raw)),
            generic=True,
        )
