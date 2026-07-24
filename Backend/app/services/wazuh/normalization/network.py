"""Network and firewall alert normalization."""

from typing import Any

from app.services.wazuh.normalization.base import AlertNormalizer, outcome_from_text
from app.services.wazuh.normalization.field_extractors import combined_text, integer, port, text
from app.services.wazuh.normalization.schemas import NetworkDetails


class NetworkNormalizer(AlertNormalizer):
    priority = 50
    category = "network"
    attack_family = "network_activity"

    def matches(self, raw: dict[str, Any]) -> bool:
        value = combined_text(raw)
        return any(marker in value for marker in ("firewall", "network connection", "iptables"))

    def normalize(self, raw: dict[str, Any]):
        value = combined_text(raw)
        destination_port = port(raw, "destination.port", "destination_port", "data.dstport")
        details = NetworkDetails(
            protocol=text(raw, "network.transport", "data.protocol"),
            connection_count=integer(raw, "event_count", default=1) or 1,
            bytes_sent=integer(raw, "network.bytes", "data.bytes_sent"),
            bytes_received=integer(raw, "data.bytes_received"),
            destination_ports=[destination_port] if destination_port is not None else [],
        ).model_dump(mode="json", exclude_none=True)
        return self.build(
            raw,
            event_type="network_connection",
            summary="Network or firewall activity observed.",
            outcome=outcome_from_text(value),
            attack_details=details,
        )
