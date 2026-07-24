"""Sysmon process, network, file, and registry normalization."""

from typing import Any

from app.services.wazuh.normalization.base import AlertNormalizer, outcome_from_text
from app.services.wazuh.normalization.field_extractors import combined_text, text


class SysmonNormalizer(AlertNormalizer):
    priority = 25
    category = "endpoint"
    attack_family = "endpoint_activity"

    def matches(self, raw: dict[str, Any]) -> bool:
        return "sysmon" in combined_text(raw)

    def normalize(self, raw: dict[str, Any]):
        value = combined_text(raw)
        if "network connection" in value or "event id: 3" in value:
            event_type, category = "network_connection", "network"
        elif "file create" in value or "event id: 11" in value:
            event_type, category = "file_created", "file_integrity"
        elif "registry" in value:
            event_type, category = "registry_changed", "configuration_change"
        else:
            event_type, category = "process_created", "process_execution"
        process = text(raw, "data.win.eventdata.image", "process.executable")
        parent = text(raw, "data.win.eventdata.parentImage", "process.parent.executable")
        path = text(raw, "data.win.eventdata.targetFilename", "file.path")
        return self.build(
            raw,
            event_type=event_type,
            category=category,
            summary=f"Sysmon {event_type.replace('_', ' ')} event.",
            outcome=outcome_from_text(value),
            attack_details={
                "provider": "sysmon",
                "event_id": text(raw, "data.win.system.eventID"),
            },
            process_name=process,
            parent_process_name=parent,
            file_path=path,
        )
