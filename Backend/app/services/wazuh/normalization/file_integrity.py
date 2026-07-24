"""Wazuh syscheck and file-integrity normalization."""

from typing import Any

from app.services.wazuh.normalization.base import AlertNormalizer
from app.services.wazuh.normalization.field_extractors import combined_text, text
from app.services.wazuh.normalization.schemas import FileIntegrityDetails


class FileIntegrityNormalizer(AlertNormalizer):
    priority = 45
    category = "file_integrity"
    attack_family = "file_change"

    def matches(self, raw: dict[str, Any]) -> bool:
        value = combined_text(raw)
        return "syscheck" in value or "file integrity" in value

    def normalize(self, raw: dict[str, Any]):
        value = combined_text(raw)
        if "deleted" in value:
            operation = "deleted"
        elif "added" in value or "created" in value:
            operation = "created"
        else:
            operation = "modified"
        path = text(raw, "syscheck.path", "data.path", "file.path")
        details = FileIntegrityDetails(
            path=path,
            operation=operation,
            previous_hash=text(raw, "syscheck.md5_before", "syscheck.sha256_before"),
            current_hash=text(raw, "syscheck.md5_after", "syscheck.sha256_after"),
            user=text(raw, "syscheck.uname_after", "user.name"),
            process=text(raw, "syscheck.process_name", "process.name"),
            file_type=text(raw, "syscheck.type", "file.type"),
        ).model_dump(mode="json", exclude_none=True)
        return self.build(
            raw,
            event_type=f"file_{operation}",
            summary=f"File {path or 'unknown path'} was {operation}.",
            attack_details=details,
            file_path=path,
        )
