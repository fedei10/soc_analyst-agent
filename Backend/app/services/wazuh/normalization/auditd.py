"""Linux Auditd process-execution normalization."""

from typing import Any

from app.services.wazuh.normalization.base import AlertNormalizer, outcome_from_text
from app.services.wazuh.normalization.field_extractors import (
    combined_text,
    hash_sensitive,
    integer,
    text,
)
from app.services.wazuh.normalization.schemas import ProcessExecutionDetails


class AuditdNormalizer(AlertNormalizer):
    priority = 20
    category = "process_execution"
    attack_family = "execution"

    def matches(self, raw: dict[str, Any]) -> bool:
        value = combined_text(raw)
        return "auditd" in value or "execve" in value

    def normalize(self, raw: dict[str, Any]):
        value = combined_text(raw)
        executable = text(
            raw,
            "data.audit.exe",
            "data.exe",
            "process.executable",
            "process.name",
        )
        parent = text(raw, "data.audit.parent", "process.parent.name")
        command = text(raw, "data.audit.command", "process.command_line", "data.command")
        details = ProcessExecutionDetails(
            executable=executable,
            parent_process=parent,
            command_line_hash=hash_sensitive(command),
            user=text(raw, "data.audit.uid", "user.name", "data.user"),
            privilege_level=text(raw, "data.audit.euid"),
            suspicious_interpreter=bool(
                executable
                and executable.rsplit("/", 1)[-1].lower()
                in {"bash", "sh", "powershell.exe", "pwsh", "python", "perl"}
            ),
            execution_count=integer(raw, "event_count", default=1) or 1,
        ).model_dump(mode="json", exclude_none=True)
        return self.build(
            raw,
            event_type="process_execution",
            summary=f"Process execution observed for {executable or 'unknown executable'}.",
            outcome=outcome_from_text(value),
            attack_details=details,
            process_name=executable,
            parent_process_name=parent,
        )
