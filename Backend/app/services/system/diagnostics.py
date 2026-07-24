"""Allowlisted read-only diagnostics for the host running the TSAGE API."""

import shutil
import subprocess
from datetime import UTC, datetime
from functools import lru_cache
from typing import Literal

from app.config import settings


DiagnosticName = Literal[
    "listening_ports",
    "network_connections",
    "routing_table",
    "firewall_status",
    "failed_services",
    "process_snapshot",
]

MAX_DIAGNOSTIC_OUTPUT = 20_000


class SystemDiagnosticsDisabledError(PermissionError):
    pass


class SystemDiagnosticService:
    def __init__(
        self,
        *,
        enabled: bool | None = None,
        timeout: int | None = None,
    ) -> None:
        self.enabled = (
            settings.SYSTEM_DIAGNOSTICS_ENABLED
            if enabled is None
            else enabled
        )
        self.timeout = timeout or settings.SYSTEM_COMMAND_TIMEOUT

    @staticmethod
    def _command(diagnostic: DiagnosticName) -> list[str]:
        commands = {
            "listening_ports": ["ss", "-lntup"],
            "network_connections": ["ss", "-tunap"],
            "routing_table": ["ip", "route", "show"],
            "failed_services": [
                "systemctl",
                "--failed",
                "--no-legend",
                "--no-pager",
            ],
            "process_snapshot": [
                "ps",
                "-eo",
                "pid,user,comm,%cpu,%mem",
                "--sort=-%cpu",
            ],
        }
        if diagnostic == "firewall_status":
            if shutil.which("nft"):
                return ["nft", "list", "ruleset"]
            if shutil.which("ufw"):
                return ["ufw", "status", "verbose"]
            return ["iptables", "-S"]
        return commands[diagnostic]

    def collect(self, diagnostic: DiagnosticName) -> dict:
        if not self.enabled:
            raise SystemDiagnosticsDisabledError(
                "System diagnostics are disabled."
            )
        command = self._command(diagnostic)
        executable = shutil.which(command[0])
        if executable is None:
            return {
                "diagnostic": diagnostic,
                "scope": "tsage_api_host",
                "status": "unavailable",
                "reason": f"{command[0]} is not installed.",
                "captured_at": datetime.now(UTC).isoformat(),
            }

        try:
            completed = subprocess.run(
                [executable, *command[1:]],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "diagnostic": diagnostic,
                "scope": "tsage_api_host",
                "status": "timeout",
                "captured_at": datetime.now(UTC).isoformat(),
            }

        stdout = completed.stdout[:MAX_DIAGNOSTIC_OUTPUT]
        stderr = completed.stderr[:MAX_DIAGNOSTIC_OUTPUT]
        truncated = (
            len(completed.stdout) > len(stdout)
            or len(completed.stderr) > len(stderr)
        )
        return {
            "diagnostic": diagnostic,
            "scope": "tsage_api_host",
            "status": "completed" if completed.returncode == 0 else "failed",
            "executable": command[0],
            "exit_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": truncated,
            "captured_at": datetime.now(UTC).isoformat(),
        }


@lru_cache(maxsize=1)
def get_system_diagnostic_service() -> SystemDiagnosticService:
    return SystemDiagnosticService()
