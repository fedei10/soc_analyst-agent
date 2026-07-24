"""Human-approved allowlisted remediation on the TSAGE API host."""

import re
import shutil
import subprocess
from datetime import UTC, datetime

from app.config import settings


SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")


class SystemRemediationError(RuntimeError):
    pass


class SystemRemediationService:
    def __init__(
        self,
        *,
        enabled: bool | None = None,
        service_allowlist: set[str] | None = None,
        timeout: int | None = None,
    ) -> None:
        self.enabled = (
            settings.SELF_HEALING_ENABLED if enabled is None else enabled
        )
        configured = {
            item.strip()
            for item in settings.SELF_HEALING_SERVICE_ALLOWLIST.split(",")
            if item.strip()
        }
        self.service_allowlist = (
            configured if service_allowlist is None else service_allowlist
        )
        self.timeout = timeout or settings.SYSTEM_COMMAND_TIMEOUT

    def validate_service(self, service_name: str) -> None:
        if not self.enabled:
            raise SystemRemediationError("Self-healing is disabled.")
        if not SERVICE_NAME.fullmatch(service_name):
            raise SystemRemediationError("Invalid service name.")
        if service_name not in self.service_allowlist:
            raise SystemRemediationError("Service is not allowlisted.")
        if shutil.which("systemctl") is None:
            raise SystemRemediationError("systemctl is unavailable.")

    def restart_service(self, service_name: str) -> dict:
        self.validate_service(service_name)
        completed = subprocess.run(
            ["systemctl", "restart", service_name],
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise SystemRemediationError("Service restart failed.")
        return {
            "action_type": "restart_service",
            "target": service_name,
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
        }
