"""Wazuh service-layer exceptions. Tools catch these and return structured errors."""


class WazuhError(Exception):
    """Base for every Wazuh service error (including transport failures)."""


class WazuhAuthError(WazuhError):
    """Authentication against /security/user/authenticate failed (401)."""


class WazuhAPIError(WazuhError):
    """Wazuh API returned an error response (4xx/5xx) or was unreachable."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class WazuhTimeoutError(WazuhAPIError):
    """A Wazuh operation exceeded its configured action timeout."""


class WazuhPermissionError(WazuhError):
    """Forbidden by Wazuh RBAC (403) or blocked by WAZUH_READ_ONLY."""


class WazuhValidationError(WazuhError):
    """Client-side parameter validation failed (e.g. limit > WAZUH_MAX_LIMIT)."""


class WazuhDangerousActionBlocked(WazuhError):
    """Dangerous action attempted while WAZUH_ALLOW_DANGEROUS_TOOLS is false."""
