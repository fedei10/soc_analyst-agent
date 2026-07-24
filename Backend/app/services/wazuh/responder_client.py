"""Human-approved Wazuh response operations using separate credentials."""

from typing import Any

from app.config import settings
from app.services.wazuh.exceptions import WazuhDangerousActionBlocked
from app.services.wazuh.server_client import _AuthenticatedWazuhTransport


class WazuhResponderClient:
    """Write-only response surface; never inject this object into an LLM tool."""

    def __init__(self) -> None:
        if not settings.WAZUH_ALLOW_DANGEROUS_TOOLS:
            raise WazuhDangerousActionBlocked(
                "Response actions are disabled. Set WAZUH_ALLOW_DANGEROUS_TOOLS=true only "
                "for the protected human-approved response workflow."
            )
        username = settings.WAZUH_RESPONDER_USERNAME
        password = settings.WAZUH_RESPONDER_PASSWORD.get_secret_value()
        if not username or not password:
            raise WazuhDangerousActionBlocked(
                "Responder credentials are not configured. Set WAZUH_RESPONDER_USERNAME and "
                "WAZUH_RESPONDER_PASSWORD for the human-approved response endpoint."
            )
        verify: bool | str = (
            settings.WAZUH_CA_CERT or True
        ) if settings.WAZUH_VERIFY_SSL else False
        self._transport = _AuthenticatedWazuhTransport(
            base_url=settings.WAZUH_BASE_URL,
            username=username,
            password=password,
            verify=verify,
            component="responder",
        )

    def run_active_response(
        self,
        *,
        agent_id: str,
        command: str,
        arguments: list[str] | None = None,
        alert: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"command": command, "arguments": arguments or []}
        if alert:
            body["alert"] = alert
        return self._transport.request(
            "PUT",
            "/active-response",
            params={"agents_list": agent_id},
            json=body,
        ).json()

    def restart_agent(self, agent_id: str) -> dict[str, Any]:
        return self._transport.request("PUT", f"/agents/{agent_id}/restart").json()

    def close(self) -> None:
        self._transport.close()
