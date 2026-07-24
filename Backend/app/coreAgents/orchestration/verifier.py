"""Deterministic post-action verification for approved responses."""

from app.coreAgents.orchestration.nodes import audit_event
from app.coreAgents.orchestration.state import InvestigationState


def verify_response(
    state: InvestigationState,
    *,
    gateway=None,
    system_executor=None,
) -> dict:
    executed = state.get("executed_actions", [])
    if not executed:
        return {
            "status": "running",
            "current_stage": "verification",
            "verification_results": [],
            "audit_events": [
                audit_event(
                    state,
                    stage="verification",
                    event="response_verification_skipped",
                )
            ],
        }

    results: list[dict] = []
    verified_actions: list[dict] = []
    for action in executed:
        action_type = action.get("action_type")
        target = str(action.get("target") or "")
        status = "verification_pending"
        code = "VERIFICATION_NOT_SUPPORTED"

        try:
            if action_type == "restart_service":
                if system_executor is None:
                    from app.services.system.remediation import (
                        SystemRemediationService,
                    )

                    system_executor = SystemRemediationService()
                active = system_executor.is_service_active(target)
                status = "verified" if active else "verification_failed"
                code = "SERVICE_ACTIVE" if active else "SERVICE_INACTIVE"
            elif action_type == "restart_agent":
                if gateway is None:
                    from app.services.wazuh.dependencies import get_wazuh_gateway

                    gateway = get_wazuh_gateway()
                summary = gateway.get_agent_summary(target)
                active = (
                    summary is not None
                    and str(getattr(summary, "status", "")).lower() == "active"
                )
                status = "verified" if active else "verification_failed"
                code = "AGENT_ACTIVE" if active else "AGENT_NOT_ACTIVE"
            elif action_type == "block_ip":
                # Wazuh queues active responses but exposes no reliable
                # read-after-write firewall state through this gateway.
                code = "ACTIVE_RESPONSE_CONFIRMATION_REQUIRED"
        except Exception:
            status = "verification_failed"
            code = "VERIFICATION_CHECK_FAILED"

        result = {
            "action_id": action.get("action_id"),
            "action_type": action_type,
            "target": target,
            "status": status,
            "code": code,
        }
        results.append(result)
        verified_actions.append({**action, "status": status, "verification": result})

    event = (
        "response_verified"
        if all(item["status"] == "verified" for item in results)
        else "response_verification_incomplete"
    )
    return {
        "status": "running",
        "current_stage": "verification",
        "executed_actions": verified_actions,
        "verification_results": results,
        "audit_events": [
            {
                **audit_event(state, stage="verification", event=event),
                "result_count": len(results),
            }
        ],
    }
