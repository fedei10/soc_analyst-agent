"""Human-approved response execution boundary.

SOC agents never import this module. It is invoked only after the approval
interrupt has resumed with a validated human decision.
"""

from datetime import UTC, datetime
from ipaddress import ip_address

from app.coreAgents.orchestration.nodes import audit_event, failed_update
from app.coreAgents.orchestration.routing import requires_approval
from app.coreAgents.orchestration.state import InvestigationState


SUPPORTED_RESPONSE_ACTIONS = {
    "block_ip",
    "restart_agent",
    "restart_service",
}


def _executor_failure(
    state: InvestigationState,
    *,
    code: str,
    executed_actions: list[dict] | None = None,
) -> dict:
    update = failed_update(
        state,
        stage="response_execution",
        code=code,
    )
    if executed_actions is not None:
        update["executed_actions"] = executed_actions
    return update


def _parse_expiry(value) -> datetime | None:
    try:
        expires_at = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if expires_at.tzinfo is None:
        return None
    return expires_at


def _agent_id(state: InvestigationState) -> str | None:
    value = state.get("agent_id")
    if value is None:
        value = (state.get("normalized_alert") or {}).get("agent_id")
    value = str(value) if value is not None else ""
    return value if value.isdigit() else None


def execute_response(
    state: InvestigationState,
    *,
    responder=None,
    system_executor=None,
    settings_obj=None,
    now: datetime | None = None,
) -> dict:
    """Execute exactly the approved allowlisted write actions."""
    if settings_obj is None:
        from app.config import settings as application_settings

        settings_obj = application_settings

    if (
        getattr(settings_obj, "WAZUH_READ_ONLY", True)
        or not getattr(settings_obj, "WAZUH_ALLOW_DANGEROUS_TOOLS", False)
    ):
        return _executor_failure(
            state,
            code="RESPONSE_ACTIONS_DISABLED",
        )

    request = state.get("approval_request")
    decision = state.get("approval_decision")
    if not isinstance(request, dict) or not isinstance(decision, dict):
        return _executor_failure(state, code="VALID_APPROVAL_MISSING")

    if request.get("investigation_id") != state.get("investigation_id"):
        return _executor_failure(
            state,
            code="INVESTIGATION_ID_MISMATCH",
        )
    if (
        not decision.get("approval_id")
        or decision.get("approval_id") != request.get("approval_id")
    ):
        return _executor_failure(state, code="APPROVAL_ID_MISMATCH")
    if decision.get("decision") != "approve" or not decision.get("approved_by"):
        return _executor_failure(state, code="VALID_APPROVAL_MISSING")

    expires_at = _parse_expiry(request.get("expires_at"))
    current_time = now or datetime.now(UTC)
    if (
        expires_at is None
        or current_time.tzinfo is None
        or expires_at <= current_time
    ):
        return _executor_failure(state, code="APPROVAL_EXPIRED")

    approved_actions = request.get("proposed_actions")
    proposed_actions = state.get("proposed_actions", [])
    if (
        not isinstance(approved_actions, list)
        or not isinstance(proposed_actions, list)
        or any(not isinstance(action, dict) for action in approved_actions)
        or any(not isinstance(action, dict) for action in proposed_actions)
    ):
        return _executor_failure(state, code="APPROVED_ACTION_MISMATCH")

    current_actions = [
        action
        for action in proposed_actions
        if requires_approval(action)
    ]
    if approved_actions != current_actions:
        return _executor_failure(state, code="APPROVED_ACTION_MISMATCH")

    if not approved_actions:
        return _executor_failure(state, code="APPROVED_ACTIONS_MISSING")
    if any(
        action.get("action_type") not in SUPPORTED_RESPONSE_ACTIONS
        for action in approved_actions
    ):
        return _executor_failure(
            state,
            code="UNSUPPORTED_RESPONSE_ACTION",
        )

    agent_id = _agent_id(state)
    requires_wazuh = any(
        action["action_type"] in {"block_ip", "restart_agent"}
        for action in approved_actions
    )
    if requires_wazuh and agent_id is None:
        return _executor_failure(state, code="INVALID_RESPONSE_AGENT")

    validated_targets: list[str] = []
    for action in approved_actions:
        action_type = action["action_type"]
        target = action.get("target")
        if action_type == "block_ip":
            try:
                validated_targets.append(str(ip_address(target)))
            except (TypeError, ValueError):
                return _executor_failure(
                    state,
                    code="INVALID_RESPONSE_TARGET",
                )
        elif action_type == "restart_agent":
            target_agent = str(target or "")
            if (
                not target_agent.isdigit()
                or target_agent != agent_id
            ):
                return _executor_failure(
                    state,
                    code="INVALID_RESPONSE_TARGET",
                )
            validated_targets.append(target_agent)
        else:
            service_name = str(target or "")
            if system_executor is None:
                try:
                    from app.services.system.remediation import (
                        SystemRemediationService,
                    )

                    system_executor = SystemRemediationService()
                except Exception:
                    return _executor_failure(
                        state,
                        code="SELF_HEALING_UNAVAILABLE",
                    )
            try:
                system_executor.validate_service(service_name)
            except Exception:
                return _executor_failure(
                    state,
                    code="INVALID_RESPONSE_TARGET",
                )
            validated_targets.append(service_name)

    if requires_wazuh and responder is None:
        try:
            from app.services.wazuh.dependencies import get_wazuh_responder

            responder = get_wazuh_responder()
        except Exception:
            return _executor_failure(
                state,
                code="RESPONSE_EXECUTOR_UNAVAILABLE",
            )

    executed = list(state.get("executed_actions", []))
    for action, target in zip(approved_actions, validated_targets):
        action_type = action["action_type"]
        try:
            if action_type == "block_ip":
                responder.run_active_response(
                    agent_id=agent_id,
                    command="firewall-drop",
                    arguments=[target],
                    alert=state.get("source_alert"),
                )
                execution_status = "queued"
            elif action_type == "restart_agent":
                responder.restart_agent(target)
                execution_status = "queued"
            else:
                system_executor.restart_service(target)
                execution_status = "completed"
        except Exception:
            return _executor_failure(
                state,
                code="RESPONSE_EXECUTION_FAILED",
                executed_actions=executed,
            )

        executed.append(
            {
                "action_type": action["action_type"],
                "target": target,
                "status": execution_status,
                "approval_id": decision["approval_id"],
                "approved_by": decision["approved_by"],
            }
        )

    return {
        "status": "running",
        "current_stage": "response_executed",
        "executed_actions": executed,
        "audit_events": [
            {
                **audit_event(
                    state,
                    stage="response_execution",
                    event="response_actions_executed",
                ),
                "approval_id": decision["approval_id"],
                "approved_by": decision["approved_by"],
                "action_count": len(approved_actions),
            }
        ],
    }
