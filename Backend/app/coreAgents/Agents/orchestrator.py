"""Compatibility imports for the canonical orchestration package."""

from app.coreAgents.orchestration.executor import execute_response
from app.coreAgents.orchestration.graph import (
    create_investigation_graph,
    investigation_config,
)
from app.coreAgents.orchestration.nodes import (
    create_final_report,
    handle_failure,
    initialize_investigation,
    load_wazuh_alert,
    mark_awaiting_approval,
    mark_response_approved,
    normalize_alert,
    prepare_actions,
    request_human_approval,
    run_l1,
    run_l2,
    run_l3,
)
from app.coreAgents.orchestration.routing import (
    route_after_l1,
    route_after_l2,
    route_after_action_policy,
    route_after_approval,
    route_after_step,
    requires_approval,
)

__all__ = [
    "create_final_report",
    "create_investigation_graph",
    "execute_response",
    "handle_failure",
    "initialize_investigation",
    "investigation_config",
    "load_wazuh_alert",
    "mark_awaiting_approval",
    "mark_response_approved",
    "normalize_alert",
    "prepare_actions",
    "request_human_approval",
    "requires_approval",
    "route_after_action_policy",
    "route_after_approval",
    "route_after_l1",
    "route_after_l2",
    "route_after_step",
    "run_l1",
    "run_l2",
    "run_l3",
]
