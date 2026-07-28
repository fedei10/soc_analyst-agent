"""Code-owned registries for actions, verification checks, and playbooks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.mape_k.schemas import ActionType, RemediationPlan


ApprovalRole = Literal["soc_l2", "soc_l3", "security_admin"]
CheckCategory = Literal["security", "health"]

ROLE_LEVEL: dict[str, int] = {
    "soc_l2": 2,
    "soc_l3": 3,
    "security_admin": 4,
}


@dataclass(frozen=True)
class ActionRegistration:
    action_type: ActionType
    executor_key: str
    minimum_role: ApprovalRole
    rollback_action_type: ActionType | None = None
    allowed_parameter_keys: frozenset[str] = frozenset()
    mutating: bool = True


class ActionRegistry:
    def __init__(self, *, version: str) -> None:
        self.version = version
        self._items: dict[ActionType, ActionRegistration] = {}

    def register(self, item: ActionRegistration) -> None:
        if item.action_type in self._items:
            raise ValueError(f"Action {item.action_type} is already registered.")
        self._items[item.action_type] = item

    def get(self, action_type: ActionType) -> ActionRegistration | None:
        return self._items.get(action_type)

    def require(self, action_type: ActionType) -> ActionRegistration:
        item = self.get(action_type)
        if item is None:
            raise LookupError(f"Action {action_type} has no registered executor.")
        return item

    def minimum_role(self, action_types: list[ActionType]) -> ApprovalRole | None:
        registrations = [self.require(action_type) for action_type in action_types]
        if not registrations:
            return None
        return max(
            (item.minimum_role for item in registrations),
            key=lambda role: ROLE_LEVEL[role],
        )

    def forward_action_for(
        self,
        rollback_action_type: ActionType,
    ) -> ActionType | None:
        for item in self._items.values():
            if item.rollback_action_type == rollback_action_type:
                return item.action_type
        return None


@dataclass(frozen=True)
class VerificationCheckRegistration:
    name: str
    category: CheckCategory
    handler_name: str
    required: bool = True


class VerificationCheckRegistry:
    def __init__(self, *, version: str) -> None:
        self.version = version
        self._items: dict[str, VerificationCheckRegistration] = {}

    def register(self, item: VerificationCheckRegistration) -> None:
        if item.name in self._items:
            raise ValueError(f"Verification check {item.name} is already registered.")
        self._items[item.name] = item

    def get(self, name: str) -> VerificationCheckRegistration | None:
        return self._items.get(name)

    def require(self, name: str) -> VerificationCheckRegistration:
        item = self.get(name)
        if item is None:
            raise LookupError(f"Verification check {name} is not registered.")
        return item


@dataclass(frozen=True)
class PlaybookRegistration:
    playbook_id: str
    version: str
    incident_types: frozenset[str]
    action_types: frozenset[ActionType]
    rollback_action_types: frozenset[ActionType]
    security_checks: frozenset[str]
    health_checks: frozenset[str]
    action_count: int
    rollback_action_count: int


class PlaybookRegistry:
    def __init__(
        self,
        *,
        actions: ActionRegistry,
        checks: VerificationCheckRegistry,
    ) -> None:
        self.actions = actions
        self.checks = checks
        self._items: dict[tuple[str, str], PlaybookRegistration] = {}

    def register(self, item: PlaybookRegistration) -> None:
        key = (item.playbook_id, item.version)
        if key in self._items:
            raise ValueError(
                f"Playbook {item.playbook_id}@{item.version} is already registered."
            )
        for action_type in item.action_types | item.rollback_action_types:
            self.actions.require(action_type)
        for check_name in item.security_checks | item.health_checks:
            self.checks.require(check_name)
        self._items[key] = item

    def get(self, playbook_id: str, version: str) -> PlaybookRegistration | None:
        return self._items.get((playbook_id, version))

    def require(self, playbook_id: str, version: str) -> PlaybookRegistration:
        item = self.get(playbook_id, version)
        if item is None:
            raise LookupError(f"Playbook {playbook_id}@{version} is not registered.")
        return item

    def known_incident_types(self) -> set[str]:
        """Every diagnosis label that some registered playbook can act on."""

        return {
            incident_type
            for item in self._items.values()
            for incident_type in item.incident_types
        }

    def for_incident_type(self, incident_type: str) -> list[PlaybookRegistration]:
        """Registered playbooks that publish support for this diagnosis."""

        return [
            item
            for item in self._items.values()
            if incident_type in item.incident_types
        ]

    def validate_plan(
        self,
        plan: RemediationPlan,
        *,
        diagnosis_type: str | None = None,
    ) -> None:
        registration = self.require(plan.playbook_id, plan.playbook_version)
        if diagnosis_type and diagnosis_type not in registration.incident_types:
            raise ValueError("Playbook does not support the diagnosed incident type.")

        action_ids = [action.action_id for action in plan.actions]
        rollback_ids = [action.action_id for action in plan.rollback_actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("Forward action IDs must be unique.")
        if len(rollback_ids) != len(set(rollback_ids)):
            raise ValueError("Rollback action IDs must be unique.")
        if len(plan.actions) != registration.action_count:
            raise ValueError("Plan action count does not match the published playbook.")
        if len(plan.rollback_actions) != registration.rollback_action_count:
            raise ValueError(
                "Plan rollback count does not match the published playbook."
            )
        if len(plan.security_checks) != len(set(plan.security_checks)):
            raise ValueError("Plan security checks must be unique.")
        if len(plan.health_checks) != len(set(plan.health_checks)):
            raise ValueError("Plan health checks must be unique.")

        action_types = {action.action_type for action in plan.actions}
        rollback_types = {action.action_type for action in plan.rollback_actions}
        if not action_types <= registration.action_types:
            raise ValueError("Plan contains an action not published by this playbook.")
        if not rollback_types <= registration.rollback_action_types:
            raise ValueError("Plan contains an unpublished rollback action.")
        if set(plan.security_checks) != set(registration.security_checks):
            raise ValueError("Plan security checks do not match the published playbook.")
        if set(plan.health_checks) != set(registration.health_checks):
            raise ValueError("Plan health checks do not match the published playbook.")

        for action in plan.actions:
            action_registration = self.actions.require(action.action_type)
            if not set(action.parameters) <= action_registration.allowed_parameter_keys:
                raise ValueError(
                    f"Action {action.action_id} has unpublished parameters."
                )
            expected_rollback = action_registration.rollback_action_type
            if expected_rollback is None:
                continue
            matches = [
                rollback
                for rollback in plan.rollback_actions
                if rollback.action_type == expected_rollback
                and rollback.target == action.target
                and rollback.parameters.get("reverts_action_id") == action.action_id
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"Action {action.action_id} must have one exact rollback action."
                )


ACTION_CATALOGUE_VERSION = "1.0"
VERIFICATION_CATALOGUE_VERSION = "1.0"

ACTION_REGISTRY = ActionRegistry(version=ACTION_CATALOGUE_VERSION)
ACTION_REGISTRY.register(
    ActionRegistration(
        action_type=ActionType.BLOCK_IP,
        executor_key="wazuh_active_response.firewall_drop",
        minimum_role="soc_l2",
        rollback_action_type=ActionType.UNBLOCK_IP,
        allowed_parameter_keys=frozenset({"scope"}),
    )
)
ACTION_REGISTRY.register(
    ActionRegistration(
        action_type=ActionType.UNBLOCK_IP,
        executor_key="wazuh_active_response.firewall_drop_delete",
        minimum_role="soc_l2",
        allowed_parameter_keys=frozenset({"reverts_action_id"}),
    )
)
# Locking an account cuts off a human being's access, so it sits a role
# above an IP block even though both are reversible.
ACTION_REGISTRY.register(
    ActionRegistration(
        action_type=ActionType.DISABLE_USER,
        executor_key="wazuh_active_response.disable_account",
        minimum_role="soc_l3",
        rollback_action_type=ActionType.ENABLE_USER,
        allowed_parameter_keys=frozenset({"scope"}),
    )
)
ACTION_REGISTRY.register(
    ActionRegistration(
        action_type=ActionType.ENABLE_USER,
        executor_key="wazuh_active_response.disable_account_delete",
        minimum_role="soc_l3",
        allowed_parameter_keys=frozenset({"reverts_action_id"}),
    )
)

VERIFICATION_CHECK_REGISTRY = VerificationCheckRegistry(
    version=VERIFICATION_CATALOGUE_VERSION
)
for _check in (
    VerificationCheckRegistration(
        name="ssh_attempts_stopped",
        category="security",
        handler_name="_verify_ssh_attempts_stopped",
    ),
    VerificationCheckRegistration(
        name="no_new_critical_alerts",
        category="security",
        handler_name="_verify_no_new_critical_alerts",
    ),
    VerificationCheckRegistration(
        name="wazuh_agent_connected",
        category="health",
        handler_name="_verify_wazuh_agent_connected",
    ),
    VerificationCheckRegistration(
        name="ssh_port_listening",
        category="health",
        handler_name="_verify_ssh_port_listening",
    ),
    VerificationCheckRegistration(
        name="management_ssh_reachable",
        category="health",
        handler_name="_verify_management_ssh_reachable",
        required=False,
    ),
    VerificationCheckRegistration(
        name="no_new_auth_success_for_user",
        category="security",
        handler_name="_verify_no_new_auth_success_for_user",
    ),
):
    VERIFICATION_CHECK_REGISTRY.register(_check)

PLAYBOOK_REGISTRY = PlaybookRegistry(
    actions=ACTION_REGISTRY,
    checks=VERIFICATION_CHECK_REGISTRY,
)
_SSH_HEALTH_CHECKS = frozenset(
    {
        "wazuh_agent_connected",
        "ssh_port_listening",
        "management_ssh_reachable",
    }
)

PLAYBOOK_REGISTRY.register(
    PlaybookRegistration(
        playbook_id="ssh-bruteforce-v1",
        version="1.0",
        incident_types=frozenset({"ssh_brute_force"}),
        action_types=frozenset({ActionType.BLOCK_IP}),
        rollback_action_types=frozenset({ActionType.UNBLOCK_IP}),
        security_checks=frozenset(
            {"ssh_attempts_stopped", "no_new_critical_alerts"}
        ),
        health_checks=_SSH_HEALTH_CHECKS,
        action_count=1,
        rollback_action_count=1,
    )
)
# Spraying is the same containment as brute force - one source, many
# accounts - but it stays a separate published playbook so an approver sees
# which detection actually fired.
PLAYBOOK_REGISTRY.register(
    PlaybookRegistration(
        playbook_id="ssh-password-spray-v1",
        version="1.0",
        incident_types=frozenset({"ssh_password_spraying"}),
        action_types=frozenset({ActionType.BLOCK_IP}),
        rollback_action_types=frozenset({ActionType.UNBLOCK_IP}),
        security_checks=frozenset(
            {"ssh_attempts_stopped", "no_new_critical_alerts"}
        ),
        health_checks=_SSH_HEALTH_CHECKS,
        action_count=1,
        rollback_action_count=1,
    )
)
# A login that succeeded after repeated failures is an account problem, not
# a network one: blocking the source leaves working credentials in play.
PLAYBOOK_REGISTRY.register(
    PlaybookRegistration(
        playbook_id="credential-compromise-v1",
        version="1.0",
        incident_types=frozenset({"ssh_success_after_failures"}),
        action_types=frozenset({ActionType.DISABLE_USER}),
        rollback_action_types=frozenset({ActionType.ENABLE_USER}),
        security_checks=frozenset(
            {"no_new_auth_success_for_user", "no_new_critical_alerts"}
        ),
        health_checks=frozenset(
            {"wazuh_agent_connected", "management_ssh_reachable"}
        ),
        action_count=1,
        rollback_action_count=1,
    )
)
