from types import SimpleNamespace

from app.coreAgents.orchestration.verifier import verify_response


def state(action_type, target):
    return {
        "investigation_id": "INV-1",
        "executed_actions": [{
            "action_id": "ACT-1",
            "action_type": action_type,
            "target": target,
            "status": "executed",
        }],
    }


class SystemVerifier:
    def __init__(self, active):
        self.active = active

    def is_service_active(self, service_name):
        return self.active


class Gateway:
    def __init__(self, status):
        self.status = status

    def get_agent_summary(self, agent_id):
        return SimpleNamespace(status=self.status)


def test_service_restart_is_verified_from_actual_service_state():
    update = verify_response(
        state("restart_service", "wazuh-agent.service"),
        system_executor=SystemVerifier(True),
    )

    assert update["executed_actions"][0]["status"] == "verified"
    assert update["verification_results"][0]["code"] == "SERVICE_ACTIVE"


def test_inactive_agent_fails_post_action_verification():
    update = verify_response(
        state("restart_agent", "001"),
        gateway=Gateway("disconnected"),
    )

    assert update["executed_actions"][0]["status"] == "verification_failed"
    assert update["verification_results"][0]["code"] == "AGENT_NOT_ACTIVE"


def test_block_ip_is_not_falsely_reported_as_verified():
    update = verify_response(state("block_ip", "192.0.2.10"))

    assert update["executed_actions"][0]["status"] == "verification_pending"
    assert update["verification_results"][0]["code"] == (
        "ACTIVE_RESPONSE_CONFIRMATION_REQUIRED"
    )
