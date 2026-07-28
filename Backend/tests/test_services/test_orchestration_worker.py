from app.workers.orchestration import run_cycle


class FakeRepository:
    durable = True

    def list_response_action_organizations(self):
        return ["user-1"]


class FakeService:
    def __init__(self):
        self.repository = FakeRepository()

    def process_background_once(self):
        return {
            "candidates": 1,
            "processed": 1,
            "results": [
                {
                    "investigation_id": "INV-1",
                    "operation": "investigation",
                    "status": "waiting_approval",
                }
            ],
        }


def test_worker_cycle_runs_orchestration_and_safe_disabled_recovery():
    result = run_cycle(FakeService())

    assert result["orchestration"]["processed"] == 1
    assert result["recoveries"] == [
        {
            "organization_id": "user-1",
            "status": "disabled",
            "reason": "real_response_execution_is_disabled",
            "claimed": 0,
            "results": [],
        }
    ]
