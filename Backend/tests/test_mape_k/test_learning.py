from datetime import UTC, datetime, timedelta

from app.mape_k.learning import incident_priors
from app.mape_k.schemas import IncidentWorkflowState


def _state(**overrides):
    payload = {
        "incident_id": "INC-LEARN",
        "investigation_id": "INV-LEARN",
        "alert_id": "alert-1",
        "agent_id": "004",
        "findings": [
            {
                "finding_id": "FND-1",
                "event_type": "ssh_login_failure",
                "attack_family": "credential_access",
            }
        ],
    }
    payload.update(overrides)
    return IncidentWorkflowState(**payload)


class FakeFindings:
    def __init__(self, records, feedback):
        self.records = records
        self.feedback = feedback

    def list(self, *, organization_id, limit, **_kwargs):
        return self.records[:limit]

    def list_feedback(self, finding_id, *, organization_id):
        return self.feedback.get(finding_id, [])


class FakeMemory:
    def __init__(self, counts):
        self.counts = counts

    def count_alerts_since(self, _since, *, agent_id=None, min_level=0):
        return self.counts.get((agent_id, min_level), 0)


def _feedback(disposition, *, days_ago=1, notes=None):
    return {
        "disposition": disposition,
        "notes": notes,
        "created_at": datetime.now(UTC) - timedelta(days=days_ago),
    }


def test_benign_history_becomes_a_prior():
    findings = FakeFindings(
        records=[{"finding_id": "FND-OLD", "event_type": "ssh_login_failure"}],
        feedback={
            "FND-OLD": [
                _feedback("confirmed_benign", notes="Backup job, expected."),
                _feedback("confirmed_benign"),
                _feedback("confirmed_malicious"),
            ]
        },
    )

    priors = incident_priors(
        _state(),
        finding_repository=findings,
        memory_repository=FakeMemory({}),
    )

    feedback = priors["analyst_feedback"]
    assert feedback["total_dispositions"] == 3
    assert feedback["benign_rate"] == round(2 / 3, 3)
    assert feedback["malicious_rate"] == round(1 / 3, 3)
    assert feedback["analyst_notes"] == ["Backup job, expected."]


def test_unrelated_findings_are_not_joined():
    findings = FakeFindings(
        records=[{"finding_id": "FND-X", "event_type": "malware_detected"}],
        feedback={"FND-X": [_feedback("confirmed_malicious")]},
    )

    priors = incident_priors(
        _state(),
        finding_repository=findings,
        memory_repository=FakeMemory({}),
    )

    assert "analyst_feedback" not in priors


def test_feedback_outside_the_lookback_window_is_ignored():
    findings = FakeFindings(
        records=[{"finding_id": "FND-OLD", "event_type": "ssh_login_failure"}],
        feedback={"FND-OLD": [_feedback("confirmed_benign", days_ago=400)]},
    )

    priors = incident_priors(
        _state(),
        finding_repository=findings,
        memory_repository=FakeMemory({}),
    )

    assert "analyst_feedback" not in priors


def test_prevalence_gives_noise_a_denominator():
    priors = incident_priors(
        _state(),
        finding_repository=FakeFindings([], {}),
        memory_repository=FakeMemory({("004", 0): 600, ("004", 10): 12}),
    )

    prevalence = priors["asset_prevalence"]
    assert prevalence["alerts_in_window"] == 600
    assert prevalence["high_level_alerts_in_window"] == 12
    assert prevalence["alerts_per_day"] > 0


def test_repository_failure_degrades_to_no_priors():
    class Broken:
        def list(self, **_kwargs):
            raise RuntimeError("database is down")

        def count_alerts_since(self, *_args, **_kwargs):
            raise RuntimeError("database is down")

    # A priors outage must never fail the investigation.
    assert incident_priors(
        _state(),
        finding_repository=Broken(),
        memory_repository=Broken(),
    ) == {}


class FakeInvestigations:
    def __init__(self, snapshots):
        self.snapshots = snapshots

    def list_snapshots(self, *, organization_id, limit, **_kwargs):
        return self.snapshots[:limit]


def _past(investigation_id, *, decision=None, verification=None, rollback=None):
    return {
        "investigation_id": investigation_id,
        "updated_at": datetime.now(UTC).isoformat(),
        "findings": [
            {"event_type": "ssh_login_failure", "attack_family": "credential_access"}
        ],
        "approval_decision": {"decision": decision} if decision else None,
        "verification": {"outcome": verification} if verification else None,
        "rollback": rollback,
    }


def test_outcome_priors_summarize_past_decisions():
    priors = incident_priors(
        _state(),
        finding_repository=FakeFindings(records=[], feedback={}),
        memory_repository=FakeMemory({}),
        investigation_repository=FakeInvestigations(
            [
                _past("INV-A", decision="reject"),
                _past("INV-B", decision="reject"),
                _past("INV-C", decision="approve", verification="failed"),
                _past("INV-D", rollback={"status": "done"}),
            ]
        ),
    )

    outcomes = priors["past_outcomes"]
    assert outcomes["similar_investigations"] == 4
    assert outcomes["approval_decisions"] == {"reject": 2, "approve": 1}
    assert outcomes["verification_outcomes"] == {"failed": 1}
    assert outcomes["rollbacks"] == 1


def test_outcome_priors_skip_the_current_investigation_and_thin_history():
    priors = incident_priors(
        _state(),
        finding_repository=FakeFindings(records=[], feedback={}),
        memory_repository=FakeMemory({}),
        investigation_repository=FakeInvestigations(
            [
                _past("INV-LEARN", decision="approve"),
                _past("INV-A", decision="approve"),
            ]
        ),
    )
    assert "past_outcomes" not in priors
