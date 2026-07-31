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


def _diag(**kw):
    from app.mape_k.schemas import Diagnosis

    payload = {
        "incident_type": "ssh_brute_force",
        "summary": "s",
        "root_cause": "r",
        "evidence_ids": ["EV-1"],
        "confidence": 0.96,
    }
    payload.update(kw)
    return Diagnosis(**payload)


def _result(evidence_type, status, required=True):
    from app.mape_k.schemas import EvidenceCollectionResult

    return EvidenceCollectionResult(
        evidence_type=evidence_type,
        collector="c",
        required=required,
        status=status,
        source="s",
    )


def test_unavailable_collector_yields_telemetry_unavailable_not_confidence():
    """A collector that never ran must not read as 'nothing found'."""
    from app.mape_k.schemas import DiagnosisVerdict, assess_evidence

    assessed = assess_evidence(
        _diag(),
        [
            _result("auth_timeline", "collected"),
            _result("session_archives", "not_configured"),
        ],
        completeness_threshold=0.8,
    )
    assert assessed.verdict == DiagnosisVerdict.TELEMETRY_UNAVAILABLE
    assert assessed.telemetry_gaps == ["session_archives"]
    assert assessed.evidence_completeness == 0.5


def test_not_found_is_answered_evidence_that_weakens_the_hypothesis():
    """'Searched and found nothing' is a real answer - and an unfavourable one.

    It still counts toward completeness (the collector ran), but the predicted
    artefact is absent, so it must cost the verdict a band rather than being
    silently folded into supporting evidence.
    """
    from app.mape_k.schemas import DiagnosisVerdict, assess_evidence

    assessed = assess_evidence(
        _diag(),
        [
            _result("auth_timeline", "collected"),
            _result("post_login_activity", "not_found"),
        ],
        completeness_threshold=0.8,
    )
    assert assessed.evidence_completeness == 1.0
    assert assessed.telemetry_gaps == []
    assert assessed.contradicting_requirements == ["post_login_activity"]
    # 0.96 confidence would otherwise be CONFIRMED_MALICIOUS.
    assert assessed.verdict == DiagnosisVerdict.LIKELY_MALICIOUS


def test_remediation_blocked_by_gaps_and_low_completeness():
    from app.mape_k.schemas import assess_evidence, remediation_allowed

    complete = assess_evidence(
        _diag(),
        [_result("auth_timeline", "collected")],
        completeness_threshold=0.8,
    )
    gapped = assess_evidence(
        _diag(),
        [
            _result("auth_timeline", "collected"),
            _result("session_archives", "collector_unavailable"),
        ],
        completeness_threshold=0.8,
    )
    kwargs = {
        "confidence_threshold": 0.8,
        "completeness_threshold": 0.8,
    }
    assert remediation_allowed(complete, **kwargs) is True
    assert remediation_allowed(gapped, **kwargs) is False
    # High confidence must not rescue missing telemetry.
    assert gapped.confidence == 0.96


def test_low_confidence_stays_suspicious_and_cannot_remediate():
    from app.mape_k.schemas import DiagnosisVerdict, assess_evidence, remediation_allowed

    assessed = assess_evidence(
        _diag(confidence=0.6),
        [_result("auth_timeline", "collected")],
        completeness_threshold=0.8,
    )
    assert assessed.verdict == DiagnosisVerdict.SUSPICIOUS
    assert (
        remediation_allowed(
            assessed,
            confidence_threshold=0.8,
            completeness_threshold=0.8,
        )
        is False
    )


def test_deferred_evidence_requests_another_pass_but_is_not_a_gap():
    """minimum_pass requirements must trigger recollection, not escalation."""
    from app.mape_k.schemas import DiagnosisVerdict, assess_evidence

    assessed = assess_evidence(
        _diag(),
        [
            _result("auth_timeline", "collected"),
            _result("session_archives", "deferred"),
        ],
        completeness_threshold=0.8,
    )
    assert assessed.verdict == DiagnosisVerdict.INSUFFICIENT_EVIDENCE
    assert assessed.telemetry_gaps == []
    assert assessed.needs_more_evidence is True


def test_permanent_gap_does_not_request_another_pass():
    """Re-collecting cannot conjure telemetry that is not configured."""
    from app.mape_k.schemas import DiagnosisVerdict, assess_evidence

    assessed = assess_evidence(
        _diag(),
        [
            _result("auth_timeline", "collected"),
            _result("session_archives", "not_configured"),
        ],
        completeness_threshold=0.8,
    )
    assert assessed.verdict == DiagnosisVerdict.TELEMETRY_UNAVAILABLE
    assert assessed.needs_more_evidence is False


def test_factual_capability_cannot_reach_a_malicious_verdict():
    """A confirmed CVE is a confirmed fact, not a confirmed compromise."""
    from app.mape_k.capabilities import capability_for_incident
    from app.mape_k.schemas import (
        DiagnosisVerdict,
        ObservedCondition,
        assess_evidence,
    )

    diagnosis = _diag(
        incident_type="high_risk_vulnerability_exposure", confidence=0.9
    )
    capability = capability_for_incident(diagnosis.incident_type)
    assert capability is not None and capability.threat_bearing is False

    assessed = assess_evidence(
        diagnosis,
        [_result("vulnerability_identity", "collected")],
        completeness_threshold=0.8,
        threat_bearing=capability.threat_bearing,
    )
    # The observation is established; the threat claim is not.
    assert assessed.observed_condition == ObservedCondition.CONFIRMED
    assert assessed.verdict == DiagnosisVerdict.SUSPICIOUS


def test_threat_bearing_capability_still_reaches_malicious():
    """The cap must not blunt genuine attack-pattern capabilities."""
    from app.mape_k.capabilities import capability_for_incident
    from app.mape_k.schemas import DiagnosisVerdict, assess_evidence

    diagnosis = _diag(
        incident_type="command_and_control_activity", confidence=0.9
    )
    capability = capability_for_incident(diagnosis.incident_type)
    assert capability is not None and capability.threat_bearing is True

    assessed = assess_evidence(
        diagnosis,
        [_result("network_destination", "collected")],
        completeness_threshold=0.8,
        threat_bearing=capability.threat_bearing,
    )
    assert assessed.verdict == DiagnosisVerdict.CONFIRMED_MALICIOUS


def test_contradicting_evidence_blocks_remediation():
    """Enough unfavourable answers must drop below the remediation bar."""
    from app.mape_k.schemas import assess_evidence, remediation_allowed

    assessed = assess_evidence(
        _diag(),
        [
            _result("auth_timeline", "collected"),
            _result("post_login_activity", "not_found"),
            _result("process_inventory", "not_found"),
        ],
        completeness_threshold=0.8,
    )
    assert len(assessed.contradicting_requirements) == 2
    assert (
        remediation_allowed(
            assessed,
            confidence_threshold=0.8,
            completeness_threshold=0.8,
        )
        is False
    )
