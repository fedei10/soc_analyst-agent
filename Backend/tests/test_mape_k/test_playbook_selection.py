import pytest

from app.mape_k.playbooks import PlaybookPlanner, PlaybookSelection
from app.mape_k.policy import PolicyEngine
from app.mape_k.schemas import (
    ActionType,
    Diagnosis,
    EvidenceReference,
    IncidentWorkflowState,
)


EVIDENCE_ID = "EV-ABCDEF123456"


def _state(diagnosis: Diagnosis) -> IncidentWorkflowState:
    return IncidentWorkflowState(
        incident_id="INC-PLAYBOOK",
        investigation_id="INV-PLAYBOOK",
        alert_id="alert-1",
        agent_id="004",
        evidence=[
            EvidenceReference(
                evidence_id=EVIDENCE_ID,
                source_type="wazuh_alert",
                source_ref="wazuh:alert:alert-1",
                summary="SSH evidence",
                content_hash="c" * 64,
            )
        ],
        evidence_version="version-1",
        diagnosis=diagnosis,
    )


def _diagnosis(incident_type: str, **entities) -> Diagnosis:
    return Diagnosis(
        incident_type=incident_type,
        summary="Summary",
        root_cause="Root cause",
        evidence_ids=[EVIDENCE_ID],
        affected_entities=entities,
        confidence=0.95,
    )


class StubLLM:
    def __init__(self, selection):
        self.selection = selection
        self.calls = 0

    def invoke_structured(self, _schema, _messages):
        self.calls += 1
        return self.selection, {"input_tokens": 1, "output_tokens": 1}


def test_catalogue_match_needs_no_model():
    llm = StubLLM(None)
    selection = PlaybookPlanner(llm=llm).plan(
        _state(_diagnosis("ssh_password_spraying", source_ip="203.0.113.9"))
    )

    assert selection.selected_by == "catalogue"
    assert selection.plan.playbook_id == "ssh-password-spray-v1"
    assert selection.plan.actions[0].action_type == ActionType.BLOCK_IP
    assert llm.calls == 0


def test_credential_compromise_disables_the_account_not_the_ip():
    selection = PlaybookPlanner(llm=StubLLM(None)).plan(
        _state(
            _diagnosis(
                "ssh_success_after_failures",
                source_ip="203.0.113.9",
                users=["backup-svc"],
            )
        )
    )

    plan = selection.plan
    assert plan.playbook_id == "credential-compromise-v1"
    assert plan.actions[0].action_type == ActionType.DISABLE_USER
    assert plan.actions[0].target == "backup-svc"
    assert plan.rollback_actions[0].action_type == ActionType.ENABLE_USER
    assert plan.required_role == "soc_l3"


def test_ambiguous_account_set_returns_advisory_instead_of_guessing():
    selection = PlaybookPlanner(llm=StubLLM(None)).plan(
        _state(
            _diagnosis(
                "ssh_success_after_failures",
                users=["alice", "bob"],
            )
        )
    )

    assert selection.plan is None
    assert selection.selected_by == "advisory"
    assert selection.advisory_plan is not None
    assert selection.advisory_plan.executable is False
    assert selection.advisory_plan.human_review_required is True


def test_model_maps_an_unknown_incident_type_onto_a_published_playbook():
    llm = StubLLM(
        PlaybookSelection(
            applies=True,
            playbook_id="ssh-bruteforce-v1",
            canonical_incident_type="ssh_brute_force",
            rationale="Repeated SSH password guessing under another name.",
        )
    )

    selection = PlaybookPlanner(llm=llm).plan(
        _state(_diagnosis("ssh_credential_stuffing", source_ip="203.0.113.9"))
    )

    assert llm.calls == 1
    assert selection.selected_by == "model"
    assert selection.canonical_incident_type == "ssh_brute_force"
    assert selection.plan.playbook_id == "ssh-bruteforce-v1"


def test_model_declining_returns_attack_specific_advisory():
    llm = StubLLM(
        PlaybookSelection(
            applies=False,
            rationale="Different problem entirely.",
            advisory_summary="Investigate suspected outbound data theft.",
            investigation_steps=[
                "Correlate outbound transfers with process activity."
            ],
            containment_recommendations=["Validate and isolate the affected host."],
        )
    )

    selection = PlaybookPlanner(llm=llm).plan(
        _state(_diagnosis("data_exfiltration", source_ip="203.0.113.9"))
    )

    advisory = selection.advisory_plan
    assert selection.plan is None
    assert selection.selected_by == "advisory"
    assert selection.usage["input_tokens"] == 1
    assert advisory is not None
    assert advisory.diagnosis_type == "data_exfiltration"
    assert advisory.investigation_steps == [
        "Correlate outbound transfers with process activity."
    ]
    assert advisory.executable is False
    assert advisory.evidence_ids == [EVIDENCE_ID]


def test_model_cannot_invent_an_unregistered_playbook():
    llm = StubLLM(
        PlaybookSelection(
            applies=True,
            playbook_id="wipe-the-host-v9",
            canonical_incident_type="ssh_brute_force",
        )
    )

    selection = PlaybookPlanner(llm=llm).plan(
        _state(_diagnosis("something_novel", source_ip="203.0.113.9"))
    )

    assert selection.plan is None
    assert selection.advisory_plan is not None
    assert selection.advisory_plan.executable is False
    assert "not registered" in (selection.rationale or "")


def test_model_selected_plan_still_satisfies_the_policy_engine():
    """The model may choose, but the deterministic gate still decides."""

    llm = StubLLM(
        PlaybookSelection(
            applies=True,
            playbook_id="ssh-bruteforce-v1",
            canonical_incident_type="ssh_brute_force",
        )
    )
    state = _state(_diagnosis("ssh_credential_stuffing", source_ip="203.0.113.9"))
    selection = PlaybookPlanner(llm=llm).plan(state)

    # Policy re-validates against the canonicalized diagnosis, exactly as
    # plan_node rewrites it before the policy gate runs.
    canonical = state.diagnosis.model_copy(
        update={"incident_type": selection.canonical_incident_type}
    )
    decision = PolicyEngine().evaluate(
        state.model_copy(
            update={
                "diagnosis": canonical,
                "remediation_plan": selection.plan,
            }
        )
    )

    assert decision.allowed is True
    assert decision.approval_required is True
    assert decision.required_role == "soc_l2"


def test_account_targets_reject_shell_metacharacters():
    from pydantic import ValidationError

    from app.mape_k.schemas import RemediationAction

    with pytest.raises(ValidationError):
        RemediationAction(
            action_id="ACT-BAD",
            action_type=ActionType.DISABLE_USER,
            target="alice; rm -rf /",
            risk_level=2,
            evidence_refs=[EVIDENCE_ID],
        )


def test_executor_dispatches_the_registered_active_response_command():
    """A new action type is only executable once it is also given an adapter."""

    from app.mape_k.executor import ACTIVE_RESPONSE_COMMANDS, RestrictedExecutor
    from app.mape_k.schemas import RemediationAction

    class RecordingResponder:
        def __init__(self):
            self.calls = []

        def run_active_response(self, **kwargs):
            self.calls.append(kwargs)
            return {"accepted": True}

    responder = RecordingResponder()
    executor = RestrictedExecutor(responder=responder)
    state = _state(_diagnosis("ssh_success_after_failures", users=["backup-svc"]))

    disable = RemediationAction(
        action_id="ACT-DISABLE",
        action_type=ActionType.DISABLE_USER,
        target="backup-svc",
        risk_level=2,
        evidence_refs=[EVIDENCE_ID],
    )
    executor._execute_real(disable, state)

    assert responder.calls[0]["command"] == "disable-account"
    assert responder.calls[0]["arguments"] == ["backup-svc"]
    assert responder.calls[0]["agent_id"] == "004"

    # Registered in the action catalogue but with no adapter entry: planning
    # it is possible, executing it is not.
    orphan = RemediationAction(
        action_id="ACT-ORPHAN",
        action_type=ActionType.ISOLATE_HOST,
        target="host-1",
        risk_level=3,
        evidence_refs=[EVIDENCE_ID],
    )
    with pytest.raises(ValueError):
        executor._execute_real(orphan, state)

    assert ActionType.ISOLATE_HOST not in {
        key for key in ACTIVE_RESPONSE_COMMANDS
    }
    assert len(responder.calls) == 1
