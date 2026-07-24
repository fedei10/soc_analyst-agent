from app.coreAgents.orchestration.routing import route_after_l1, route_after_l2


def l1_result(**overrides):
    result = {
        "summary": "Alert triage completed",
        "classification": "suspicious",
        "severity": "low",
        "confidence": 0.95,
        "evidence_refs": ["alert:alert-1"],
    }
    result.update(overrides)
    return result


def l2_result(**overrides):
    result = {
        "summary": "Investigation completed",
        "severity": "medium",
        "confidence": 0.9,
        "evidence_refs": ["alert:alert-1"],
    }
    result.update(overrides)
    return result


def test_low_risk_alert_stops_after_l1():
    state = {"l1_result": l1_result()}

    assert route_after_l1(state) == "final_report"


def test_medium_alert_reaches_l2():
    state = {"l1_result": l1_result(severity="medium")}

    assert route_after_l1(state) == "l2_investigation"


def test_low_confidence_alert_reaches_l2():
    state = {"l1_result": l1_result(confidence=0.69)}

    assert route_after_l1(state) == "l2_investigation"


def test_high_confidence_false_positive_stops_after_l1():
    state = {
        "l1_result": l1_result(
            classification="false_positive",
            false_positive=True,
            confidence=0.90,
        )
    }

    assert route_after_l1(state) == "final_report"


def test_high_severity_alert_reaches_l3_after_l2():
    state = {"l2_result": l2_result(severity="high")}

    assert route_after_l2(state) == "l3_analysis"


def test_detection_gap_reaches_l3():
    state = {"l2_result": l2_result(detection_gap=True)}

    assert route_after_l2(state) == "l3_analysis"


def test_resolved_medium_alert_stops_after_l2():
    state = {"l2_result": l2_result()}

    assert route_after_l2(state) == "final_report"


def test_missing_agent_results_fail_closed():
    assert route_after_l1({}) == "failed"
    assert route_after_l2({}) == "failed"


def test_invalid_agent_results_fail_closed():
    assert route_after_l1({"l1_result": {"severity": "extreme"}}) == "failed"
    assert route_after_l2({"l2_result": {"confidence": 4}}) == "failed"
