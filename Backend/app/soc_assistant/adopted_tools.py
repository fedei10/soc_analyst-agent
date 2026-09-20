"""Prototype hunting ideas adapted to TSAGE's bounded, read-only gateway."""

from datetime import datetime, timedelta
from typing import Any, Callable, Literal

from langchain_core.tools import tool

from app.config import settings
from app.services.wazuh.gateway import WazuhGateway


def build_hunting_tools(
    gateway: WazuhGateway, *, clip: Callable[[Any], str], bounds_factory: Callable[[], Any],
) -> list[Any]:
    """Server-owned clients and serializers; no model-provided paths or DSL."""
    cap = max(1, min(168, settings.SOC_ANALYST_MAX_QUERY_HOURS))

    @tool
    def sca_policy_summary(agent_id: str, limit: int = 20, offset: int = 0) -> str:
        """SCA policy IDs, scores and scan dates for one agent. Use the policy ID
        with sca_failed_checks for actual hardening gaps and remediation text."""
        bounds = bounds_factory()
        result = gateway.get_sca_evidence(
            agent_id=agent_id, limit=bounds.integer("limit", limit, low=1, high=50),
            offset=bounds.integer("offset", offset, low=0, high=5000),
        )
        return clip(result | bounds.envelope())

    @tool
    def sca_failed_checks(agent_id: str, policy_id: str, limit: int = 10, offset: int = 0) -> str:
        """Failed SCA checks with native title, rationale, remediation and compliance.
        Findings reflect the scan, not compromise; suggested changes are not executed.
        Preserve check evidence IDs and paginate when results are partial."""
        bounds = bounds_factory()
        result = gateway.get_sca_evidence(
            agent_id=agent_id, policy_id=policy_id,
            limit=bounds.integer("limit", limit, low=1, high=50),
            offset=bounds.integer("offset", offset, low=0, high=5000),
        )
        return clip(result | bounds.envelope())

    @tool
    def mitre_search(
        keyword: str, resource: Literal["techniques", "tactics", "mitigations", "groups", "software"] = "techniques",
        limit: int = 5,
    ) -> str:
        """Search Wazuh's ATT&CK catalog when the technique ID is unknown.
        external_id is the T/M/TA ID; id is a STIX identifier. This is reference
        knowledge, not evidence that a threat group or attack was observed."""
        bounds = bounds_factory()
        result = gateway.search_mitre_catalog(
            keyword=keyword, resource=resource, limit=bounds.integer("limit", limit, low=1, high=20),
        )
        return clip(result | bounds.envelope())

    @tool
    def mitre_metadata() -> str:
        """Read the ATT&CK dataset metadata bundled with Wazuh for reproducible reports."""
        return clip(gateway.get_mitre_metadata())

    @tool
    def correlated_alerts(agent_id: str, timestamp: str, window_minutes: int = 10, limit: int = 20, offset: int = 0) -> str:
        """Exact-agent alert sequence around a timezone-aware ISO timestamp.
        Preserves IDs and Linux/Windows commands, users and PID/PPID. Never
        merges different commands by rule description. Time proximity is not causation."""
        pivot = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if pivot.tzinfo is None or pivot.utcoffset() is None:
            raise ValueError("timestamp must include a timezone.")
        if not agent_id:
            raise ValueError("agent_id is required for correlation.")
        bounds = bounds_factory()
        minutes = bounds.integer("window_minutes", window_minutes, low=1, high=min(120, cap * 30))
        result = gateway.threat_hunt(
            agent_id=agent_id, start_time=pivot - timedelta(minutes=minutes),
            end_time=pivot + timedelta(minutes=minutes),
            limit=bounds.integer("limit", limit, low=1, high=min(100, settings.SOC_ANALYST_MAX_QUERY_RESULTS)),
            offset=bounds.integer("offset", offset, low=0, high=5000),
        )
        result["correlation_note"] = "Same agent and time window only; verify matching PID/user/path before asserting links."
        return clip(result | bounds.envelope())

    @tool
    def alert_timeline(agent_id: str | None = None, hours: int = 24, interval_minutes: int | None = None, min_level: int = 0) -> str:
        """Indexer alert counts over time, including zero buckets. A burst is not
        proof of an attack. Default interval targets about 60 buckets; max 168."""
        bounds = bounds_factory()
        applied_hours = bounds.integer("hours", hours, low=1, high=cap)
        interval = interval_minutes if interval_minutes is not None else applied_hours
        result = gateway.alert_statistics(
            mode="timeline", agent_id=agent_id or None, hours=applied_hours,
            interval_minutes=bounds.integer("interval_minutes", interval, low=1, high=1440),
            min_level=bounds.integer("min_level", min_level, low=0, high=15),
        )
        return clip(result | bounds.envelope())

    @tool
    def compare_alert_windows(agent_id: str | None = None, rule_id: str | None = None, hours: int = 24, baseline_hours: int = 144, min_level: int = 0) -> str:
        """Compare current activity with the immediately preceding, non-overlapping
        baseline using identical filters and normalized hourly rates. Combined
        windows max seven days. Zero baseline does not mean never seen historically."""
        if cap < 2:
            raise ValueError("Comparison needs a configured query window of at least two hours.")
        bounds = bounds_factory()
        current = bounds.integer("hours", hours, low=1, high=cap - 1)
        result = gateway.alert_statistics(
            mode="baseline", agent_id=agent_id or None, rule_id=rule_id or None, hours=current,
            baseline_hours=bounds.integer("baseline_hours", baseline_hours, low=1, high=cap - current),
            min_level=bounds.integer("min_level", min_level, low=0, high=15),
        )
        return clip(result | bounds.envelope())

    @tool
    def mitre_attack_coverage(agent_id: str | None = None, hours: int = 24, min_level: int = 0) -> str:
        """Rank observed ATT&CK alert mappings and affected agents, with unmapped
        counts and top-bucket error/omission metadata. Not a detection coverage
        guarantee, threat-group attribution, or proof that compromise occurred."""
        bounds = bounds_factory()
        result = gateway.alert_statistics(
            mode="mitre", agent_id=agent_id or None,
            hours=bounds.integer("hours", hours, low=1, high=cap),
            min_level=bounds.integer("min_level", min_level, low=0, high=15),
        )
        return clip(result | bounds.envelope())

    return [sca_policy_summary, sca_failed_checks, mitre_search, mitre_metadata,
            correlated_alerts, alert_timeline, compare_alert_windows, mitre_attack_coverage]
