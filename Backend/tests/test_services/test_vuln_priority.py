"""Checks for the exploitability-based vulnerability ranking."""

from app.services.wazuh.triage.vuln_priority import prioritize_vulnerabilities


def _vuln(cve, severity="High", cvss=7.5):
    return {
        "vulnerability": {"id": cve, "severity": severity, "score": {"base": cvss}},
        "agent": {"id": "001", "name": "web-01"},
        "package": {"name": "openssl"},
    }


def test_kev_membership_outranks_higher_cvss():
    ranked = prioritize_vulnerabilities(
        [
            _vuln("CVE-2024-0001", severity="Critical", cvss=9.8),
            _vuln("CVE-2024-0002", severity="Medium", cvss=5.0),
        ],
        kev_cves=frozenset({"CVE-2024-0002"}),
        epss_scores={},
    )
    assert ranked[0]["cve"] == "CVE-2024-0002"
    assert ranked[0]["known_exploited"] is True
    assert "CISA KEV" in ranked[0]["reasons"][0]


def test_epss_breaks_ties_and_offline_falls_back_to_cvss():
    ranked = prioritize_vulnerabilities(
        [
            _vuln("CVE-2024-0003", cvss=7.5),
            _vuln("CVE-2024-0004", cvss=7.5),
        ],
        kev_cves=frozenset(),
        epss_scores={"CVE-2024-0004": 0.72},
    )
    assert ranked[0]["cve"] == "CVE-2024-0004"
    assert ranked[0]["epss"] == 0.72

    offline = prioritize_vulnerabilities(
        [
            _vuln("CVE-2024-0005", cvss=9.0),
            _vuln("CVE-2024-0006", cvss=4.0),
        ],
        kev_cves=frozenset(),
        epss_scores={},
    )
    assert offline[0]["cve"] == "CVE-2024-0005"
