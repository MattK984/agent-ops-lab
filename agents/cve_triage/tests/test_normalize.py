from cve_triage.normalize import normalize, pick_cvss

import fixtures as fx


def test_fields():
    n = normalize(fx.OPENSSH_IN_RANGE)
    assert n.cve_id == "CVE-2026-1002"
    assert n.description == "Test vulnerability."
    assert n.cwe == ["CWE-787"]
    assert n.cvss.score == 9.8 and n.cvss.version == "3.1" and n.cvss.primary
    assert n.kev_added == "2026-11-19"
    assert len(n.configurations) == 1 and len(n.configurations[0].nodes[0].matches) == 2
    assert not n.awaiting_analysis and not n.rejected


def test_pending_and_rejected():
    assert normalize(fx.KERNEL_PENDING).awaiting_analysis
    assert normalize(fx.KERNEL_PENDING).cvss is None
    assert normalize(fx.REJECTED).rejected


def test_nvd_primary_beats_newer_cna_score():
    metrics = {
        "cvssMetricV40": [{"source": "cna@example", "type": "Secondary",
                           "cvssData": {"version": "4.0", "baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                           "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}}],
    }
    s = pick_cvss(metrics)
    assert (s.score, s.version, s.primary) == (7.5, "3.1", True)
    del metrics["cvssMetricV31"]
    s = pick_cvss(metrics)
    assert (s.score, s.version, s.primary) == (9.3, "4.0", False)
    assert pick_cvss({}) is None
