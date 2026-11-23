"""Rule floor and guard: the deterministic half of checkpoint B."""

from types import SimpleNamespace

import pytest

from cve_triage.priority import CORRECTED, PASSED, REJECTED, guard, rule_priority

WAF = "WAF in blocking mode in front of the application"


@pytest.mark.parametrize("cvss,kev,zone,crit,expected", [
    (9.8, False, "dmz", "critical", "P1"),
    (9.8, False, "internal", "high", "P2"),      # >= 9 but not exposed
    (8.1, False, "internal", "critical", "P2"),  # critical counts as exposed
    (8.1, False, "internal", "medium", "P3"),
    (5.0, True, "internal", "low", "P1"),        # KEV beats everything
    (None, False, "dmz", "critical", "P3"),      # unknown is not low
    (3.1, False, "internet", "critical", "P4"),
])
def test_rule_priority(cvss, kev, zone, crit, expected):
    assert rule_priority(cvss, kev, zone, crit)[0] == expected


def out(**kw):
    base = dict(cve_id="CVE-2026-1001", host_id="web-ob-01", priority="P1", rationale="Because.",
                recommended_action="Patch.", cited_fields=["cvss_score"], compensating_control=None)
    return SimpleNamespace(**{**base, **kw})


def g(o, rule="P1", **kw):
    return guard(cve_id="CVE-2026-1001", host_id="web-ob-01", rule=rule, controls=[WAF], output=o, **kw)


def test_agree_and_raise_pass():
    assert (r := g(out(), rule="P1")).result == PASSED and r.final_priority == "P1"
    assert (r := g(out(priority="P1"), rule="P3")).result == PASSED and r.final_priority == "P1"


def test_lower_one_level_needs_a_listed_control():
    r = g(out(priority="P2", compensating_control="  waf in BLOCKING mode in front of the application "))
    assert r.result == PASSED and r.final_priority == "P2"
    r = g(out(priority="P2"))
    assert r.result == CORRECTED and r.final_priority == "P1"
    r = g(out(priority="P2", compensating_control="Network segmentation"))
    assert r.result == CORRECTED and r.final_priority == "P1" and "not listed" in r.reasons[0]


def test_lowering_more_than_one_level_is_clamped():
    r = g(out(priority="P4", compensating_control=WAF))
    assert r.result == CORRECTED and r.final_priority == "P2"


@pytest.mark.parametrize("o,why", [
    (None, "no usable model output"),
    (out(cve_id="CVE-2026-9999"), "identity mismatch"),
    (out(host_id="db-core-01"), "identity mismatch"),
    (out(rationale="   "), "empty rationale"),
    (out(priority="P0"), "invalid priority"),
    (out(rationale="Similar to CVE-2025-0001, which was exploited."), "not in the evidence"),
])
def test_rejections_keep_rule_priority_and_flag_review(o, why):
    r = g(o, rule="P2")
    assert r.result == REJECTED and r.final_priority == "P2" and r.needs_review
    assert why in r.reasons[0]


def test_recalled_cve_ids_may_be_mentioned():
    r = g(out(rationale="Consistent with CVE-2025-0001 last month."), allowed_cve_ids={"CVE-2025-0001"})
    assert r.result == PASSED
