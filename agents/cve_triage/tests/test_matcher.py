import pytest

from cve_triage.matcher import Inventory, compare_versions, match_cve, parse_cpe
from cve_triage.normalize import normalize

import fixtures as fx


@pytest.fixture(scope="module")
def inv():
    return Inventory.load(fx.INVENTORY)


def results(rec, inv):
    return {(r.host_id, r.cpe.split(":")[4]): r.result for r in match_cve(normalize(rec), inv)}


@pytest.mark.parametrize("a,b,expected", [
    ("9.0.80", "9.0.83", -1),
    ("9.0.80", "11.0.0-M1", -1),
    ("5.15", "5.15.0", 0),
    ("10.0.17763.5329", "10.0.17763.6532", -1),
    ("14.1.1.0.0", "14.1.1.0.0", 0),
    ("3.0.11", "1.1.1w", 1),
    ("9.3p2", "9.3p1", None),
    ("11.0.0-M1", "11.0.0", None),
    ("R81", "R80", None),
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_parse_cpe_escapes():
    c = parse_cpe(r"cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*")
    assert c.product == "prod:uct" and c.version == "1.0"
    with pytest.raises(ValueError):
        parse_cpe("cpe:/a:apache:tomcat:9.0")


def test_every_inventory_cpe_parses(inv):
    assert len(inv.hosts) == 8
    assert all(sw.cpe.part in "aoh" for h in inv.hosts for sw in h.software)


@pytest.mark.parametrize("rec,expected", [
    (fx.TOMCAT, {("web-ob-01", "tomcat"): "affected"}),
    (fx.OPENSSH_IN_RANGE, {("pay-gw-01", "openssh"): "affected"}),
    (fx.OPENSSH_ON_BOUND, {("pay-gw-01", "openssh"): "needs_review"}),
    (fx.FORTIOS_OTHER, {("fw-edge-01", "fortios"): "not_affected"}),
    (fx.FORTIOS_HIT, {("fw-edge-01", "fortios"): "affected"}),
    (fx.CONFLUENCE_ON_WINDOWS, {("wiki-int-01", "confluence_data_center"): "needs_review"}),
    (fx.WINDOWS_NA, {("dc-ad-01", "windows_server_2019"): "needs_review"}),
    (fx.WINDOWS_RANGE, {("dc-ad-01", "windows_server_2019"): "affected"}),
    (fx.WINDOWS_PATCHED, {("dc-ad-01", "windows_server_2019"): "not_affected"}),
    (fx.KERNEL_PENDING, {("web-ob-01", "linux_kernel"): "needs_review"}),
    (fx.REJECTED, {}),
    (fx.UNRELATED, {}),
    (fx.VCENTER_U1, {("virt-vc-01", "vcenter_server"): "affected"}),
    (fx.VCENTER_U2, {("virt-vc-01", "vcenter_server"): "not_affected"}),
    (fx.UNRELATED_PENDING, {}),
])
def test_match(rec, expected, inv):
    assert results(rec, inv) == expected


def test_evidence_explains_decision(inv):
    [r] = match_cve(normalize(fx.OPENSSH_ON_BOUND), inv)
    assert "range bound 9.3" in r.detail["evidence"][0]["why"]
    [r] = match_cve(normalize(fx.CONFLUENCE_ON_WINDOWS), inv)
    assert any(e.get("platform") and "not in host inventory" in e["why"] for e in r.detail["evidence"])


def test_prefilter(inv):
    keep = {r["id"] for r in fx.ALL if inv.is_candidate(r)}
    assert keep == {r["id"] for r in fx.ALL} - {"CVE-2026-1011", "CVE-2026-1012", "CVE-2026-1015"}
