"""Hand-built NVD CVE records in the API 2.0 shape (trimmed to the fields the agent reads)."""

from __future__ import annotations

from pathlib import Path

INVENTORY = Path(__file__).resolve().parents[1] / "inventory" / "bank-estate.yaml"


def m(criteria, vulnerable=True, **rng):
    keys = {"si": "versionStartIncluding", "se": "versionStartExcluding",
            "ei": "versionEndIncluding", "ee": "versionEndExcluding"}
    out = {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "00000000"}
    out.update({keys[k]: v for k, v in rng.items()})
    return out


def cve(cve_id, *configs, status="Analyzed", desc="Test vulnerability.", score=9.8, kev=None, metrics=None):
    rec = {
        "id": cve_id,
        "vulnStatus": status,
        "published": "2026-11-18T10:00:00.000",
        "lastModified": "2026-11-20T10:00:00.000",
        "descriptions": [{"lang": "es", "value": "Prueba."}, {"lang": "en", "value": desc}],
        "metrics": metrics if metrics is not None else {"cvssMetricV31": [{
            "source": "nvd@nist.gov", "type": "Primary",
            "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                         "baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "HIGH"}}]},
        "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-787"}, {"lang": "en", "value": "NVD-CWE-noinfo"}]}],
        "configurations": list(configs),
    }
    if kev:
        rec.update(cisaExploitAdd=kev, cisaActionDue="2026-12-10", cisaRequiredAction="Apply updates.")
    return rec


def conf(*nodes, operator=None):
    c = {"nodes": list(nodes)}
    if operator:
        c["operator"] = operator
    return c


def node(*matches, operator="OR", negate=False):
    return {"operator": operator, "negate": negate, "cpeMatch": list(matches)}


TOMCAT = cve("CVE-2026-1001", conf(node(
    m("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", si="11.0.0-M1", ee="11.0.2"),
    m("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", si="9.0.0-M1", ee="9.0.83"),
)))
OPENSSH_IN_RANGE = cve("CVE-2026-1002", conf(node(
    m("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", si="8.5", ee="9.8"),
    m("cpe:2.3:a:openbsd:openssh:9.8:-:*:*:*:*:*:*"),
)), kev="2026-11-19")
OPENSSH_ON_BOUND = cve("CVE-2026-1003", conf(node(
    m("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", ee="9.3"),
)), score=7.5)
FORTIOS_OTHER = cve("CVE-2026-1004", conf(node(
    m("cpe:2.3:o:fortinet:fortios:7.2.5:*:*:*:*:*:*:*"),
    m("cpe:2.3:o:fortinet:fortios:7.4.0:*:*:*:*:*:*:*"),
)))
FORTIOS_HIT = cve("CVE-2026-1005", conf(node(
    m("cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"),
)))
CONFLUENCE_ON_WINDOWS = cve("CVE-2026-1006", conf(
    node(m("cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*", si="8.5.0", ee="8.5.4")),
    node(m("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", vulnerable=False)),
    operator="AND",
), score=6.5)
WINDOWS_NA = cve("CVE-2026-1007", conf(node(
    m("cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"),
)), score=8.8)
WINDOWS_RANGE = cve("CVE-2026-1008", conf(node(
    m("cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:x64:*", ee="10.0.17763.6532"),
)), score=8.1)
WINDOWS_PATCHED = cve("CVE-2026-1009", conf(node(
    m("cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:x64:*", ee="10.0.17763.5000"),
)), score=8.1)
KERNEL_PENDING = cve("CVE-2026-1010", status="Awaiting Analysis", metrics={},
                     desc="In the Linux kernel, the following vulnerability has been resolved: net: fix UAF.")
REJECTED = cve("CVE-2026-1011", conf(node(m("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"))), status="Rejected")
UNRELATED = cve("CVE-2026-1012", conf(node(m("cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*"))))
VCENTER_U1 = cve("CVE-2026-1013", conf(node(
    m("cpe:2.3:a:vmware:vcenter_server:8.0:update1:*:*:*:*:*:*"),
    m("cpe:2.3:a:vmware:vcenter_server:8.0:update1a:*:*:*:*:*:*"),
)))
VCENTER_U2 = cve("CVE-2026-1014", conf(node(
    m("cpe:2.3:a:vmware:vcenter_server:8.0:update2:*:*:*:*:*:*"),
)))
UNRELATED_PENDING = cve("CVE-2026-1015", status="Received", metrics={},
                        desc="A flaw in Example Widget allows remote code execution.")

ALL = [TOMCAT, OPENSSH_IN_RANGE, OPENSSH_ON_BOUND, FORTIOS_OTHER, FORTIOS_HIT, CONFLUENCE_ON_WINDOWS,
       WINDOWS_NA, WINDOWS_RANGE, WINDOWS_PATCHED, KERNEL_PENDING, REJECTED, UNRELATED, VCENTER_U1,
       VCENTER_U2, UNRELATED_PENDING]
