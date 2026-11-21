"""Offline test: the graph runs end to end against a fake NVD response."""

import httpx

from cve_triage import hello_graph, nvd

FAKE_PAGE = {
    "resultsPerPage": 3,
    "startIndex": 0,
    "totalResults": 3,
    "vulnerabilities": [
        {"cve": {"id": "CVE-2026-0001", "metrics": {"cvssMetricV31": [
            {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}},
        {"cve": {"id": "CVE-2026-0002", "metrics": {"cvssMetricV40": [
            {"type": "Secondary", "cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}]}}},
        {"cve": {"id": "CVE-2026-0003", "metrics": {}}},
    ],
}


def test_severity():
    sevs = [nvd.severity(v["cve"]) for v in FAKE_PAGE["vulnerabilities"]]
    assert sevs == ["CRITICAL", "MEDIUM", "UNSCORED"]


def test_graph_end_to_end(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = dict(request.url.params)
        return httpx.Response(200, json=FAKE_PAGE)

    real = nvd.fetch_published
    monkeypatch.setattr(
        nvd, "fetch_published",
        lambda s, e, **kw: real(s, e, client=httpx.Client(transport=httpx.MockTransport(handler)), api_key=""),
    )
    out = hello_graph.build_graph().invoke({"hours": 24})
    assert out["total"] == 3
    assert out["by_severity"] == {"CRITICAL": 1, "MEDIUM": 1, "UNSCORED": 1}
    assert seen["params"]["pubStartDate"].endswith(".000+00:00")
