"""Checkpoint B end to end, offline: fake NVD pages, fake model, fake embedder, in-memory store."""

import copy
import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from cve_triage import triage
from cve_triage.assess import Assessment, Outcome
from cve_triage.db import MemoryStore
from cve_triage.matcher import Inventory

import fixtures as fx

NOW = datetime(2026, 11, 23, 6, 0, tzinfo=UTC)
AFFECTED_PAIRS = {("CVE-2026-1001", "web-ob-01"), ("CVE-2026-1002", "pay-gw-01"), ("CVE-2026-1005", "fw-edge-01"),
                  ("CVE-2026-1008", "dc-ad-01"), ("CVE-2026-1013", "virt-vc-01")}


@pytest.fixture(scope="module")
def inv():
    return Inventory.load(fx.INVENTORY)


def pages(records):
    def fetch(start, end):
        yield list(records)
    return fetch


def embed(texts):
    """Deterministic 384-dim vectors; identical text -> identical vector."""
    out = []
    for t in texts:
        h = hashlib.sha256(t.encode()).digest()
        out.append([((h[i % 32] + i) % 17) / 17.0 + 0.01 for i in range(384)])
    return out


class FakeAssessor:
    model = "fake-model"

    def __init__(self, decide=None):
        self.decide = decide or (lambda c: {"priority": c.rule_priority})
        self.calls = []

    def __call__(self, cands):
        self.calls.append([c.key for c in cands])
        outs = []
        for c in cands:
            d = self.decide(c)
            if isinstance(d, Outcome):
                outs.append(d)
                continue
            fields = dict(cve_id=c.cve_id, host_id=c.host_id, priority=c.rule_priority,
                          rationale=f"{c.cve_id} on {c.host_id}.",
                          recommended_action="Patch in the next window.", cited_fields=["cvss_score"])
            fields.update(d)
            outs.append(Outcome(Assessment(**fields), input_tokens=1000, output_tokens=100))
        return outs


def go(store, inv, records, assessor=None, now=NOW, **settings):
    return triage.run(store, inv, pages(records), now=now, assessor=assessor, embedder=embed,
                      settings={"price_in": 1.0, "price_out": 5.0, **settings})


def test_first_run_assesses_every_affected_pair(inv):
    store, llm = MemoryStore(), FakeAssessor()
    s = go(store, inv, fx.ALL, llm)
    assert s["assessment"] == {"affected_pairs": 5, "unchanged": 0, "llm": 5, "rule-only": 0, "cap": 0}
    assert {(a["cve_id"], a["host_id"]) for a in store.analyses} == AFFECTED_PAIRS
    assert all(len(a["embedding"]) == 384 and a["guard_result"] == "passed" for a in store.analyses)
    assert s["final_priority"] == {"P1": 3, "P2": 2}      # tomcat/openssh(KEV)/fortios P1; windows/vcenter P2
    assert s["usage"] == {"input_tokens": 5000, "output_tokens": 500, "cost_usd": 0.0075}
    assert store.runs[1]["cost_usd"] == 0.0075
    assert all(a["langsmith_run_id"] == s["langsmith_run_id"] for a in store.analyses)
    md = store.digests[1]
    assert "## P1 · 3" in md and "CVE-2026-1002" in md and "KEV" in md
    assert "Waiting for NVD analysis" in md               # the needs_review rows are counted, not assessed
    assert s["digest"] == md


def test_unchanged_pairs_are_not_reassessed(inv):
    store, llm = MemoryStore(), FakeAssessor()
    go(store, inv, fx.ALL, llm)
    s = go(store, inv, fx.ALL, llm, now=NOW + timedelta(days=1))
    assert s["assessment"]["unchanged"] == 5 and s["stored_analyses"] == 0
    assert len(llm.calls) == 1
    assert "Nothing new or changed" in store.digests[2]


def test_material_change_triggers_reassessment_with_recall(inv):
    store, llm = MemoryStore(), FakeAssessor()
    go(store, inv, fx.ALL, llm)
    bumped = copy.deepcopy(fx.WINDOWS_RANGE)
    bumped["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 9.1
    s = go(store, inv, [bumped], llm, now=NOW + timedelta(days=1))
    assert s["assessment"]["llm"] == 1
    new = store.analyses[-1]
    assert new["cve_id"] == "CVE-2026-1008" and new["rule_priority"] == "P1"
    assert new["evidence"]["previous_fingerprint"]["cvss"] == 8.1
    assert new["evidence"]["recalled"] and new["evidence"]["recalled"][0]["cve_id"] == "CVE-2026-1008"


def test_below_threshold_is_rule_only(inv):
    store, llm = MemoryStore(), FakeAssessor()
    low = fx.cve("CVE-2026-2001", fx.conf(fx.node(fx.m("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", ee="9.0.83"))),
                 score=5.3)
    s = go(store, inv, [low], llm)
    assert s["assessment"]["rule-only"] == 1 and llm.calls == []
    a = store.analyses[0]
    assert a["model"] == "rule-only" and a["final_priority"] == "P3" and not a["needs_review"]
    assert "below the LLM threshold" in a["rationale"]


def test_cap_keeps_most_urgent_for_the_model(inv):
    store, llm = MemoryStore(), FakeAssessor()
    s = go(store, inv, fx.ALL, llm, cap=2)
    assert s["assessment"]["llm"] == 2 and s["assessment"]["cap"] == 3
    by_route = {a["evidence"]["route"]: a for a in store.analyses}
    assert all(a["rule_priority"] == "P1" for a in store.analyses if a["evidence"]["route"] == "llm")
    assert by_route["cap"]["needs_review"] and by_route["cap"]["model"] == "rule-only"
    md = store.digests[1]
    assert "Needs human review · 3" in md and "3 deferred over the model cap" in md
    assert "Rule priority only, no model assessment" in md
    assert md.count("rule-only (over cap)") == 0          # deferred rows are counted, not listed


def test_guard_corrects_and_rejects_inside_the_graph(inv):
    waf = "WAF in blocking mode in front of the application"

    def decide(c):
        if c.host_id == "web-ob-01":
            return {"priority": "P3", "compensating_control": waf}        # two levels down -> clamp
        if c.host_id == "fw-edge-01":
            return {"rationale": "Like CVE-2019-0001 we saw before."}     # invented CVE -> reject
        if c.host_id == "dc-ad-01":
            return Outcome(None, "TimeoutError: model timed out")         # failure -> reject
        return {"priority": c.rule_priority}

    store = MemoryStore()
    s = go(store, inv, fx.ALL, FakeAssessor(decide))
    rows = {a["host_id"]: a for a in store.analyses}
    assert rows["web-ob-01"]["guard_result"] == "corrected" and rows["web-ob-01"]["final_priority"] == "P2"
    assert rows["fw-edge-01"]["guard_result"] == "rejected" and rows["fw-edge-01"]["final_priority"] == "P1"
    assert rows["fw-edge-01"]["needs_review"] and "Model output rejected" in rows["fw-edge-01"]["rationale"]
    assert rows["dc-ad-01"]["guard_result"] == "rejected"
    assert "TimeoutError" in rows["dc-ad-01"]["evidence"]["model_error"]
    assert s["guard"] == {"corrected": 1, "passed": 2, "rejected": 2}


def test_failed_model_calls_are_retried_when_the_pair_reappears(inv):
    store = MemoryStore()
    quota = FakeAssessor(lambda c: Outcome(None, "OpenAIRateLimitError: 429 no credits"))
    go(store, inv, fx.ALL, quota)
    assert all(a["guard_result"] == "rejected" for a in store.analyses)
    ok = FakeAssessor()
    s = go(store, inv, fx.ALL, ok, now=NOW + timedelta(days=1),
           start_override="2026-11-16T06:00:00", end_override="2026-11-23T06:00:00")
    assert s["assessment"]["llm"] == 5 and s["assessment"]["unchanged"] == 0
    s = go(store, inv, fx.ALL, ok, now=NOW + timedelta(days=2),
           start_override="2026-11-16T06:00:00", end_override="2026-11-23T06:00:00")
    assert s["assessment"]["unchanged"] == 5


def test_without_a_model_everything_is_rule_floor_and_flagged(inv):
    store = MemoryStore()
    s = go(store, inv, fx.ALL, assessor=None)
    assert s["assessment"]["cap"] == 5 and s["model"] == "none"
    assert all(a["needs_review"] and a["model"] == "rule-only" for a in store.analyses)
    assert "LLM disabled" in store.analyses[0]["rationale"]


def test_deferred_rows_are_assessed_when_they_reappear(inv):
    store, llm = MemoryStore(), FakeAssessor()
    go(store, inv, fx.ALL, llm, cap=2)                          # 3 pairs deferred over the cap
    s = go(store, inv, fx.ALL, llm, now=NOW + timedelta(days=1),
           start_override="2026-11-16T06:00:00", end_override="2026-11-23T06:00:00")   # replay
    assert s["assessment"]["unchanged"] == 2 and s["assessment"]["llm"] == 3 and s["assessment"]["cap"] == 0
