"""Checkpoint A end to end, offline: fake NVD pages, in-memory store."""

from datetime import UTC, datetime, timedelta

import pytest

from cve_triage import triage
from cve_triage.db import MemoryStore
from cve_triage.matcher import Inventory

import fixtures as fx

NOW = datetime(2026, 11, 23, 6, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def inv():
    return Inventory.load(fx.INVENTORY)


def pages(records, size=4, seen=None):
    def fetch(start, end):
        if seen is not None:
            seen.append((start, end))
        for i in range(0, len(records), size):
            yield records[i:i + size]
    return fetch


def test_first_run(inv):
    store, seen = MemoryStore(), []
    s = triage.run(store, inv, pages(fx.ALL, seen=seen), now=NOW, backfill_days=7)
    assert seen == [(NOW - timedelta(days=7), NOW)]
    assert s["fetched"] == 15 and s["candidates"] == 12
    assert s["by_result"] == {"affected": 5, "needs_review": 4, "not_affected": 3}
    assert store.runs[1]["status"] == "ok"
    assert store.runs[1]["matches_found"] == 9
    assert store.runs[1]["langsmith_trace"] == s["langsmith_run_id"]
    assert set(store.cves) == {r["id"] for r in fx.ALL} - {"CVE-2026-1011", "CVE-2026-1012", "CVE-2026-1015"}
    assert len(store.matches) == 12


def test_next_run_continues_from_last_window(inv):
    store, seen = MemoryStore(), []
    triage.run(store, inv, pages([]), now=NOW)
    later = NOW + timedelta(days=1)
    s = triage.run(store, inv, pages([fx.UNRELATED], seen=seen), now=later)
    assert seen == [(NOW - triage.OVERLAP, later)]
    assert s["match_rows"] == 0 and store.runs[2]["status"] == "ok"


def test_failure_is_recorded(inv):
    store = MemoryStore()

    def broken(start, end):
        raise RuntimeError("NVD down")
        yield  # pragma: no cover

    with pytest.raises(RuntimeError):
        triage.run(store, inv, broken, now=NOW)
    assert store.runs[1]["status"] == "failed"
    assert "NVD down" in store.runs[1]["error"]
    # a failed run does not move the window forward
    assert store.last_ok_window_end() is None


def test_window_override_replays_fixed_window(inv):
    store, seen = MemoryStore(), []
    triage.run(store, inv, pages([]), now=NOW)          # a normal run exists
    triage.run(store, inv, pages([], seen=seen), now=NOW + timedelta(days=1),
               start_override="2026-11-15T11:28:28", end_override="2026-11-22T11:28:28+00:00")
    assert seen == [(datetime(2026, 11, 15, 11, 28, 28, tzinfo=UTC), datetime(2026, 11, 22, 11, 28, 28, tzinfo=UTC))]
    with pytest.raises(ValueError):
        triage.compute_window(store, start_override="2026-11-22T00:00:00", end_override="2026-11-21T00:00:00")
