"""PostgresStore against a real database with the `cve` schema applied.

Skipped unless TEST_DATABASE_URL points at a THROWAWAY database, e.g.
    TEST_DATABASE_URL="host=/tmp/pg port=5433 user=agent_ops dbname=agent_ops" uv run pytest -q
Checkpoint-A tests delete the runs/matches/cves/digests they created; the checkpoint-B test
runs inside a transaction that is rolled back (analyses are append-only and cannot be deleted).
"""

import os
from datetime import UTC, datetime, timedelta

import pytest

from cve_triage import triage
from cve_triage.matcher import Inventory

import fixtures as fx

DSN = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")

NOW = datetime(2026, 11, 23, 6, 0, tzinfo=UTC)


@pytest.fixture
def store():
    from cve_triage.db import PostgresStore

    s = PostgresStore(DSN)
    yield s
    with s.conn.transaction(), s.conn.cursor() as cur:
        cur.execute("DELETE FROM cve.matches WHERE cve_id LIKE 'CVE-2026-10%'")
        cur.execute("DELETE FROM cve.cves WHERE cve_id LIKE 'CVE-2026-10%'")
        cur.execute("DELETE FROM cve.digests WHERE run_id IN (SELECT id FROM cve.runs WHERE window_end >= %s)",
                    (NOW - timedelta(days=1),))
        cur.execute("DELETE FROM cve.runs WHERE window_end >= %s", (NOW - timedelta(days=1),))
    s.close()


def pages(records):
    def fetch(start, end):
        yield records
    return fetch


def test_run_persists_and_continues(store):
    inv = Inventory.load(fx.INVENTORY)
    s1 = triage.run(store, inv, pages(fx.ALL), now=NOW)
    with store.conn.cursor() as cur:
        cur.execute("SELECT status, cves_fetched, matches_found, langsmith_trace FROM cve.runs WHERE id = %s",
                    (s1["run_id"],))
        assert cur.fetchone() == ("ok", 15, 9, s1["langsmith_run_id"])
        cur.execute("SELECT result, count(*) FROM cve.matches WHERE run_id = %s GROUP BY 1 ORDER BY 1",
                    (s1["run_id"],))
        assert cur.fetchall() == [("affected", 5), ("needs_review", 4), ("not_affected", 3)]
        cur.execute("SELECT cvss_score::float, cvss_version, cwe, kev_added::text, raw->>'vulnStatus' "
                    "FROM cve.cves WHERE cve_id = 'CVE-2026-1002'")
        assert cur.fetchone() == (9.8, "3.1", ["CWE-787"], "2026-11-19", "Analyzed")
        cur.execute("SELECT match_detail->'evidence'->0->>'why' FROM cve.matches "
                    "WHERE run_id = %s AND cve_id = 'CVE-2026-1003'", (s1["run_id"],))
        assert "range bound" in cur.fetchone()[0]
    store.conn.commit()

    # Second run: window continues from the first; an older NVD version must not overwrite a newer one
    stale = dict(fx.OPENSSH_IN_RANGE, lastModified="2026-11-01T00:00:00.000", vulnStatus="Modified")
    s2 = triage.run(store, inv, pages([stale]), now=NOW + timedelta(hours=6))
    assert s2["window_start"] == (NOW - triage.OVERLAP).isoformat()
    with store.conn.cursor() as cur:
        cur.execute("SELECT raw->>'vulnStatus' FROM cve.cves WHERE cve_id = 'CVE-2026-1002'")
        assert cur.fetchone()[0] == "Analyzed"
    store.conn.commit()


def test_failed_run_is_recorded(store):
    def broken(start, end):
        raise RuntimeError("NVD down")
        yield  # pragma: no cover

    with pytest.raises(RuntimeError):
        triage.run(store, Inventory.load(fx.INVENTORY), broken, now=NOW)
    with store.conn.cursor() as cur:
        cur.execute("SELECT status, error FROM cve.runs ORDER BY id DESC LIMIT 1")
        status, error = cur.fetchone()
    store.conn.commit()
    assert status == "failed" and "NVD down" in error


def test_checkpoint_b_persists_append_only_analyses_and_digest():
    """Everything inside one transaction that is rolled back, because analyses cannot be deleted."""
    from cve_triage.db import PostgresStore
    from test_checkpoint_b import FakeAssessor, embed

    store = PostgresStore(DSN)
    inv = Inventory.load(fx.INVENTORY)
    try:
        with store.conn.transaction(force_rollback=True):
            w = dict(start_override="2020-01-01T00:00:00", end_override="2020-01-08T00:00:00")
            s1 = triage.run(store, inv, pages(fx.ALL), assessor=FakeAssessor(), embedder=embed,
                            settings={"price_in": 1.0, "price_out": 5.0}, **w)
            assert s1["stored_analyses"] == 5
            with store.conn.cursor() as cur:
                cur.execute("SELECT count(*), count(embedding), bool_and(guard_result = 'passed') "
                            "FROM cve.analyses WHERE run_id = %s", (s1["run_id"],))
                assert cur.fetchone() == (5, 5, True)
                cur.execute("SELECT cost_usd::float FROM cve.runs WHERE id = %s", (s1["run_id"],))
                assert cur.fetchone()[0] == 0.0075
                cur.execute("SELECT markdown FROM cve.digests WHERE run_id = %s", (s1["run_id"],))
                assert "## P1 · 3" in cur.fetchone()[0]
            fp = store.latest_fingerprints([("CVE-2026-1002", "pay-gw-01")])
            assert fp == {("CVE-2026-1002", "pay-gw-01"): {"result": "affected", "cvss": 9.8, "kev": "2026-11-19"}}
            recalled = store.recall(embed(["x"])[0], 3, exclude_run_id=-1)
            assert len(recalled) == 3 and {"cve_id", "similarity"} <= set(recalled[0])

            # append-only: the trigger blocks UPDATE/DELETE even for the owner; cve_agent lacks the grant
            for sql in ("UPDATE cve.analyses SET final_priority = 'P4' WHERE run_id = %s",
                        "DELETE FROM cve.analyses WHERE run_id = %s"):
                with pytest.raises(Exception, match="append-only|permission denied"):
                    with store.conn.transaction(), store.conn.cursor() as cur:
                        cur.execute(sql, (s1["run_id"],))

            # next window, same data: nothing is re-assessed
            s2 = triage.run(store, inv, pages(fx.ALL), assessor=FakeAssessor(), embedder=embed,
                            start_override="2020-01-08T00:00:00", end_override="2020-01-09T00:00:00")
            assert s2["assessment"]["unchanged"] == 5 and s2["stored_analyses"] == 0
    finally:
        store.close()
