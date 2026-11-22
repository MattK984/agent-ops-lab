"""PostgresStore against a real database with the `cve` schema applied.

Skipped unless TEST_DATABASE_URL points at a THROWAWAY database, e.g.
    TEST_DATABASE_URL="host=/tmp/pg port=5433 user=agent_ops dbname=agent_ops" uv run pytest -q
The test deletes runs/matches/cves it created (analyses are untouched).
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
