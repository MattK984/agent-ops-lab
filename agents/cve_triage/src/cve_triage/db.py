"""Postgres persistence for the CVE triage agent (schema `cve`, see db/init/001_cve_memory.sql).

Connection: DATABASE_URL if set, otherwise the standard libpq variables
(PGHOST, PGUSER, PGPASSWORD, PGDATABASE), which compose.yaml passes in.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Protocol

from cve_triage.matcher import MatchResult
from cve_triage.normalize import NormalizedCve


class Store(Protocol):
    def last_ok_window_end(self) -> datetime | None: ...
    def start_run(self, window_start: datetime, window_end: datetime) -> int: ...
    def save_cves(self, cves: list[tuple[NormalizedCve, dict[str, Any]]]) -> int: ...
    def save_matches(self, run_id: int, matches: list[MatchResult]) -> int: ...
    def finish_run(self, run_id: int, *, status: str, cves_fetched: int | None = None,
                   matches_found: int | None = None, langsmith_trace: str | None = None,
                   error: str | None = None) -> None: ...


class PostgresStore:
    """Each method commits on its own, so a crash leaves a consistent, inspectable state."""

    def __init__(self, conninfo: str | None = None):
        import psycopg  # imported here so the offline tests need no database driver

        self._psycopg = psycopg
        # autocommit: every `with conn.transaction()` below is a real, self-contained transaction
        self.conn = psycopg.connect(
            conninfo if conninfo is not None else os.getenv("DATABASE_URL", ""), autocommit=True
        )

    def close(self) -> None:
        self.conn.close()

    def last_ok_window_end(self) -> datetime | None:
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute("SELECT max(window_end) FROM cve.runs WHERE status = 'ok'")
            return cur.fetchone()[0]

    def start_run(self, window_start: datetime, window_end: datetime) -> int:
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO cve.runs (window_start, window_end) VALUES (%s, %s) RETURNING id",
                (window_start, window_end),
            )
            return cur.fetchone()[0]

    def save_cves(self, cves: list[tuple[NormalizedCve, dict[str, Any]]]) -> int:
        """Upsert; an older NVD version never overwrites a newer one."""
        from psycopg.types.json import Jsonb

        rows = [
            (
                n.cve_id, n.published, n.last_modified,
                n.cvss.score if n.cvss else None,
                n.cvss.vector if n.cvss else None,
                n.cvss.version if n.cvss else None,
                n.cvss.severity if n.cvss else None,
                n.cwe, n.kev_added, n.description, Jsonb(raw),
            )
            for n, raw in cves
        ]
        if not rows:
            return 0
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO cve.cves (cve_id, published, last_modified, cvss_score, cvss_vector,
                                      cvss_version, severity, cwe, kev_added, description, raw)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    published = EXCLUDED.published,
                    last_modified = EXCLUDED.last_modified,
                    cvss_score = EXCLUDED.cvss_score,
                    cvss_vector = EXCLUDED.cvss_vector,
                    cvss_version = EXCLUDED.cvss_version,
                    severity = EXCLUDED.severity,
                    cwe = EXCLUDED.cwe,
                    kev_added = EXCLUDED.kev_added,
                    description = EXCLUDED.description,
                    raw = EXCLUDED.raw,
                    updated_at = now()
                WHERE cve.cves.last_modified IS NULL
                   OR EXCLUDED.last_modified >= cve.cves.last_modified
                """,
                rows,
            )
        return len(rows)

    def save_matches(self, run_id: int, matches: list[MatchResult]) -> int:
        from psycopg.types.json import Jsonb

        if not matches:
            return 0
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO cve.matches (run_id, cve_id, host_id, cpe, result, match_detail)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_id, cve_id, host_id, cpe) DO NOTHING
                """,
                [(run_id, m.cve_id, m.host_id, m.cpe, m.result, Jsonb(m.detail)) for m in matches],
            )
        return len(matches)

    def finish_run(self, run_id: int, *, status: str, cves_fetched: int | None = None,
                   matches_found: int | None = None, langsmith_trace: str | None = None,
                   error: str | None = None) -> None:
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute(
                """
                UPDATE cve.runs SET finished_at = now(), status = %s,
                    cves_fetched = COALESCE(%s, cves_fetched),
                    matches_found = COALESCE(%s, matches_found),
                    langsmith_trace = COALESCE(%s, langsmith_trace),
                    error = %s
                WHERE id = %s
                """,
                (status, cves_fetched, matches_found, langsmith_trace, error, run_id),
            )


class MemoryStore:
    """In-memory Store for offline tests."""

    def __init__(self, last_end: datetime | None = None):
        self.last_end = last_end
        self.runs: dict[int, dict[str, Any]] = {}
        self.cves: dict[str, tuple[NormalizedCve, dict[str, Any]]] = {}
        self.matches: list[tuple[int, MatchResult]] = []

    def last_ok_window_end(self) -> datetime | None:
        ends = [r["window_end"] for r in self.runs.values() if r["status"] == "ok"]
        return max(ends) if ends else self.last_end

    def start_run(self, window_start: datetime, window_end: datetime) -> int:
        rid = len(self.runs) + 1
        self.runs[rid] = {"window_start": window_start, "window_end": window_end, "status": "running"}
        return rid

    def save_cves(self, cves):
        for n, raw in cves:
            self.cves[n.cve_id] = (n, raw)
        return len(cves)

    def save_matches(self, run_id, matches):
        self.matches.extend((run_id, m) for m in matches)
        return len(matches)

    def finish_run(self, run_id, *, status, cves_fetched=None, matches_found=None,
                   langsmith_trace=None, error=None):
        self.runs[run_id].update(status=status, cves_fetched=cves_fetched,
                                 matches_found=matches_found, langsmith_trace=langsmith_trace, error=error)
