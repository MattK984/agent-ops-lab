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
                   error: str | None = None, cost_usd: float | None = None) -> None: ...
    # checkpoint B
    def latest_fingerprints(self, keys: list[tuple[str, str]]) -> dict[tuple[str, str], dict[str, Any]]: ...
    def recall(self, embedding: list[float], k: int, exclude_run_id: int) -> list[dict[str, Any]]: ...
    def save_analyses(self, rows: list[dict[str, Any]]) -> int: ...
    def save_digest(self, run_id: int, markdown: str) -> None: ...


def _vec(v: list[float] | None) -> str | None:
    """pgvector text literal; avoids a client-side pgvector dependency."""
    return None if v is None else "[" + ",".join(f"{x:.7g}" for x in v) + "]"


ANALYSIS_COLUMNS = ("run_id", "cve_id", "host_id", "rule_priority", "final_priority", "rationale",
                    "recommended_action", "evidence", "guard_result", "needs_review", "model",
                    "prompt_version", "langsmith_run_id", "embedding")


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
                   error: str | None = None, cost_usd: float | None = None) -> None:
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute(
                """
                UPDATE cve.runs SET finished_at = now(), status = %s,
                    cves_fetched = COALESCE(%s, cves_fetched),
                    matches_found = COALESCE(%s, matches_found),
                    langsmith_trace = COALESCE(%s, langsmith_trace),
                    cost_usd = COALESCE(%s, cost_usd),
                    error = %s
                WHERE id = %s
                """,
                (status, cves_fetched, matches_found, langsmith_trace, cost_usd, error, run_id),
            )

    def latest_fingerprints(self, keys):
        """Fingerprint of the newest analysis per (cve_id, host_id)."""
        if not keys:
            return {}
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (a.cve_id, a.host_id) a.cve_id, a.host_id, a.evidence->'fingerprint'
                FROM cve.analyses a
                JOIN unnest(%s::text[], %s::text[]) AS k(cve_id, host_id)
                  ON a.cve_id = k.cve_id AND a.host_id = k.host_id
                ORDER BY a.cve_id, a.host_id, a.created_at DESC, a.id DESC
                """,
                ([c for c, _ in keys], [h for _, h in keys]),
            )
            return {(c, h): fp for c, h, fp in cur.fetchall()}

    def recall(self, embedding, k, exclude_run_id):
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT cve_id, host_id, final_priority, rule_priority, guard_result,
                       left(rationale, 400), created_at::date::text,
                       round((1 - (embedding <=> %s::vector))::numeric, 3)::float
                FROM cve.analyses
                WHERE embedding IS NOT NULL AND run_id <> %s
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (_vec(embedding), exclude_run_id, _vec(embedding), k),
            )
            cols = ("cve_id", "host_id", "final_priority", "rule_priority", "guard_result",
                    "rationale", "date", "similarity")
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def save_analyses(self, rows):
        from psycopg.types.json import Jsonb

        if not rows:
            return 0
        placeholders = ", ".join("%s::vector" if c == "embedding" else "%s" for c in ANALYSIS_COLUMNS)
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.executemany(
                f"INSERT INTO cve.analyses ({', '.join(ANALYSIS_COLUMNS)}) VALUES ({placeholders})",
                [tuple(Jsonb(r[c]) if c == "evidence" else _vec(r[c]) if c == "embedding" else r[c]
                       for c in ANALYSIS_COLUMNS) for r in rows],
            )
        return len(rows)

    def save_digest(self, run_id, markdown):
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute("INSERT INTO cve.digests (run_id, markdown) VALUES (%s, %s)", (run_id, markdown))


class MemoryStore:
    """In-memory Store for offline tests."""

    def __init__(self, last_end: datetime | None = None):
        self.last_end = last_end
        self.runs: dict[int, dict[str, Any]] = {}
        self.cves: dict[str, tuple[NormalizedCve, dict[str, Any]]] = {}
        self.matches: list[tuple[int, MatchResult]] = []
        self.analyses: list[dict[str, Any]] = []
        self.digests: dict[int, str] = {}

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
                   langsmith_trace=None, error=None, cost_usd=None):
        self.runs[run_id].update(status=status, cves_fetched=cves_fetched, matches_found=matches_found,
                                 langsmith_trace=langsmith_trace, error=error, cost_usd=cost_usd)

    def latest_fingerprints(self, keys):
        wanted, out = set(keys), {}
        for a in self.analyses:  # insertion order = time order
            k = (a["cve_id"], a["host_id"])
            if k in wanted:
                out[k] = a["evidence"]["fingerprint"]
        return out

    def recall(self, embedding, k, exclude_run_id):
        def cos(a, b):
            num = sum(x * y for x, y in zip(a, b))
            den = (sum(x * x for x in a) ** 0.5) * (sum(y * y for y in b) ** 0.5)
            return num / den if den else 0.0

        scored = [(cos(embedding, a["embedding"]), a) for a in self.analyses
                  if a["embedding"] is not None and a["run_id"] != exclude_run_id]
        scored.sort(key=lambda t: -t[0])
        return [{"cve_id": a["cve_id"], "host_id": a["host_id"], "final_priority": a["final_priority"],
                 "rule_priority": a["rule_priority"], "guard_result": a["guard_result"],
                 "rationale": a["rationale"][:400], "similarity": round(sim, 3)} for sim, a in scored[:k]]

    def save_analyses(self, rows):
        self.analyses.extend(dict(r) for r in rows)
        return len(rows)

    def save_digest(self, run_id, markdown):
        self.digests[run_id] = markdown
