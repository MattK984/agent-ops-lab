"""CVE triage agent, checkpoint A (Q-2.1-04): deterministic part, no LLM.

    fetch_nvd -> normalize -> match_inventory -> persist -> summarize
                                    \\-- no matches --------------/

- Window: lastModified since the end of the last successful run (minus a small
  overlap for NVD indexing lag); first run: TRIAGE_BACKFILL_DAYS (default 7).
- fetch_nvd pages through NVD and keeps only records that could concern an
  inventory product, so a large window never sits in memory or in the trace.
- Only CVEs with at least one match row are stored in cve.cves.
- Every run is recorded in cve.runs (ok / failed) with its LangSmith run id.

    python -m cve_triage.triage            # or: docker compose run --rm cve-triage
"""

from __future__ import annotations

import json
import os
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from cve_triage import nvd
from cve_triage.db import Store
from cve_triage.matcher import AFFECTED, NEEDS_REVIEW, Inventory, MatchResult, match_cve
from cve_triage.normalize import NormalizedCve, normalize

DEFAULT_INVENTORY = "/app/inventory/bank-estate.yaml"
OVERLAP = timedelta(minutes=15)  # re-read the tail of the last window; upserts are idempotent

PageFetcher = Callable[[datetime, datetime], Iterator[list[dict[str, Any]]]]


class State(TypedDict, total=False):
    run_id: int
    window_start: str
    window_end: str
    fetched: int
    candidates: list[dict[str, Any]]   # raw NVD records that passed the pre-filter
    normalized: list[NormalizedCve]
    matches: list[MatchResult]
    stored_cves: int
    stored_matches: int
    summary: dict[str, Any]


def compute_window(store: Store, now: datetime | None = None, backfill_days: int = 7) -> tuple[datetime, datetime]:
    end = (now or datetime.now(UTC)).replace(microsecond=0)
    last = store.last_ok_window_end()
    start = (last - OVERLAP) if last else end - timedelta(days=backfill_days)
    return start.astimezone(UTC), end.astimezone(UTC)


def build_graph(store: Store, inventory: Inventory, fetch_pages: PageFetcher = nvd.iter_modified):

    def fetch_nvd(state: State) -> State:
        fetched, keep = 0, []
        for page in fetch_pages(datetime.fromisoformat(state["window_start"]),
                                datetime.fromisoformat(state["window_end"])):
            fetched += len(page)
            keep.extend(r for r in page if inventory.is_candidate(r))
        return {"fetched": fetched, "candidates": keep}

    def normalize_node(state: State) -> State:
        return {"normalized": [normalize(r) for r in state["candidates"]]}

    def match_inventory(state: State) -> State:
        out: list[MatchResult] = []
        for cve in state["normalized"]:
            out.extend(match_cve(cve, inventory))
        return {"matches": out}

    def route(state: State) -> str:
        return "persist" if state["matches"] else "summarize"

    def persist(state: State) -> State:
        matched_ids = {m.cve_id for m in state["matches"]}
        raw_by_id = {r["id"]: r for r in state["candidates"]}
        cves = [(n, raw_by_id[n.cve_id]) for n in state["normalized"] if n.cve_id in matched_ids]
        return {
            "stored_cves": store.save_cves(cves),
            "stored_matches": store.save_matches(state["run_id"], state["matches"]),
        }

    def summarize(state: State) -> State:
        matches = state.get("matches", [])
        by_result = Counter(m.result for m in matches)
        by_host: dict[str, Counter] = {}
        for m in matches:
            by_host.setdefault(m.host_id, Counter())[m.result] += 1
        actionable = [m for m in matches if m.result in (AFFECTED, NEEDS_REVIEW)]
        summary = {
            "run_id": state["run_id"],
            "window_start": state["window_start"],
            "window_end": state["window_end"],
            "fetched": state.get("fetched", 0),
            "candidates": len(state.get("candidates", [])),
            "match_rows": len(matches),
            "by_result": dict(sorted(by_result.items())),
            "by_host": {h: dict(sorted(c.items())) for h, c in sorted(by_host.items())},
            "actionable_sample": [f"{m.cve_id} -> {m.host_id} ({m.result})" for m in actionable[:15]],
            "stored_cves": state.get("stored_cves", 0),
        }
        return {"summary": summary}

    g = StateGraph(State)
    g.add_node("fetch_nvd", fetch_nvd)
    g.add_node("normalize", normalize_node)
    g.add_node("match_inventory", match_inventory)
    g.add_node("persist", persist)
    g.add_node("summarize", summarize)
    g.add_edge(START, "fetch_nvd")
    g.add_edge("fetch_nvd", "normalize")
    g.add_edge("normalize", "match_inventory")
    g.add_conditional_edges("match_inventory", route, ["persist", "summarize"])
    g.add_edge("persist", "summarize")
    g.add_edge("summarize", END)
    return g.compile()


def run(store: Store, inventory: Inventory, fetch_pages: PageFetcher = nvd.iter_modified,
        *, now: datetime | None = None, backfill_days: int = 7) -> dict[str, Any]:
    """One full run with bookkeeping in cve.runs. Returns the summary."""
    start, end = compute_window(store, now, backfill_days)
    run_id = store.start_run(start, end)
    trace_id = str(uuid.uuid4())
    try:
        out = build_graph(store, inventory, fetch_pages).invoke(
            {"run_id": run_id, "window_start": start.isoformat(), "window_end": end.isoformat()},
            config={"run_name": "cve-triage-a", "run_id": trace_id,
                    "tags": ["q-2.1-04", "checkpoint-a"], "metadata": {"db_run_id": run_id}},
        )
    except Exception as exc:
        store.finish_run(run_id, status="failed", langsmith_trace=trace_id,
                         error=f"{type(exc).__name__}: {exc}"[:2000])
        raise
    s = out["summary"]
    store.finish_run(run_id, status="ok", cves_fetched=s["fetched"],
                     matches_found=s["by_result"].get(AFFECTED, 0) + s["by_result"].get(NEEDS_REVIEW, 0),
                     langsmith_trace=trace_id)
    s["langsmith_run_id"] = trace_id
    return s


def main() -> None:
    from cve_triage.db import PostgresStore

    inventory = Inventory.load(os.getenv("CVE_INVENTORY") or DEFAULT_INVENTORY)
    store = PostgresStore()
    try:
        summary = run(store, inventory, backfill_days=int(os.getenv("TRIAGE_BACKFILL_DAYS", "7")))
    finally:
        store.close()
        try:
            from langchain_core.tracers.langchain import wait_for_all_tracers

            wait_for_all_tracers()
        except ImportError:
            pass
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
