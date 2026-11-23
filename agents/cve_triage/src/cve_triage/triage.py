"""CVE triage agent (Q-2.1-04), checkpoints A + B.

    fetch_nvd -> normalize -> match_inventory -> persist -> select -> recall -> assess
              -> guard -> persist_analyses -> summarize -> digest
    (no matches / nothing new: straight to summarize -> digest)

Checkpoint A (deterministic): window since the last successful run, NVD fetch with a
pre-filter, normalise, CPE/version match, store runs/CVEs/matches.

Checkpoint B:
- select: affected (CVE, host) pairs that are new or whose (result, CVSS, KEV) changed
  since the last analysis; route llm / rule-only / cap (see assess.py)
- recall: local embedding of each case, top-k similar earlier analyses from pgvector
- assess: TRIAGE_LLM_PROVIDER anthropic (default claude-haiku-5-5) or openai (default gpt-6-luna),
  TRIAGE_LLM_MODEL overrides the model; structured output
- guard: deterministic checks (priority.py); the rule floor wins on any doubt
- persist_analyses: append-only rows in cve.analyses, with embedding and evidence
- digest: markdown in cve.digests (and on stdout)

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
from cve_triage.assess import CAP, LLM, PROMPT_VERSION, Assessor, Candidate, Outcome, select_candidates
from cve_triage.db import Store
from cve_triage.digest import render
from cve_triage.matcher import AFFECTED, NEEDS_REVIEW, Inventory, MatchResult, match_cve
from cve_triage.memory import Embedder, case_text
from cve_triage.normalize import NormalizedCve, normalize
from cve_triage.priority import guard as run_guard

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
    # checkpoint B
    trace_id: str
    assess_candidates: list[Candidate]
    assess_stats: dict[str, int]
    outcomes: dict[str, Outcome]          # "cve|host" -> model outcome (llm route only)
    analyses: list[dict[str, Any]]        # rows written to cve.analyses (embedding stripped)
    stored_analyses: int
    digest: str


class Settings(TypedDict, total=False):
    min_cvss: float        # TRIAGE_LLM_MIN_CVSS, default 7.0
    cap: int               # TRIAGE_LLM_CAP, default 40
    recall_k: int          # TRIAGE_RECALL_K, default 3
    price_in: float | None   # USD per million input tokens (TRIAGE_PRICE_IN_PER_MTOK)
    price_out: float | None  # USD per million output tokens (TRIAGE_PRICE_OUT_PER_MTOK)


DEFAULT_SETTINGS: Settings = {"min_cvss": 7.0, "cap": 40, "recall_k": 3, "price_in": None, "price_out": None}


def _k(cve_id: str, host_id: str) -> str:
    return f"{cve_id}|{host_id}"


def _parse_ts(value: str) -> datetime:
    ts = datetime.fromisoformat(value)
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def compute_window(store: Store, now: datetime | None = None, backfill_days: int = 7,
                   start_override: str | None = None,
                   end_override: str | None = None) -> tuple[datetime, datetime]:
    end = _parse_ts(end_override) if end_override else (now or datetime.now(UTC)).replace(microsecond=0)
    if start_override:
        start = _parse_ts(start_override)
    else:
        last = store.last_ok_window_end()
        start = (last - OVERLAP) if last else end - timedelta(days=backfill_days)
    if start >= end:
        raise ValueError(f"empty window: {start.isoformat()} >= {end.isoformat()}")
    return start.astimezone(UTC), end.astimezone(UTC)


def build_graph(store: Store, inventory: Inventory, fetch_pages: PageFetcher = nvd.iter_modified,
                assessor: Assessor | None = None, embedder: Embedder | None = None,
                settings: Settings | None = None):
    cfg: Settings = {**DEFAULT_SETTINGS, **(settings or {})}
    model_name = getattr(assessor, "model", None) or "none"
    embeddings: dict[str, list[float]] = {}   # kept out of graph state, so traces stay small

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

    def route_matches(state: State) -> str:
        return "persist" if state["matches"] else "summarize"

    def persist(state: State) -> State:
        matched_ids = {m.cve_id for m in state["matches"]}
        raw_by_id = {r["id"]: r for r in state["candidates"]}
        cves = [(n, raw_by_id[n.cve_id]) for n in state["normalized"] if n.cve_id in matched_ids]
        return {
            "stored_cves": store.save_cves(cves),
            "stored_matches": store.save_matches(state["run_id"], state["matches"]),
        }

    # ------------------------------------------------------------ checkpoint B

    def select(state: State) -> State:
        by_id = {n.cve_id: n for n in state["normalized"]}
        keys = sorted({(m.cve_id, m.host_id) for m in state["matches"] if m.result == AFFECTED})
        previous = store.latest_fingerprints(keys)
        cands, stats = select_candidates(state["matches"], by_id, inventory, previous,
                                         min_cvss=cfg["min_cvss"], cap=cfg["cap"],
                                         llm_enabled=assessor is not None)
        return {"assess_candidates": cands, "assess_stats": stats}

    def route_selected(state: State) -> str:
        return "recall" if state["assess_candidates"] else "summarize"

    def recall(state: State) -> State:
        cands = state["assess_candidates"]
        if embedder is None:
            return {}
        vectors = embedder([case_text(c) for c in cands])
        for c, v in zip(cands, vectors):
            embeddings[_k(*c.key)] = v
            if c.route == LLM:
                c.recalled = store.recall(v, cfg["recall_k"], state["run_id"])
        return {"assess_candidates": cands}

    def assess(state: State) -> State:
        todo = [c for c in state["assess_candidates"] if c.route == LLM]
        if not todo or assessor is None:
            return {"outcomes": {}}
        return {"outcomes": {_k(*c.key): o for c, o in zip(todo, assessor(todo))}}

    def guard_node(state: State) -> State:
        rows = []
        for c in state["assess_candidates"]:
            controls = list(c.host.get("compensating_controls") or [])
            base_evidence = {
                "fingerprint": c.fingerprint, "previous_fingerprint": c.previous, "route": c.route,
                "cpes": c.cpes, "rule_reason": c.rule_reason,
                "cvss": c.cve.get("cvss_score"), "kev": c.cve.get("kev_added"),
                "recalled": [{"cve_id": r["cve_id"], "host_id": r["host_id"],
                              "final_priority": r["final_priority"], "similarity": r.get("similarity")}
                             for r in c.recalled],
            }
            if c.route == LLM:
                o = state["outcomes"].get(_k(*c.key)) or Outcome(None, "no outcome")
                a = o.assessment
                g = run_guard(cve_id=c.cve_id, host_id=c.host_id, rule=c.rule_priority, controls=controls,
                              output=a, error=o.error,
                              allowed_cve_ids={r["cve_id"] for r in c.recalled})
                rationale = (a.rationale.strip() if a and g.result != "rejected" else "") or \
                    f"Rule priority kept: {c.rule_reason}. Model output rejected by guard."
                evidence = {**base_evidence,
                            "model_priority": a.priority if a else None,
                            "cited_fields": a.cited_fields if a else [],
                            "compensating_control": a.compensating_control if a else None,
                            "guard_reasons": g.reasons, "model_error": o.error,
                            "tokens": {"input": o.input_tokens, "output": o.output_tokens}}
                rows.append(dict(final_priority=g.final_priority, guard_result=g.result,
                                 needs_review=g.needs_review, rationale=rationale,
                                 recommended_action=a.recommended_action if a else None,
                                 model=model_name, evidence=evidence, _c=c))
            else:
                why = ("over the LLM cap for this run" if assessor is not None
                       else "LLM disabled") if c.route == CAP else \
                    f"below the LLM threshold (CVSS < {cfg['min_cvss']}, not KEV)"
                evidence = {**base_evidence, "guard_reasons": [f"rule-only: {why}"]}
                if c.route == CAP:
                    # deferred: the fingerprint never equals a real one, so the pair is assessed
                    # by the model the next time it appears (new NVD version or a window replay)
                    evidence["fingerprint"] = {**c.fingerprint, "deferred": True}
                rows.append(dict(final_priority=c.rule_priority, guard_result="passed",
                                 needs_review=c.route == CAP,
                                 rationale=f"Rule priority: {c.rule_reason}. Not sent to the model: {why}.",
                                 recommended_action=None, model="rule-only", evidence=evidence, _c=c))
        analyses = []
        for r in rows:
            c: Candidate = r.pop("_c")
            analyses.append({**r, "run_id": state["run_id"], "cve_id": c.cve_id, "host_id": c.host_id,
                             "rule_priority": c.rule_priority, "prompt_version": PROMPT_VERSION,
                             "langsmith_run_id": state.get("trace_id")})
        return {"analyses": analyses}

    def persist_analyses(state: State) -> State:
        rows = [{**a, "embedding": embeddings.get(_k(a["cve_id"], a["host_id"]))} for a in state["analyses"]]
        return {"stored_analyses": store.save_analyses(rows)}

    # ------------------------------------------------------------ report

    def summarize(state: State) -> State:
        matches = state.get("matches", [])
        by_result = Counter(m.result for m in matches)
        by_host: dict[str, Counter] = {}
        for m in matches:
            by_host.setdefault(m.host_id, Counter())[m.result] += 1
        actionable = [m for m in matches if m.result in (AFFECTED, NEEDS_REVIEW)]
        analyses = state.get("analyses", [])
        tin = sum(a["evidence"].get("tokens", {}).get("input", 0) for a in analyses)
        tout = sum(a["evidence"].get("tokens", {}).get("output", 0) for a in analyses)
        cost = None
        if cfg["price_in"] is not None and cfg["price_out"] is not None:
            cost = round(tin / 1e6 * cfg["price_in"] + tout / 1e6 * cfg["price_out"], 4)
        nr = [m for m in matches if m.result == NEEDS_REVIEW]
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
            "needs_review": {"rows": len(nr), "cves": len({m.cve_id for m in nr})},
            "assessment": state.get("assess_stats", {}),
            "guard": dict(sorted(Counter(a["guard_result"] for a in analyses).items())),
            "final_priority": dict(sorted(Counter(a["final_priority"] for a in analyses).items())),
            "stored_analyses": state.get("stored_analyses", 0),
            "usage": {"input_tokens": tin, "output_tokens": tout, "cost_usd": cost},
            "model": model_name,
            "prompt_version": PROMPT_VERSION,
            "langsmith_run_id": state.get("trace_id"),
        }
        return {"summary": summary}

    def digest(state: State) -> State:
        md = render(state["summary"], state.get("analyses", []))
        store.save_digest(state["run_id"], md)
        return {"digest": md}

    g = StateGraph(State)
    for name, fn in [("fetch_nvd", fetch_nvd), ("normalize", normalize_node),
                     ("match_inventory", match_inventory), ("persist", persist), ("select", select),
                     ("recall", recall), ("assess", assess), ("guard", guard_node),
                     ("persist_analyses", persist_analyses), ("summarize", summarize), ("digest", digest)]:
        g.add_node(name, fn)
    g.add_edge(START, "fetch_nvd")
    g.add_edge("fetch_nvd", "normalize")
    g.add_edge("normalize", "match_inventory")
    g.add_conditional_edges("match_inventory", route_matches, ["persist", "summarize"])
    # Neither model nor embedder: checkpoint-A behaviour (deterministic part only)
    g.add_conditional_edges("persist", lambda _: "select" if (assessor or embedder) else "summarize",
                            ["select", "summarize"])
    g.add_conditional_edges("select", route_selected, ["recall", "summarize"])
    g.add_edge("recall", "assess")
    g.add_edge("assess", "guard")
    g.add_edge("guard", "persist_analyses")
    g.add_edge("persist_analyses", "summarize")
    g.add_edge("summarize", "digest")
    g.add_edge("digest", END)
    return g.compile()


def run(store: Store, inventory: Inventory, fetch_pages: PageFetcher = nvd.iter_modified,
        *, now: datetime | None = None, backfill_days: int = 7,
        start_override: str | None = None, end_override: str | None = None,
        assessor: Assessor | None = None, embedder: Embedder | None = None,
        settings: Settings | None = None) -> dict[str, Any]:
    """One full run with bookkeeping in cve.runs. Returns the summary (digest under "digest")."""
    start, end = compute_window(store, now, backfill_days, start_override, end_override)
    run_id = store.start_run(start, end)
    trace_id = str(uuid.uuid4())
    try:
        out = build_graph(store, inventory, fetch_pages, assessor, embedder, settings).invoke(
            {"run_id": run_id, "window_start": start.isoformat(), "window_end": end.isoformat(),
             "trace_id": trace_id},
            config={"run_name": "cve-triage", "run_id": trace_id,
                    "tags": ["q-2.1-04", "checkpoint-b"], "metadata": {"db_run_id": run_id}},
        )
    except Exception as exc:
        store.finish_run(run_id, status="failed", langsmith_trace=trace_id,
                         error=f"{type(exc).__name__}: {exc}"[:2000])
        raise
    s = out["summary"]
    store.finish_run(run_id, status="ok", cves_fetched=s["fetched"],
                     matches_found=s["by_result"].get(AFFECTED, 0) + s["by_result"].get(NEEDS_REVIEW, 0),
                     langsmith_trace=trace_id, cost_usd=s["usage"]["cost_usd"])
    s["digest"] = out.get("digest", "")
    return s


def _float_env(name: str) -> float | None:
    v = os.getenv(name)
    return float(v) if v else None


def main() -> None:
    from cve_triage.assess import PROVIDERS, LLMAssessor
    from cve_triage.db import PostgresStore
    from cve_triage.memory import FastEmbedder

    inventory = Inventory.load(os.getenv("CVE_INVENTORY") or DEFAULT_INVENTORY)
    llm_on = os.getenv("TRIAGE_LLM", "on").lower() not in ("off", "0", "false")
    provider = (os.getenv("TRIAGE_LLM_PROVIDER") or "anthropic").lower()
    if provider not in PROVIDERS:
        raise SystemExit(f"TRIAGE_LLM_PROVIDER must be one of {sorted(PROVIDERS)}, not {provider!r}")
    key_var = PROVIDERS[provider][1]
    if llm_on and not os.getenv(key_var):
        raise SystemExit(f"{key_var} is not set for provider {provider} (or set TRIAGE_LLM=off for a rule-only run)")
    assessor = LLMAssessor(provider, os.getenv("TRIAGE_LLM_MODEL") or None,
                           reasoning_effort=os.getenv("TRIAGE_LLM_REASONING_EFFORT") or None) if llm_on else None
    settings: Settings = {
        "min_cvss": float(os.getenv("TRIAGE_LLM_MIN_CVSS") or 7.0),
        "cap": int(os.getenv("TRIAGE_LLM_CAP") or 40),
        "recall_k": int(os.getenv("TRIAGE_RECALL_K") or 3),
        "price_in": _float_env("TRIAGE_PRICE_IN_PER_MTOK"),
        "price_out": _float_env("TRIAGE_PRICE_OUT_PER_MTOK"),
    }
    store = PostgresStore()
    try:
        summary = run(store, inventory, backfill_days=int(os.getenv("TRIAGE_BACKFILL_DAYS", "7")),
                      start_override=os.getenv("TRIAGE_WINDOW_START") or None,
                      end_override=os.getenv("TRIAGE_WINDOW_END") or None,
                      assessor=assessor, embedder=FastEmbedder(), settings=settings)
    finally:
        store.close()
        try:
            from langchain_core.tracers.langchain import wait_for_all_tracers

            wait_for_all_tracers()
        except ImportError:
            pass
    digest = summary.pop("digest", "")
    print(json.dumps(summary, indent=2, default=str))
    if os.getenv("TRIAGE_PRINT_DIGEST", "true").lower() not in ("false", "0", "off"):
        print("\n" + "-" * 72 + "\n" + digest)


if __name__ == "__main__":
    main()
