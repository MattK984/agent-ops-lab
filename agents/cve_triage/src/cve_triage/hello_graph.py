"""Q-2.1-03 hello world: fetch the CVEs NVD published in the last 24 h and count them.

Three-node LangGraph graph, traced in LangSmith when LANGSMITH_TRACING=true and
LANGSMITH_API_KEY are set. No LLM, no database: this proves the runtime,
the NVD access and the tracing path before the real agent is built.

    python -m cve_triage.hello_graph            # or: docker compose run --rm cve-triage
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from cve_triage import nvd


class State(TypedDict, total=False):
    hours: int
    window_start: str
    window_end: str
    total: int
    by_severity: dict[str, int]
    sample: list[str]


def set_window(state: State) -> State:
    end = datetime.now(UTC).replace(microsecond=0)
    start = end - timedelta(hours=state.get("hours", 24))
    return {"window_start": start.isoformat(), "window_end": end.isoformat()}


def fetch_nvd(state: State) -> State:
    records = nvd.fetch_published(
        datetime.fromisoformat(state["window_start"]),
        datetime.fromisoformat(state["window_end"]),
    )
    counts = Counter(nvd.severity(r) for r in records)
    return {
        "total": len(records),
        "by_severity": dict(sorted(counts.items())),
        "sample": [r["id"] for r in records[:5]],
    }


def summarize(state: State) -> State:
    print(json.dumps(
        {k: state.get(k) for k in ("window_start", "window_end", "total", "by_severity", "sample")},
        indent=2,
    ))
    return {}


def build_graph():
    g = StateGraph(State)
    g.add_node("set_window", set_window)
    g.add_node("fetch_nvd", fetch_nvd)
    g.add_node("summarize", summarize)
    g.add_edge(START, "set_window")
    g.add_edge("set_window", "fetch_nvd")
    g.add_edge("fetch_nvd", "summarize")
    g.add_edge("summarize", END)
    return g.compile()


def main() -> None:
    graph = build_graph()
    graph.invoke(
        {"hours": int(os.getenv("HELLO_HOURS", "24"))},
        config={"run_name": "hello-nvd", "tags": ["q-2.1-03", "hello-world"]},
    )
    # Short-lived process: make sure traces are sent before exit.
    try:
        from langchain_core.tracers.langchain import wait_for_all_tracers

        wait_for_all_tracers()
    except ImportError:
        pass
    if os.getenv("LANGSMITH_TRACING", "").lower() == "true":
        print(f"Trace sent to LangSmith project '{os.getenv('LANGSMITH_PROJECT', 'default')}'.")


if __name__ == "__main__":
    main()
