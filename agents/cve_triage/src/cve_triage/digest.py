"""Markdown digest of one triage run (deterministic template, no LLM).

P1 and P2 are listed in full; P3 and P4 as counts per host plus the top rows, so a
kernel-heavy week stays readable. Stored in cve.digests; delivery is Q-2.1-05.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

DETAIL = ("P1", "P2")
TOP_LOW = 5


def _kev(a: dict[str, Any]) -> str:
    return "KEV" if a.get("kev") else ""


def _guard(a: dict[str, Any]) -> str:
    g = a["guard_result"]
    if a["route"] != "llm":
        return "rule-only" + (" (over cap)" if a["route"] == "cap" else "")
    if g == "passed" and a["final_priority"] != a["rule_priority"]:
        return f"model {a['rule_priority']}→{a['final_priority']}"
    return g


def _cell(s: Any, n: int = 160) -> str:
    s = " ".join(str(s or "").split()).replace("|", "/")
    return s if len(s) <= n else s[: n - 1] + "…"


def _view(a: dict[str, Any]) -> dict[str, Any]:
    ev = a.get("evidence") or {}
    return {**a, "route": ev.get("route", "llm"), "cvss": ev.get("cvss"), "kev": ev.get("kev"),
            "guard_reason": "; ".join(ev.get("guard_reasons") or [])}


def render(summary: dict[str, Any], analyses: list[dict[str, Any]]) -> str:
    s = summary
    analyses = [_view(a) for a in analyses]
    a_stats = s.get("assessment", {})
    guard = Counter(a["guard_result"] for a in analyses)
    by_prio: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in analyses:
        by_prio[a["final_priority"]].append(a)
    for rows in by_prio.values():
        rows.sort(key=lambda a: (-(a.get("cvss") or 0), a["host_id"], a["cve_id"]))

    lines = [
        f"# CVE triage digest · run {s['run_id']}",
        "",
        f"Window {s['window_start'][:16]} → {s['window_end'][:16]} UTC · Musterbank AG (synthetic estate)",
        "",
        "| | |",
        "|---|---|",
        f"| CVEs read from NVD | {s.get('fetched', 0)} |",
        f"| Affected (CVE × host) | {a_stats.get('affected_pairs', 0)} · new or changed: "
        f"{len(analyses)} · unchanged, already assessed: {a_stats.get('unchanged', 0)} |",
        f"| Assessed by model / rule only / over cap | {a_stats.get('llm', 0)} / {a_stats.get('rule-only', 0)}"
        f" / {a_stats.get('cap', 0)} |",
        f"| Guard passed / corrected / rejected | {guard.get('passed', 0)} / {guard.get('corrected', 0)}"
        f" / {guard.get('rejected', 0)} |",
        f"| Priorities P1 / P2 / P3 / P4 | " + " / ".join(str(len(by_prio.get(p, []))) for p in
                                                           ("P1", "P2", "P3", "P4")) + " |",
    ]
    usage = s.get("usage", {})
    if usage.get("input_tokens"):
        cost = usage.get("cost_usd")
        lines.append(f"| Model usage | {usage['input_tokens']:,} in / {usage['output_tokens']:,} out tokens"
                     + (f" · ${cost:.4f}" if cost is not None else "") + " |")
    nr = s.get("needs_review", {})
    if nr.get("rows"):
        lines.append(f"| Waiting for NVD analysis (not assessed) | {nr['rows']} rows, {nr['cves']} CVEs |")

    if not analyses:
        lines += ["", "Nothing new or changed in this window."]
        return "\n".join(lines) + "\n"

    for p in DETAIL:
        rows = by_prio.get(p, [])
        lines += ["", f"## {p} · {len(rows)}"]
        if not rows:
            lines.append("None.")
            continue
        lines += ["", "| Host | CVE | CVSS | | Action | Check |", "|---|---|---|---|---|---|"]
        for a in rows:
            lines.append(f"| {a['host_id']} | [{a['cve_id']}](https://nvd.nist.gov/vuln/detail/{a['cve_id']}) | "
                         f"{a.get('cvss') if a.get('cvss') is not None else '–'} | {_kev(a)} | "
                         f"{_cell(a.get('recommended_action'))} | {_guard(a)} |")

    low = [a for p in ("P3", "P4") for a in by_prio.get(p, [])]
    if low:
        per_host = Counter((a["host_id"], a["final_priority"]) for a in low)
        lines += ["", f"## P3 / P4 · {len(low)}", ""]
        lines.append(" · ".join(f"{h} {p}: {n}" for (h, p), n in sorted(per_host.items())))
        lines += ["", f"Top {min(TOP_LOW, len(low))} by CVSS:", ""]
        for a in sorted(low, key=lambda a: -(a.get("cvss") or 0))[:TOP_LOW]:
            lines.append(f"- {a['final_priority']} {a['host_id']} {a['cve_id']} "
                         f"(CVSS {a.get('cvss') if a.get('cvss') is not None else '–'}, {_guard(a)})")

    flagged = [a for a in analyses if a["needs_review"]]
    if flagged:
        lines += ["", f"## Needs human review · {len(flagged)}", ""]
        for a in flagged[:20]:
            lines.append(f"- {a['host_id']} {a['cve_id']} {a['final_priority']}: {_cell(a.get('guard_reason'), 200)}")

    lines += ["", f"_Trace: LangSmith run `{s.get('langsmith_run_id', '')}` · prompt {s.get('prompt_version', '')}"
                  f" · model {s.get('model', '')}_"]
    return "\n".join(lines) + "\n"
