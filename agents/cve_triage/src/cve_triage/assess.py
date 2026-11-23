"""Checkpoint B selection and LLM assessment.

Which (CVE, host) pairs are assessed:
  - only matcher result `affected` (needs_review is counted in the digest, never sent to the LLM)
  - only if there is no analysis yet, or its fingerprint (result, CVSS, KEV) changed
  - route `llm` if CVSS >= TRIAGE_LLM_MIN_CVSS (default 7.0), KEV, or no CVSS yet;
    otherwise `rule-only` (rule floor stored as the final priority, no model call)
  - at most TRIAGE_LLM_CAP (default 40) LLM calls per run, most urgent first;
    the rest are stored rule-only with needs_review = true (route `cap`)

The model only ever sees one (CVE, host) pair plus its facts and recalled earlier
analyses. It never decides whether a host is affected.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from cve_triage.matcher import AFFECTED, Inventory, MatchResult, parse_cpe
from cve_triage.normalize import NormalizedCve
from cve_triage.priority import level, rule_priority

PROMPT_VERSION = "assess-v2"  # v2: rule_reason no longer calls critical internal hosts "exposed"
LLM, RULE_ONLY, CAP = "llm", "rule-only", "cap"
HOST_FIELDS = ("role", "zone", "criticality", "data_class", "owner", "compensating_controls", "patch_window")


class Assessment(BaseModel):
    """Structured output of the assess node (one CVE on one host)."""

    cve_id: str = Field(description="The CVE id you were given, unchanged")
    host_id: str = Field(description="The host id you were given, unchanged")
    priority: Literal["P1", "P2", "P3", "P4"] = Field(description="Final business priority")
    rationale: str = Field(description="2-4 sentences: why this priority for this host. Cite the facts used.")
    recommended_action: str = Field(description="One concrete next step for the system owner")
    cited_fields: list[str] = Field(description="Input fields the decision rests on, e.g. cvss_score, kev, "
                                                "zone, criticality, data_class, compensating_controls, "
                                                "description, recalled_analyses")
    compensating_control: str | None = Field(
        default=None,
        description="Only if priority is LOWER than rule_priority: one entry of host.compensating_controls, "
                    "copied verbatim. Otherwise null.")


def fingerprint(result: str, cve: NormalizedCve) -> dict[str, Any]:
    return {"result": result, "cvss": cve.cvss.score if cve.cvss else None, "kev": cve.kev_added}


@dataclass
class Candidate:
    cve_id: str
    host_id: str
    cpes: list[str]
    cve: dict[str, Any]          # compact CVE facts (no configurations)
    host: dict[str, Any]         # inventory facts for the host
    rule_priority: str
    rule_reason: str
    fingerprint: dict[str, Any]
    route: str = RULE_ONLY
    previous: dict[str, Any] | None = None   # fingerprint of the last analysis, if any
    recalled: list[dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return self.cve_id, self.host_id

    @property
    def products(self) -> list[str]:
        out = []
        for c in self.cpes:
            p = parse_cpe(c)
            out.append(f"{p.vendor} {p.product} {p.version}".replace("_", " "))
        return out


def select_candidates(matches: list[MatchResult], cves: dict[str, NormalizedCve], inventory: Inventory,
                      previous: dict[tuple[str, str], dict[str, Any]], *, min_cvss: float = 7.0,
                      cap: int = 40, llm_enabled: bool = True) -> tuple[list[Candidate], dict[str, int]]:
    hosts = {h.id: h for h in inventory.hosts}
    grouped: dict[tuple[str, str], list[str]] = {}
    for m in matches:
        if m.result == AFFECTED:
            grouped.setdefault((m.cve_id, m.host_id), []).append(m.cpe)

    stats = {"affected_pairs": len(grouped), "unchanged": 0, LLM: 0, RULE_ONLY: 0, CAP: 0}
    out: list[Candidate] = []
    for (cve_id, host_id), cpes in sorted(grouped.items()):
        cve = cves[cve_id]
        fp = fingerprint(AFFECTED, cve)
        prev = previous.get((cve_id, host_id))
        if prev == fp:
            stats["unchanged"] += 1
            continue
        meta = hosts[host_id].meta
        score = cve.cvss.score if cve.cvss else None
        rule, why = rule_priority(score, bool(cve.kev_added), meta.get("zone"), meta.get("criticality"))
        facts = cve.summary()
        facts["cvss_score"] = score
        out.append(Candidate(
            cve_id, host_id, sorted(set(cpes)), facts,
            {k: meta.get(k) for k in HOST_FIELDS}, rule, why, fp, previous=prev,
            route=LLM if (score is None or score >= min_cvss or cve.kev_added) else RULE_ONLY,
        ))

    eligible = sorted((c for c in out if c.route == LLM),
                      key=lambda c: (level(c.rule_priority), -(c.cve.get("cvss_score") or 10.0), c.key))
    for i, c in enumerate(eligible):
        if not llm_enabled or i >= cap:
            c.route = CAP
    for c in out:
        stats[c.route] += 1
    return out, stats


# ---------------------------------------------------------------- the model call

SYSTEM_PROMPT = """You are a vulnerability-management analyst at a regulated European bank.
You assess ONE CVE on ONE host. A deterministic matcher has already established that the host IS affected; \
do not question that.

A deterministic rule has set a priority floor (rule_priority). Your job is to refine it using the host's \
context (zone, criticality, data class, compensating controls, patch window), the CVE facts (CVSS vector, CWE, \
KEV status, description) and earlier analyses of similar cases (recalled_analyses), so priorities stay consistent.

Rules, enforced by an automatic check after you answer:
- Echo cve_id and host_id exactly as given.
- You may RAISE the priority whenever the facts justify it; say why.
- You may LOWER it by at most ONE level, and only if one of host.compensating_controls really mitigates this \
specific weakness. Then copy that control verbatim into compensating_control. Otherwise leave it null.
- Use only the facts given. Do not mention any CVE id other than this one or those in recalled_analyses. \
Do not invent hosts, versions, exploits or controls.
- P1 = act now (emergency change), P2 = next patch window at the latest, P3 = regular cycle, P4 = backlog."""


def build_prompt(c: Candidate) -> list[tuple[str, str]]:
    facts = {
        "cve_id": c.cve_id,
        "host_id": c.host_id,
        "rule_priority": c.rule_priority,
        "rule_reason": c.rule_reason,
        "cve": {k: c.cve.get(k) for k in ("cvss_score", "cvss", "cwe", "kev_added", "kev_action_due",
                                          "kev_required_action", "status", "published", "description")},
        "affected_software": c.products,
        "host": c.host,
        "recalled_analyses": c.recalled,
    }
    return [("system", SYSTEM_PROMPT), ("human", json.dumps(facts, indent=1, default=str))]


@dataclass
class Outcome:
    assessment: Assessment | None
    error: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0


class Assessor(Protocol):
    model: str

    def __call__(self, candidates: list[Candidate]) -> list[Outcome]: ...


PROVIDERS = {"anthropic": ("claude-haiku-5-5", "ANTHROPIC_API_KEY"),
             "openai": ("gpt-6-luna", "OPENAI_API_KEY")}


class LLMAssessor:
    """Claude (langchain-anthropic) or GPT (langchain-openai), structured output, traced in
    LangSmith as child runs. Same prompt, schema and guard for both providers; the model name
    on every analysis row is stored as "<provider>:<model>"."""

    def __init__(self, provider: str = "anthropic", model: str | None = None, max_concurrency: int = 4,
                 reasoning_effort: str | None = None):
        if provider not in PROVIDERS:
            raise ValueError(f"unknown provider {provider!r}; use one of {sorted(PROVIDERS)}")
        model = model or PROVIDERS[provider][0]
        self.model = f"{provider}:{model}"
        self.max_concurrency = max_concurrency
        if provider == "anthropic":
            from langchain_anthropic import ChatAnthropic

            llm = ChatAnthropic(model=model, max_tokens=1024, timeout=60, max_retries=2)
        else:
            from langchain_openai import ChatOpenAI

            # Reasoning models spend output tokens on reasoning; "low" is enough for a P1-P4 call
            llm = ChatOpenAI(model=model, timeout=60, max_retries=2,
                             reasoning_effort=reasoning_effort or "low")
        self.llm = llm
        self.chain = llm.with_structured_output(Assessment, include_raw=True)

    def __call__(self, candidates: list[Candidate]) -> list[Outcome]:
        if not candidates:
            return []
        results = self.chain.batch(
            [build_prompt(c) for c in candidates],
            config={"max_concurrency": self.max_concurrency, "run_name": "assess",
                    "metadata": {"prompt_version": PROMPT_VERSION}},
            return_exceptions=True,
        )
        out = []
        for r in results:
            if isinstance(r, Exception):
                out.append(Outcome(None, f"{type(r).__name__}: {r}"[:500]))
                continue
            usage = getattr(r.get("raw"), "usage_metadata", None) or {}
            err = r.get("parsing_error")
            out.append(Outcome(r.get("parsed"), f"parsing error: {err}"[:500] if err else None,
                               usage.get("input_tokens", 0), usage.get("output_tokens", 0)))
        return out
