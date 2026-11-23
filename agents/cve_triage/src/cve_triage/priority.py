"""Rule priority floor and the deterministic guard around the LLM assessment.

Priority rules (product brief, "Priority rules"):

    P1  CVSS >= 9.0 on an exposed host, or CVE in CISA KEV on any affected host
    P2  CVSS >= 7.0 on an exposed host, or CVSS >= 9.0 anywhere else
    P3  CVSS >= 4.0, or no CVSS yet (unknown is not low)
    P4  everything else

"Exposed" = zone `internet` or `dmz`, or criticality `critical`.

The guard never trusts the model: it checks identity (no invented CVE or host),
the schema, a non-empty rationale, and the direction of any change against
the floor. Raising is free; lowering is allowed by one level at most, and only
when the model names a compensating control that the inventory lists for that
host, verbatim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

PRIORITIES = ("P1", "P2", "P3", "P4")
EXPOSED_ZONES = {"internet", "dmz"}
PASSED, CORRECTED, REJECTED = "passed", "corrected", "rejected"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def level(p: str) -> int:
    """0 = most urgent (P1) ... 3 = P4."""
    return PRIORITIES.index(p)


def rule_priority(cvss: float | None, kev: bool, zone: str | None,
                  criticality: str | None) -> tuple[str, str]:
    exposed = (zone or "") in EXPOSED_ZONES or (criticality or "") == "critical"
    where = f"zone={zone}, criticality={criticality}"
    if kev:
        return "P1", "CVE is in CISA KEV (known exploited)"
    if cvss is None:
        return "P3", "no CVSS score yet; unknown is not treated as low"
    if cvss >= 9.0 and exposed:
        return "P1", f"CVSS {cvss} >= 9.0 on an exposed host ({where})"
    if cvss >= 7.0 and exposed:
        return "P2", f"CVSS {cvss} >= 7.0 on an exposed host ({where})"
    if cvss >= 9.0:
        return "P2", f"CVSS {cvss} >= 9.0 on a non-exposed host ({where})"
    if cvss >= 4.0:
        return "P3", f"CVSS {cvss} >= 4.0"
    return "P4", f"CVSS {cvss} < 4.0"


@dataclass
class GuardResult:
    final_priority: str
    result: str                 # passed | corrected | rejected
    needs_review: bool
    reasons: list[str] = field(default_factory=list)


def _norm(s: str) -> str:
    return " ".join(s.split()).casefold()


def guard(*, cve_id: str, host_id: str, rule: str, controls: list[str],
          output: Any | None, error: str | None = None,
          allowed_cve_ids: set[str] | None = None) -> GuardResult:
    """Check one LLM assessment (`output` has the Assessment fields) against the facts.

    `allowed_cve_ids`: CVE ids the text may mention (this CVE + recalled ones).
    """
    def reject(why: str) -> GuardResult:
        return GuardResult(rule, REJECTED, True, [why, f"rule priority {rule} stands"])

    if output is None:
        return reject(f"no usable model output ({error or 'empty'})")
    if getattr(output, "cve_id", None) != cve_id or getattr(output, "host_id", None) != host_id:
        return reject(f"identity mismatch: model answered for {getattr(output, 'cve_id', None)} / "
                      f"{getattr(output, 'host_id', None)}, expected {cve_id} / {host_id}")
    prio = getattr(output, "priority", None)
    if prio not in PRIORITIES:
        return reject(f"invalid priority {prio!r}")
    rationale = (getattr(output, "rationale", "") or "").strip()
    if not rationale:
        return reject("empty rationale")
    allowed = {c.upper() for c in (allowed_cve_ids or set())} | {cve_id.upper()}
    text = f"{rationale} {getattr(output, 'recommended_action', '') or ''}"
    invented = sorted({m.upper() for m in _CVE_RE.findall(text)} - allowed)
    if invented:
        return reject(f"mentions CVE ids that are not in the evidence: {', '.join(invented)}")

    delta = level(prio) - level(rule)          # > 0 means the model lowered the priority
    if delta <= 0:
        return GuardResult(prio, PASSED, False,
                           ["raised above rule floor" if delta < 0 else "agrees with rule floor"])

    cited = getattr(output, "compensating_control", None) or ""
    valid = {_norm(c) for c in controls}
    if not cited.strip() or _norm(cited) not in valid:
        why = ("lowered without citing a compensating control" if not cited.strip()
               else f"cited control {cited!r} is not listed for {host_id}")
        return GuardResult(rule, CORRECTED, False, [why, f"reset to rule priority {rule}"])
    if delta > 1:
        clamped = PRIORITIES[level(rule) + 1]
        return GuardResult(clamped, CORRECTED, False,
                           [f"lowered {rule} -> {prio} exceeds one level", f"clamped to {clamped}"])
    return GuardResult(prio, PASSED, False, [f"lowered one level citing control: {cited.strip()}"])
