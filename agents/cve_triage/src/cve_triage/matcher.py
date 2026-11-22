"""Deterministic matcher: which inventory hosts does a CVE affect?

No LLM here. For every host software CPE whose vendor:product appears in a
CVE's *vulnerable* CPE criteria, the matcher returns exactly one result:

    affected       the CPE configuration evaluates to true for this host
    not_affected   vendor:product matches, but version/update/edition rule it out
    needs_review   the matcher cannot decide safely (see reasons below)

needs_review is used, never a guess, when:
  - a version comparison is ambiguous (same release, different suffixes, e.g. 9.3p2 vs 9.3p1 at a range bound)
  - the criterion has no version (`-`, "not applicable"), as in older Microsoft records
  - a running-on condition (vulnerable=false platform CPE) names a product the host inventory does not list
  - NVD has not analysed the CVE yet (no configurations) but the description names an inventory product
    and, where the inventory lists `cna_sources`, the CVE was filed by one of them

Logic inside a configuration is three-valued (true / unknown / false, Kleene):
OR takes the best value, AND the worst, NOT swaps true and false and keeps unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cve_triage.normalize import Configuration, CpeMatch, NormalizedCve

AFFECTED, NOT_AFFECTED, NEEDS_REVIEW = "affected", "not_affected", "needs_review"
_RESULT = {True: AFFECTED, None: NEEDS_REVIEW, False: NOT_AFFECTED}

CPE_FIELDS = ("part", "vendor", "product", "version", "update", "edition", "language",
              "sw_edition", "target_sw", "target_hw", "other")
_EXTRA = ("edition", "language", "sw_edition", "target_sw", "target_hw", "other")
ANY, NA = "*", "-"

# ---------------------------------------------------------------- CPE parsing


@dataclass(frozen=True)
class Cpe:
    raw: str
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.part, self.vendor, self.product)


def parse_cpe(s: str) -> Cpe:
    """Parse a CPE 2.3 formatted string; backslash escapes (e.g. `\\:`) are honoured."""
    parts, cur, esc = [], [], False
    for ch in s:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        raise ValueError(f"not a CPE 2.3 formatted string: {s!r}")
    return Cpe(s, *(p.lower() for p in parts[2:]))


# ---------------------------------------------------------- version handling

_RELEASE = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


def compare_versions(a: str, b: str) -> int | None:
    """-1 / 0 / 1, or None when the order cannot be decided safely.

    The leading dotted-numeric release decides (missing parts count as 0, so
    5.15 == 5.15.0). Only if the releases are equal do suffixes matter: equal
    suffixes compare equal, different suffixes (9.3p1 vs 9.3p2, 11.0.0-M1 vs
    11.0.0) are ambiguous and return None.
    """
    a, b = a.strip().lower(), b.strip().lower()
    if a == b:
        return 0
    ma, mb = _RELEASE.match(a), _RELEASE.match(b)
    if not ma or not mb:
        return None
    ra = [int(x) for x in ma.group(1).split(".")]
    rb = [int(x) for x in mb.group(1).split(".")]
    n = max(len(ra), len(rb))
    ra += [0] * (n - len(ra))
    rb += [0] * (n - len(rb))
    if ra != rb:
        return -1 if ra < rb else 1
    return 0 if ma.group(2) == mb.group(2) else None


# ------------------------------------------------------- three-valued logic

Tri = bool | None  # True, False, or None (= unknown)
_ORDER = {False: 0, None: 1, True: 2}


def _or(values: list[Tri]) -> Tri:
    return max(values, key=_ORDER.__getitem__) if values else False


def _and(values: list[Tri]) -> Tri:
    return min(values, key=_ORDER.__getitem__) if values else False


def _not(v: Tri) -> Tri:
    return None if v is None else not v


# ------------------------------------------------------------ inventory


@dataclass
class Software:
    cpe: Cpe
    keywords: list[str]
    cna_sources: list[str] = field(default_factory=list)  # empty = no source restriction

    def names_in(self, text: str, source: str | None) -> list[str]:
        """Keywords found in `text`, or [] if the filing source is not one of cna_sources."""
        if self.cna_sources and (source or "").lower() not in self.cna_sources:
            return []
        return [kw for kw in self.keywords if _mentions(text, kw)]


@dataclass
class Host:
    id: str
    software: list[Software]
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Inventory:
    hosts: list[Host]

    @classmethod
    def load(cls, path: str | Path) -> Inventory:
        doc = yaml.safe_load(Path(path).read_text())
        hosts = []
        for h in doc.get("hosts", []):
            sw = []
            for s in h.get("software", []):
                cpe = parse_cpe(s["cpe"])
                default_kw = cpe.product.replace("_", " ")
                sw.append(Software(
                    cpe,
                    [k.lower() for k in s.get("keywords") or [default_kw]],
                    [c.lower() for c in s.get("cna_sources") or []],
                ))
            meta = {k: v for k, v in h.items() if k not in ("id", "software")}
            hosts.append(Host(h["id"], sw, meta))
        return cls(hosts)

    @property
    def vendor_products(self) -> set[tuple[str, str]]:
        return {(s.cpe.vendor, s.cpe.product) for h in self.hosts for s in h.software}

    def is_candidate(self, raw: dict[str, Any]) -> bool:
        """Cheap pre-filter on a raw NVD record: could this CVE concern any inventory product?

        Used while paging through NVD so only relevant records are kept in memory.
        """
        if raw.get("vulnStatus") == "Rejected":
            return False
        vps = self.vendor_products
        has_config = False
        for conf in raw.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    has_config = True
                    p = m.get("criteria", "").split(":")
                    if len(p) > 4 and (p[3].lower(), p[4].lower()) in vps:
                        return True
        if has_config:
            return False
        text = " ".join(d.get("value", "") for d in raw.get("descriptions", [])).lower()
        source = raw.get("sourceIdentifier")
        return any(s.names_in(text, source) for h in self.hosts for s in h.software)


def _mentions(text: str, keyword: str) -> bool:
    return re.search(r"(?<![\w-])" + re.escape(keyword) + r"(?![\w-])", text) is not None


# ------------------------------------------------------------- matching


@dataclass
class MatchResult:
    cve_id: str
    host_id: str
    cpe: str
    result: str
    detail: dict[str, Any]


def _match_one(m: CpeMatch, crit: Cpe, sw: Cpe) -> tuple[Tri, str]:
    """Evaluate one cpeMatch criterion against one software CPE of the same part:vendor:product."""
    for f in _EXTRA:
        cv, hv = getattr(crit, f), getattr(sw, f)
        if cv not in (ANY, NA) and hv != ANY and cv != hv:
            return False, f"{f} {hv} != {cv}"
    # Host update `*` is read as "plain release, no update"
    host_update = NA if sw.update == ANY else sw.update

    if m.has_range:
        if crit.version not in (ANY, NA) and compare_versions(crit.version, sw.version) != 0:
            return False, f"version {sw.version} != {crit.version}"
        bounds = (
            (m.version_start_including, lambda c: c >= 0, ">="),
            (m.version_start_excluding, lambda c: c > 0, ">"),
            (m.version_end_including, lambda c: c <= 0, "<="),
            (m.version_end_excluding, lambda c: c < 0, "<"),
        )
        desc = []
        for bound, ok, sym in bounds:
            if not bound:
                continue
            c = compare_versions(sw.version, bound)
            desc.append(f"{sym}{bound}")
            if c is None:
                return None, f"cannot order {sw.version} against {bound}"
            if c == 0 and host_update != NA:
                return None, f"{sw.version}:{sw.update} sits on range bound {bound}"
            if not ok(c):
                return False, f"{sw.version} outside {' '.join(desc)}"
        return True, f"{sw.version} in range {' '.join(desc)}"

    if crit.version == ANY:
        return True, "all versions"
    if crit.version == NA:
        return None, "criterion has no version ('-'); cannot confirm the host's build"
    c = compare_versions(sw.version, crit.version)
    if c is None:
        return None, f"cannot compare {sw.version} with {crit.version}"
    if c != 0:
        return False, f"version {sw.version} != {crit.version}"
    if crit.update not in (ANY,) and crit.update != host_update:
        return False, f"update {sw.update} != {crit.update}"
    return True, f"exact version {crit.version}" + (f":{crit.update}" if crit.update not in (ANY, NA) else "")


def _eval_config(
    conf: Configuration,
    target: Software,
    host: Host,
    trail: list[dict[str, Any]],
) -> Tri:
    """Evaluate one configuration. Vulnerable criteria are tested against `target` only;
    running-on (vulnerable=false) criteria against all software on the host."""
    node_values = []
    for node in conf.nodes:
        values: list[Tri] = []
        for m in node.matches:
            try:
                crit = parse_cpe(m.criteria)
            except ValueError:
                values.append(None)
                trail.append({"criteria": m.criteria, "value": None, "why": "unparseable criterion"})
                continue
            if m.vulnerable:
                if crit.key != target.cpe.key:
                    values.append(False)
                    continue
                v, why = _match_one(m, crit, target.cpe)
                trail.append({"criteria": m.criteria, "id": m.match_criteria_id, "value": v, "why": why})
                values.append(v)
            else:
                same = [s for s in host.software if s.cpe.key == crit.key]
                if not same:
                    v, why = None, "running-on product not in host inventory"
                else:
                    v = _or([_match_one(m, crit, s.cpe)[0] for s in same])
                    why = "running-on condition " + {True: "met", False: "not met", None: "unclear"}[v]
                trail.append({"criteria": m.criteria, "platform": True, "value": v, "why": why})
                values.append(v)
        nv = _and(values) if node.operator == "AND" else _or(values)
        node_values.append(_not(nv) if node.negate else nv)
    cv = _and(node_values) if conf.operator == "AND" else _or(node_values)
    return _not(cv) if conf.negate else cv


def match_cve(cve: NormalizedCve, inventory: Inventory) -> list[MatchResult]:
    """All CVE x host x software results worth recording (vendor:product overlap only)."""
    if cve.rejected:
        return []
    results: list[MatchResult] = []

    if cve.awaiting_analysis:
        text = cve.description.lower()
        for host in inventory.hosts:
            for sw in host.software:
                hits = sw.names_in(text, cve.source)
                if hits:
                    results.append(MatchResult(cve.cve_id, host.id, sw.cpe.raw, NEEDS_REVIEW, {
                        "reason": f"no CPE configuration yet (vulnStatus={cve.status or 'unknown'}); "
                                  "product named in description"
                                  + (" by its own CNA" if sw.cna_sources else ""),
                        "keywords": hits,
                        "source": cve.source,
                    }))
        return results

    vulnerable_keys = set()
    for conf in cve.configurations:
        for node in conf.nodes:
            for m in node.matches:
                if m.vulnerable:
                    try:
                        vulnerable_keys.add(parse_cpe(m.criteria).key)
                    except ValueError:
                        pass
    for host in inventory.hosts:
        for sw in host.software:
            if sw.cpe.key not in vulnerable_keys:
                continue
            trail: list[dict[str, Any]] = []
            value = _or([_eval_config(c, sw, host, trail) for c in cve.configurations])
            decisive = [t for t in trail if t["value"] is value] or trail
            results.append(MatchResult(cve.cve_id, host.id, sw.cpe.raw, _RESULT[value], {
                "evaluated_criteria": len(trail),
                "evidence": decisive[:10],
            }))
    return results
