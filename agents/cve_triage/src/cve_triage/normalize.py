"""Turn a raw NVD CVE record into the fields the agent works with.

Pure functions, no I/O. The raw record is kept alongside (cve.cves.raw), so
nothing is lost if a field is interpreted differently later.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# NVD's vulnStatus values. Only REJECTED is dropped; everything else is matched.
REJECTED = "Rejected"
# Statuses where NVD has not (yet) added CPE configurations
PENDING = {"Received", "Awaiting Analysis", "Undergoing Analysis", "Deferred"}

_CVSS_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"))


@dataclass
class CvssScore:
    score: float
    vector: str | None
    version: str
    severity: str | None
    source: str | None
    primary: bool


@dataclass
class CpeMatch:
    """One cpeMatch entry of an NVD configuration node."""

    criteria: str
    vulnerable: bool
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    match_criteria_id: str | None = None

    @property
    def has_range(self) -> bool:
        return any((self.version_start_including, self.version_start_excluding,
                    self.version_end_including, self.version_end_excluding))


@dataclass
class Node:
    operator: str  # "OR" | "AND"
    negate: bool
    matches: list[CpeMatch]


@dataclass
class Configuration:
    operator: str  # "OR" (default) | "AND", applies across nodes
    negate: bool
    nodes: list[Node]


@dataclass
class NormalizedCve:
    cve_id: str
    status: str
    published: str | None
    last_modified: str | None
    description: str
    cvss: CvssScore | None
    cwe: list[str]
    kev_added: str | None
    kev_action_due: str | None
    kev_required_action: str | None
    configurations: list[Configuration] = field(default_factory=list)

    @property
    def rejected(self) -> bool:
        return self.status == REJECTED

    @property
    def awaiting_analysis(self) -> bool:
        """No CPE configuration to match against yet."""
        return not self.configurations

    def summary(self) -> dict[str, Any]:
        """Compact, JSON-safe view (for traces and logs; no configurations)."""
        d = asdict(self)
        d.pop("configurations")
        return d


def pick_cvss(metrics: dict[str, Any]) -> CvssScore | None:
    """Prefer NVD's own (Primary) score, newest CVSS version first; else the newest CNA score.

    NVD's Primary score is what its analysts assigned; a CNA (Secondary) score is
    used only when NVD has not scored the CVE yet.
    """
    candidates: list[tuple[int, int, CvssScore]] = []
    for rank, (key, version) in enumerate(_CVSS_KEYS):
        for m in metrics.get(key) or []:
            data = m.get("cvssData", {})
            if data.get("baseScore") is None:
                continue
            primary = m.get("type") == "Primary"
            candidates.append((0 if primary else 1, rank, CvssScore(
                score=float(data["baseScore"]),
                vector=data.get("vectorString"),
                version=data.get("version", version),
                severity=(data.get("baseSeverity") or m.get("baseSeverity") or "").upper() or None,
                source=m.get("source"),
                primary=primary,
            )))
    if not candidates:
        return None
    candidates.sort(key=lambda c: (c[0], c[1]))
    return candidates[0][2]


def _cwes(cve: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in seen:
                seen.append(v)
    return seen


def _description(cve: dict[str, Any]) -> str:
    descs = cve.get("descriptions", [])
    en = next((d["value"] for d in descs if d.get("lang") == "en"), None)
    return en or (descs[0]["value"] if descs else "")


def _configurations(cve: dict[str, Any]) -> list[Configuration]:
    out = []
    for conf in cve.get("configurations", []):
        nodes = [
            Node(
                operator=n.get("operator", "OR").upper(),
                negate=bool(n.get("negate", False)),
                matches=[
                    CpeMatch(
                        criteria=m["criteria"],
                        vulnerable=bool(m.get("vulnerable", False)),
                        version_start_including=m.get("versionStartIncluding"),
                        version_start_excluding=m.get("versionStartExcluding"),
                        version_end_including=m.get("versionEndIncluding"),
                        version_end_excluding=m.get("versionEndExcluding"),
                        match_criteria_id=m.get("matchCriteriaId"),
                    )
                    for m in n.get("cpeMatch", [])
                ],
            )
            for n in conf.get("nodes", [])
        ]
        if nodes:
            out.append(Configuration(
                operator=conf.get("operator", "OR").upper(),
                negate=bool(conf.get("negate", False)),
                nodes=nodes,
            ))
    return out


def normalize(cve: dict[str, Any]) -> NormalizedCve:
    return NormalizedCve(
        cve_id=cve["id"],
        status=cve.get("vulnStatus", ""),
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        description=_description(cve),
        cvss=pick_cvss(cve.get("metrics", {})),
        cwe=_cwes(cve),
        kev_added=cve.get("cisaExploitAdd"),
        kev_action_due=cve.get("cisaActionDue"),
        kev_required_action=cve.get("cisaRequiredAction"),
        configurations=_configurations(cve),
    )
