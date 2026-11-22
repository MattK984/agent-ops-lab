"""Check every CPE in the inventory against the NVD CPE dictionary (Q-2.1-04, checkpoint A).

For each CPE: does the exact name exist, is it deprecated, does vendor:product exist
at all, and which dictionary names exist for that version (to fix a wrong update/edition).

    python -m cve_triage.verify_cpes [path/to/inventory.yaml]
    # or: docker compose run --rm cve-triage python -m cve_triage.verify_cpes

Exit code 0 if every CPE exists and is not deprecated, 1 otherwise.
"""

from __future__ import annotations

import os
import sys

from cve_triage import nvd
from cve_triage.matcher import Inventory
from cve_triage.triage import DEFAULT_INVENTORY


def _prefix(cpe, upto: str) -> str:
    fields = ["part", "vendor", "product", "version"]
    vals = [getattr(cpe, f) for f in fields[: fields.index(upto) + 1]]
    return "cpe:2.3:" + ":".join(vals)


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else os.getenv("CVE_INVENTORY") or DEFAULT_INVENTORY
    inv = Inventory.load(path)
    seen, problems = set(), 0
    for host in inv.hosts:
        for sw in host.software:
            cpe = sw.cpe
            if cpe.raw in seen:
                continue
            seen.add(cpe.raw)
            print(f"\n{host.id}: {cpe.raw}")
            total, exact = nvd.search_cpes(cpe.raw, limit=5)
            hit = next((p for p in exact if p["cpeName"].lower() == cpe.raw.lower()), None)
            if hit and not hit.get("deprecated"):
                print("  OK      exact name in dictionary")
                continue
            problems += 1
            if hit:
                by = [d.get("cpeName") for d in hit.get("deprecatedBy", [])]
                print(f"  DEPRECATED  replaced by: {', '.join(by) or 'n/a'}")
                continue
            n_prod, _ = nvd.search_cpes(_prefix(cpe, "product"), limit=1)
            print(f"  MISSING exact name; vendor:product {'exists' if n_prod else 'NOT FOUND'} ({n_prod} names)")
            if n_prod:
                n_ver, names = nvd.search_cpes(_prefix(cpe, "version"), limit=10)
                if names:
                    print(f"  names for version {cpe.version} ({n_ver}):")
                    for p in names:
                        print(f"    {'(deprecated) ' if p.get('deprecated') else ''}{p['cpeName']}")
                else:
                    print(f"  no dictionary names for version {cpe.version}")
    print(f"\n{len(seen)} CPEs checked, {problems} need attention.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
