"""Minimal NVD CVE API 2.0 client.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limits: 5 requests / 30 s without a key, 50 / 30 s with one.
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD maximum


def _fmt(ts: datetime) -> str:
    """NVD wants ISO-8601 with milliseconds and an explicit UTC offset."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def fetch_published(
    start: datetime,
    end: datetime,
    *,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    max_retries: int = 3,
) -> list[dict[str, Any]]:
    """Return all CVE records published in [start, end] (UTC), following pagination."""
    api_key = api_key if api_key is not None else os.getenv("NVD_API_KEY") or None
    headers = {"apiKey": api_key} if api_key else {}
    pause = 0.6 if api_key else 6.0  # stay under the rolling 30 s limit
    own_client = client is None
    client = client or httpx.Client(timeout=60)

    records: list[dict[str, Any]] = []
    start_index = 0
    try:
        while True:
            params = {
                "pubStartDate": _fmt(start),
                "pubEndDate": _fmt(end),
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
            }
            for attempt in range(1, max_retries + 1):
                resp = client.get(NVD_URL, params=params, headers=headers)
                # NVD answers 403/429/503 when throttled or busy: back off and retry
                if resp.status_code in (403, 429, 500, 502, 503, 504) and attempt < max_retries:
                    time.sleep(pause * 5 * attempt)
                    continue
                resp.raise_for_status()
                break
            page = resp.json()
            records.extend(item["cve"] for item in page.get("vulnerabilities", []))
            start_index += page.get("resultsPerPage", 0)
            if start_index >= page.get("totalResults", 0) or page.get("resultsPerPage", 0) == 0:
                return records
            time.sleep(pause)
    finally:
        if own_client:
            client.close()


def severity(cve: dict[str, Any]) -> str:
    """Base severity from CVSS v4.0, then v3.1, then v3.0; UNSCORED if NVD has not analysed it yet."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            primary = next((m for m in entries if m.get("type") == "Primary"), entries[0])
            sev = primary.get("cvssData", {}).get("baseSeverity")
            if sev:
                return sev.upper()
    return "UNSCORED"
