"""Minimal NVD API 2.0 client (CVE and CPE endpoints).

Docs: https://nvd.nist.gov/developers/vulnerabilities
      https://nvd.nist.gov/developers/products
Rate limits: 5 requests / 30 s without a key, 50 / 30 s with one.
A date range (pub* or lastMod*) may span at most 120 days per request.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
PAGE_SIZE = 2000  # NVD maximum for the CVE endpoint
MAX_RANGE = timedelta(days=120)  # NVD limit per date-range query
RETRY_STATUS = (403, 429, 500, 502, 503, 504)  # throttled or busy: back off and retry


def _fmt(ts: datetime) -> str:
    """NVD wants ISO-8601 with milliseconds and an explicit UTC offset."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


class _Session:
    """Shared plumbing: API key header, pause between calls, retries."""

    def __init__(self, client: httpx.Client | None, api_key: str | None, max_retries: int):
        self.api_key = api_key if api_key is not None else os.getenv("NVD_API_KEY") or None
        self.headers = {"apiKey": self.api_key} if self.api_key else {}
        self.pause = 0.6 if self.api_key else 6.0  # stay under the rolling 30 s limit
        self.own_client = client is None
        self.client = client or httpx.Client(timeout=60)
        self.max_retries = max_retries
        self.requests = 0

    def get(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        if self.requests:
            time.sleep(self.pause)
        for attempt in range(1, self.max_retries + 1):
            resp = self.client.get(url, params=params, headers=self.headers)
            if resp.status_code in RETRY_STATUS and attempt < self.max_retries:
                time.sleep(self.pause * 5 * attempt)
                continue
            resp.raise_for_status()
            break
        self.requests += 1
        return resp.json()

    def close(self) -> None:
        if self.own_client:
            self.client.close()


def iter_cve_pages(
    params: dict[str, Any],
    *,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    page_size: int = PAGE_SIZE,
    max_retries: int = 3,
) -> Iterator[list[dict[str, Any]]]:
    """Yield CVE records page by page for one query, so callers never hold the full result set."""
    session = _Session(client, api_key, max_retries)
    start_index = 0
    try:
        while True:
            page = session.get(NVD_URL, {**params, "resultsPerPage": page_size, "startIndex": start_index})
            yield [item["cve"] for item in page.get("vulnerabilities", [])]
            got = page.get("resultsPerPage", 0)
            start_index += got
            if got == 0 or start_index >= page.get("totalResults", 0):
                return
    finally:
        session.close()


def _chunks(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    while start < end:
        stop = min(start + MAX_RANGE, end)
        yield start, stop
        start = stop


def iter_modified(
    start: datetime,
    end: datetime,
    **kwargs: Any,
) -> Iterator[list[dict[str, Any]]]:
    """Pages of CVE records whose lastModified falls in [start, end] (UTC).

    Newly published CVEs count as modified too, so this one window covers both.
    Windows longer than 120 days are split into chunks.
    """
    for a, b in _chunks(start, end):
        yield from iter_cve_pages({"lastModStartDate": _fmt(a), "lastModEndDate": _fmt(b)}, **kwargs)


def fetch_published(
    start: datetime,
    end: datetime,
    *,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    max_retries: int = 3,
) -> list[dict[str, Any]]:
    """Return all CVE records published in [start, end] (UTC), following pagination."""
    records: list[dict[str, Any]] = []
    for page in iter_cve_pages(
        {"pubStartDate": _fmt(start), "pubEndDate": _fmt(end)},
        client=client, api_key=api_key, max_retries=max_retries,
    ):
        records.extend(page)
    return records


def search_cpes(
    match_string: str,
    *,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    limit: int = 50,
    max_retries: int = 3,
) -> tuple[int, list[dict[str, Any]]]:
    """Query the NVD CPE dictionary. Returns (totalResults, first `limit` product entries).

    `match_string` may be a full CPE 2.3 name or a prefix such as `cpe:2.3:a:apache:tomcat`.
    Each entry looks like {"cpeName": ..., "deprecated": bool, "deprecatedBy": [...], ...}.
    """
    session = _Session(client, api_key, max_retries)
    try:
        page = session.get(CPE_URL, {"cpeMatchString": match_string, "resultsPerPage": limit})
    finally:
        session.close()
    return page.get("totalResults", 0), [p["cpe"] for p in page.get("products", [])]


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
