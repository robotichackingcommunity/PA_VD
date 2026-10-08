"""NVD CVE API 2.0."""
from __future__ import annotations

import os
import urllib.parse
from typing import Any, Iterator

from ..http import get_json
from .facts import date_only, empty_facts

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000


def _headers() -> dict[str, str]:
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def parse(item: dict) -> dict[str, Any]:
    cve = item.get("cve", item)
    f = empty_facts(cve.get("id"))
    f["published"] = date_only(cve.get("published"))
    f["last_modified"] = date_only(cve.get("lastModified"))
    f["vuln_status"] = cve.get("vulnStatus")
    f["assigner"] = cve.get("sourceIdentifier")
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            f["description"] = d.get("value")
            break
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            cid = d.get("value")
            if cid and not any(c["id"] == cid for c in f["cwes"]):
                f["cwes"].append({"id": cid, "name": None})
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            c = m.get("cvssData") or {}
            if c.get("baseScore") is None:
                continue
            sev = c.get("baseSeverity") or m.get("baseSeverity")
            f["cvss"].append({
                "version": str(c.get("version")),
                "score": float(c["baseScore"]),
                "severity": sev.upper() if isinstance(sev, str) else None,
                "vector": c.get("vectorString"),
                "source": m.get("source"),
                "type": "nvd-primary" if m.get("type") == "Primary" else "nvd-secondary",
            })
    for r in cve.get("references") or []:
        if r.get("url") and r["url"] not in f["references"]:
            f["references"].append(r["url"])
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") and m.get("criteria") and m["criteria"] not in f["cpes"]:
                    f["cpes"].append(m["criteria"])
    for cpe in f["cpes"]:
        parts = cpe.split(":")
        if len(parts) > 5:
            entry = {"vendor": parts[3], "product": parts[4], "versions": [parts[5]] if parts[5] not in ("*", "-") else [], "platforms": []}
            if entry not in f["affected"]:
                f["affected"].append(entry)
    f["sources"] = ["nvd"]
    return f


def fetch(cve_id: str, cache_ttl: float | None = 6 * 3600) -> dict[str, Any] | None:
    raw = get_json(f"{API}?cveId={cve_id}", headers=_headers(), cache_ttl=cache_ttl)
    if not raw or not raw.get("vulnerabilities"):
        return None
    return parse(raw["vulnerabilities"][0])


def iter_window(params: dict[str, str], cache_ttl: float | None = None) -> Iterator[dict[str, Any]]:
    """Iterate parsed facts for every CVE matching `params` (handles paging)."""
    start = 0
    while True:
        q = dict(params, resultsPerPage=str(PAGE), startIndex=str(start))
        raw = get_json(f"{API}?{urllib.parse.urlencode(q)}", headers=_headers(), cache_ttl=cache_ttl, timeout=180)
        if not raw:
            return
        for item in raw.get("vulnerabilities") or []:
            yield parse(item)
        start += raw.get("resultsPerPage", PAGE)
        if start >= raw.get("totalResults", 0):
            return


def keyword_search(term: str, since_iso: str | None = None, until_iso: str | None = None) -> Iterator[dict[str, Any]]:
    params: dict[str, str] = {"keywordSearch": term}
    if since_iso:
        params["lastModStartDate"] = since_iso
        params["lastModEndDate"] = until_iso or since_iso
    yield from iter_window(params)


def modified_window(since_iso: str, until_iso: str) -> Iterator[dict[str, Any]]:
    yield from iter_window({"lastModStartDate": since_iso, "lastModEndDate": until_iso})
