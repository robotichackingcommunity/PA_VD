"""GitHub Security Advisories (global advisory database)."""
from __future__ import annotations

import os
import urllib.parse
from typing import Any, Iterator

from ..http import get_json
from .facts import date_only, empty_facts

API = "https://api.github.com/advisories"


def _headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def parse(adv: dict) -> dict[str, Any]:
    f = empty_facts(adv.get("cve_id"))
    f["ghsa_id"] = adv.get("ghsa_id")
    f["ghsa_url"] = adv.get("html_url")
    f["title"] = adv.get("summary")
    f["description"] = adv.get("description")
    f["published"] = date_only(adv.get("nvd_published_at") or adv.get("published_at"))
    f["last_modified"] = date_only(adv.get("updated_at"))
    for c in adv.get("cwes") or []:
        if c.get("cwe_id"):
            f["cwes"].append({"id": c["cwe_id"], "name": c.get("name")})
    sev = (adv.get("severity") or "").upper() or None
    cs = adv.get("cvss_severities") or {}
    for key, ver in (("cvss_v4", "4.0"), ("cvss_v3", "3.1")):
        c = cs.get(key) or {}
        if c.get("vector_string") and c.get("score"):
            v = c["vector_string"]
            version = v.split("/")[0].replace("CVSS:", "") if v.startswith("CVSS:") else ver
            f["cvss"].append({"version": version, "score": float(c["score"]), "severity": sev, "vector": v, "source": "github", "type": "ghsa"})
    for r in adv.get("references") or []:
        if isinstance(r, str) and r not in f["references"]:
            f["references"].append(r)
    for v in adv.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        f["affected"].append({
            "vendor": pkg.get("ecosystem"),
            "product": pkg.get("name"),
            "versions": [v["vulnerable_version_range"]] if v.get("vulnerable_version_range") else [],
            "platforms": [],
        })
    epss = adv.get("epss")
    if isinstance(epss, dict) and epss.get("percentage") is not None:
        f["epss"] = {"score": epss.get("percentage"), "percentile": epss.get("percentile")}
    f["sources"] = ["ghsa"]
    return f


def fetch(cve_id: str, cache_ttl: float | None = 6 * 3600) -> dict[str, Any] | None:
    raw = get_json(f"{API}?cve_id={cve_id}", headers=_headers(), cache_ttl=cache_ttl)
    if not raw or not isinstance(raw, list):
        return None
    return parse(raw[0])


def iter_modified(since_iso: str, max_pages: int = 20) -> Iterator[dict[str, Any]]:
    """Advisories updated since `since_iso` (newest first)."""
    for page in range(1, max_pages + 1):
        q = urllib.parse.urlencode({"modified": f">={since_iso}", "per_page": 100, "page": page, "sort": "updated", "direction": "desc"})
        raw = get_json(f"{API}?{q}", headers=_headers())
        if not raw or not isinstance(raw, list):
            return
        for adv in raw:
            if adv.get("cve_id"):
                yield parse(adv)
        if len(raw) < 100:
            return
