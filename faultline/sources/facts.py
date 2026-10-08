"""Common, source-independent view of a CVE ("facts")."""
from __future__ import annotations

from typing import Any


def empty_facts(cve_id: str) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "published": None,         # YYYY-MM-DD
        "last_modified": None,     # YYYY-MM-DD
        "vuln_status": None,       # NVD status
        "state": None,             # MITRE state (PUBLISHED / REJECTED / RESERVED)
        "assigner": None,          # CNA short name
        "title": None,             # CNA title if any
        "description": None,
        "cwes": [],                # [{"id","name"}]
        "cvss": [],                # [{"version","score","severity","vector","source","type"}]
        "ssvc": None,              # {"exploitation","automatable","technicalImpact"}
        "references": [],          # [str]
        "affected": [],            # [{"vendor","product","versions":[str],"platforms":[str]}]
        "cpes": [],                # [str]
        "ghsa_id": None,
        "ghsa_url": None,
        "epss": None,
        "sources": [],             # which upstreams contributed
    }


def date_only(value: Any) -> str | None:
    if isinstance(value, str) and len(value) >= 10 and value[4] == "-" and value[7] == "-":
        return value[:10]
    return None


def merge_facts(*parts: dict[str, Any] | None) -> dict[str, Any]:
    """Merge facts; earlier parts win for scalar fields, lists are unioned."""
    parts = [p for p in parts if p]
    if not parts:
        return {}
    out = empty_facts(parts[0]["cve_id"])
    for p in parts:
        for k, v in p.items():
            if k == "cve_id":
                continue
            if k == "cwes" and isinstance(v, list):
                for item in v:
                    cur = next((c for c in out[k] if c.get("id") == item.get("id")), None)
                    if cur is None:
                        out[k].append(dict(item))
                    elif not cur.get("name") and item.get("name"):
                        cur["name"] = item["name"]
            elif isinstance(v, list):
                for item in v:
                    if item not in out[k]:
                        out[k].append(item)
            elif out.get(k) in (None, "") and v not in (None, ""):
                out[k] = v
    return out


def pick_cvss(facts: dict[str, Any], prefer_version: str | None = None) -> dict[str, Any] | None:
    """Choose the CVSS entry to use as the record's main score.

    Priority: requested version first; within a version NVD Primary > CNA/other
    secondary > GHSA.  Falls back to v3.1, then v4.0, then v3.0, then v2.0.
    """
    entries = facts.get("cvss") or []
    if not entries:
        return None
    rank = {"nvd-primary": 0, "cna": 1, "nvd-secondary": 2, "mitre-cna": 3, "mitre-adp": 4, "ghsa": 5}
    versions = [prefer_version] if prefer_version else []
    versions += [v for v in ("3.1", "4.0", "3.0", "2.0") if v not in versions]
    for ver in versions:
        cands = [e for e in entries if str(e.get("version")) == ver and e.get("score") is not None]
        if cands:
            return sorted(cands, key=lambda e: rank.get(e.get("type"), 9))[0]
    return None


ADVISORY_HINTS = ("advisor", "security", "psirt", "bulletin", "cve-", "vuln", "cert", "disclos", "custhelp", "/ghsa-")


def pick_advisory(references: list[str]) -> str | None:
    """Best vendor/advisory link: prefer URLs that look like advisories, skip NVD/cve.org/plain repos."""
    cands = [r for r in references or [] if "nvd.nist.gov" not in r and "cve.org" not in r and "cve.mitre.org" not in r]
    for r in cands:
        low = r.lower()
        if any(h in low for h in ADVISORY_HINTS):
            return r
    for r in cands:
        low = r.lower()
        if not (low.endswith("/tree/main") or low.rstrip("/").count("/") <= 3 and "github.com" in low):
            return r
    return cands[0] if cands else None
