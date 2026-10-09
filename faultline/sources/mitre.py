"""MITRE CVE Services (cve.org) — CVE JSON 5.x records."""
from __future__ import annotations

import re
from typing import Any

from ..http import get_json
from .facts import date_only, empty_facts

API = "https://cveawg.mitre.org/api/cve/{cve_id}"
RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve_id}.json"
TAG_RE = re.compile(r"<[^>]+>")


def _text(desc_list: list[dict] | None) -> str | None:
    if not desc_list:
        return None
    for d in desc_list:
        if d.get("lang", "en").startswith("en") and d.get("value"):
            return TAG_RE.sub("", d["value"]).strip()
    return TAG_RE.sub("", desc_list[0].get("value", "")).strip() or None


def _metrics(container: dict, kind: str) -> list[dict]:
    out = []
    for m in container.get("metrics") or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            c = m.get(key)
            if isinstance(c, dict) and c.get("baseScore") is not None:
                out.append({
                    "version": str(c.get("version") or key[4:].replace("_", ".")),
                    "score": float(c["baseScore"]),
                    "severity": (c.get("baseSeverity") or "").upper() or None,
                    "vector": c.get("vectorString"),
                    "source": container.get("providerMetadata", {}).get("shortName"),
                    "type": kind,
                })
    return out


PLACEHOLDERS = {"", "n/a", "na", "none", "unspecified", "unknown", "-"}


def _is_placeholder(value: str | None) -> bool:
    return (value or "").strip().lower() in PLACEHOLDERS


def parse(raw: dict) -> dict[str, Any]:
    meta = raw.get("cveMetadata", {})
    cna = raw.get("containers", {}).get("cna", {}) or {}
    adps = raw.get("containers", {}).get("adp", []) or []
    f = empty_facts(meta.get("cveId"))
    f["state"] = meta.get("state")
    f["assigner"] = meta.get("assignerShortName")
    f["published"] = date_only(meta.get("datePublished"))
    f["last_modified"] = date_only(meta.get("dateUpdated"))
    f["title"] = cna.get("title")
    f["description"] = _text(cna.get("descriptions")) or _text((raw.get("containers", {}).get("cna", {}).get("rejectedReasons")))
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cid = d.get("cweId")
            if cid and {"id": cid, "name": None} not in f["cwes"]:
                name = d.get("description") or ""
                name = re.sub(r"^CWE-\d+:?\s*", "", name).strip() or None
                f["cwes"].append({"id": cid, "name": name})
    f["cvss"] = _metrics(cna, "mitre-cna")
    for adp in adps:
        f["cvss"] += _metrics(adp, "mitre-adp")
        for m in adp.get("metrics") or []:
            other = m.get("other") or {}
            if other.get("type") == "ssvc":
                opts = {}
                for o in other.get("content", {}).get("options", []):
                    opts.update({k.lower().replace(" ", "_"): v for k, v in o.items()})
                f["ssvc"] = {
                    "exploitation": opts.get("exploitation"),
                    "automatable": opts.get("automatable"),
                    "technicalImpact": opts.get("technical_impact"),
                }
        for ref in adp.get("references") or []:
            if ref.get("url") and ref["url"] not in f["references"]:
                f["references"].append(ref["url"])
    for ref in cna.get("references") or []:
        if ref.get("url") and ref["url"] not in f["references"]:
            f["references"].append(ref["url"])
    for a in cna.get("affected") or []:
        versions = []
        for v in a.get("versions") or []:
            if v.get("status", "affected") != "affected":
                continue
            s = v.get("version") or ""
            if v.get("lessThan"):
                s = f"{s} < {v['lessThan']}".strip()
            elif v.get("lessThanOrEqual"):
                s = f"{s} <= {v['lessThanOrEqual']}".strip()
            if s:
                versions.append(s)
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or a.get("packageName") or "").strip()
        if _is_placeholder(vendor) and _is_placeholder(product):
            continue  # CNA placeholder rows ("n/a" / "unspecified") carry no information
        f["affected"].append({
            "vendor": None if _is_placeholder(vendor) else vendor,
            "product": product,
            "versions": [v for v in versions if not _is_placeholder(v)],
            "platforms": a.get("platforms") or [],
        })
        for c in a.get("cpes") or []:
            if c not in f["cpes"]:
                f["cpes"].append(c)
    f["sources"] = ["mitre"]
    return f


def fetch(cve_id: str, cache_ttl: float | None = 6 * 3600) -> dict[str, Any] | None:
    raw = get_json(API.format(cve_id=cve_id), cache_ttl=cache_ttl)
    if raw is None:
        year, num = cve_id.split("-")[1], cve_id.split("-")[2]
        bucket = num[:-3] + "xxx" if len(num) > 3 else "0xxx"
        raw = get_json(RAW.format(year=year, bucket=bucket, cve_id=cve_id), cache_ttl=cache_ttl)
    if not isinstance(raw, dict) or "cveMetadata" not in raw:
        return None
    return parse(raw)
