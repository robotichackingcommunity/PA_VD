"""Refresh authoritative fields of existing records from MITRE / NVD / GHSA.

Only facts that upstream owns are touched (dates, status, CVSS, CWE, source
URLs, affected configurations when absent).  Enrichment text is never changed.
"""
from __future__ import annotations

import copy
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from .records import iter_record_files, load_json, save_record
from .sources import ghsa, mitre, nvd
from .sources.facts import merge_facts, pick_cvss
from .state import load_state, now_iso, save_state
from .taxonomy import severity_for_score

log = logging.getLogger("faultline.refresh")


def gather_facts(cve_id: str, want_ghsa: bool = True) -> dict[str, Any] | None:
    n = nvd.fetch(cve_id)
    m = mitre.fetch(cve_id)
    g = ghsa.fetch(cve_id) if want_ghsa else None
    if not (n or m or g):
        return None
    return merge_facts(n, m, g)


def _cvss_from(entry: dict) -> dict:
    return {
        "version": entry["version"],
        "score": entry["score"],
        "severity": entry.get("severity") or severity_for_score(entry["score"]),
        "vector": entry.get("vector"),
        "source": entry.get("source"),
    }


def apply_facts(record: dict, facts: dict[str, Any]) -> tuple[dict, list[str]]:
    rec = copy.deepcopy(record)
    changes: list[str] = []

    def setf(key: str, value: Any, container: dict | None = None) -> None:
        target = rec if container is None else container
        if value is not None and target.get(key) != value:
            changes.append(f"{key}: {target.get(key)!r} -> {value!r}")
            target[key] = value

    setf("published", facts.get("published"))
    setf("last_modified", facts.get("last_modified"))
    status = facts.get("vuln_status")
    if status is None and facts.get("state") == "REJECTED":
        status = "Rejected"
    setf("vuln_status", status)
    if not rec.get("description") and facts.get("description"):
        setf("description", facts["description"])

    # CWE: fill gaps only; keep the curator's primary choice.
    cwe = rec.get("cwe") if isinstance(rec.get("cwe"), dict) else {"id": None, "name": None}
    up = facts.get("cwes") or []
    if not cwe.get("id") and up:
        cwe = {"id": up[0]["id"], "name": up[0].get("name")}
        changes.append(f"cwe filled from upstream: {cwe['id']}")
    elif cwe.get("id") and not cwe.get("name"):
        for u in up:
            if u["id"] == cwe["id"] and u.get("name"):
                cwe["name"] = u["name"]
                changes.append("cwe.name filled")
                break
    rec["cwe"] = cwe

    # CVSS: upstream is authoritative for the score of the record's chosen version.
    cvss = rec.get("cvss") if isinstance(rec.get("cvss"), dict) else {}
    chosen = pick_cvss(facts, prefer_version=str(cvss.get("version")) if cvss.get("version") else None)
    if chosen:
        if cvss.get("version") in (None, chosen["version"]) or cvss.get("score") is None:
            old_vector = cvss.get("vector")
            new = _cvss_from(chosen)
            for k, v in new.items():
                setf(k, v, cvss)
            if old_vector and cvss.get("vector") != old_vector and isinstance(cvss.get("cvss_4_0_estimated"), dict):
                est = cvss["cvss_4_0_estimated"]
                if not est.get("stale"):
                    est["stale"] = True
                    est["stale_reason"] = f"Base CVSS vector changed upstream ({old_vector} -> {cvss.get('vector')}); estimate predates it."
                    changes.append("cvss_4_0_estimated marked stale")
        # Keep the CNA's own score alongside NVD's primary analysis when they differ.
        if chosen.get("type") == "nvd-primary":
            cna = next((e for e in facts.get("cvss") or [] if e.get("type") in ("nvd-secondary", "mitre-cna") and e.get("version") == chosen["version"]), None)
            if cna and (cna.get("score") != chosen.get("score") or cna.get("vector") != chosen.get("vector")):
                cna_entry = {"score": cna["score"], "severity": cna.get("severity") or severity_for_score(cna["score"]), "vector": cna.get("vector"), "source": cna.get("source")}
                if cvss.get("cna") != cna_entry:
                    cvss["cna"] = cna_entry
                    changes.append("cvss.cna recorded (CNA score differs from NVD)")
        v4 = pick_cvss(facts, prefer_version="4.0")
        if v4 and v4["version"] == "4.0" and cvss.get("version") != "4.0" and not isinstance(cvss.get("cvss_4_0"), dict):
            cvss["cvss_4_0"] = _cvss_from(v4)
            changes.append("cvss_4_0 added from upstream")
        if facts.get("ssvc") and not cvss.get("ssvc"):
            cvss["ssvc"] = facts["ssvc"]
            changes.append("ssvc filled")
    rec["cvss"] = cvss

    src = rec.get("source") if isinstance(rec.get("source"), dict) else {}
    if facts.get("ghsa_url") and not src.get("github_advisory"):
        setf("github_advisory", facts["ghsa_url"], src)
    rec["source"] = src

    if not rec.get("affected_configurations") and facts.get("affected"):
        rows = []
        for a in facts["affected"]:
            if not a.get("product"):
                continue
            rows.append({
                "vendor": a.get("vendor"),
                "product": a.get("product"),
                "versions": a.get("versions") or [],
                "platforms": a.get("platforms") or [],
            })
        if rows:
            rec["affected_configurations"] = rows
            changes.append(f"affected_configurations filled ({len(rows)} rows)")

    if facts.get("epss") and rec.get("epss") != facts["epss"]:
        rec["epss"] = facts["epss"]
        changes.append("epss updated")
    return rec, changes


def refresh_all(max_age_days: int = 7, limit: int | None = None, only: set[str] | None = None, force: bool = False) -> dict[str, int]:
    state = load_state()
    recs_state = state.setdefault("records", {})
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    stats = {"checked": 0, "updated": 0, "skipped": 0, "unavailable": 0}
    for path in iter_record_files():
        rec = load_json(path)
        cve_id = rec.get("cve_id")
        if not cve_id or (only and cve_id not in only):
            continue
        last = recs_state.get(cve_id, {}).get("refreshed_at")
        if last and not force and not only:
            try:
                if datetime.fromisoformat(last.replace("Z", "+00:00")) > cutoff:
                    stats["skipped"] += 1
                    continue
            except ValueError:
                pass
        if limit is not None and stats["checked"] >= limit:
            break
        stats["checked"] += 1
        facts = gather_facts(cve_id)
        if facts is None:
            stats["unavailable"] += 1
            log.warning("%s: no upstream data available", cve_id)
            continue
        new, changes = apply_facts(rec, facts)
        if changes:
            save_record(new)
            stats["updated"] += 1
            log.info("%s: %d field(s) updated: %s", cve_id, len(changes), "; ".join(changes[:4]))
        recs_state[cve_id] = {"refreshed_at": now_iso(), "sources": facts.get("sources", [])}
        save_state(state)
    log.info("refresh done: %s", stats)
    return stats
