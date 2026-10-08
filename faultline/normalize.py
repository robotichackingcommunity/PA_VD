"""Bring a record into canonical shape (idempotent)."""
from __future__ import annotations

import copy
import re
from typing import Any

from .schema import NVD_STATUSES
from .taxonomy import (
    LAYER_AS_DOMAIN_FALLBACK,
    canonical_domain,
    canonical_layer,
    canonical_vendor,
    severity_for_score,
)

LEGACY_RATIONALE = "Normalized from legacy string value; rationale not recorded."
DATE_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def _date(value: Any) -> Any:
    if isinstance(value, str):
        m = DATE_PREFIX.match(value.strip())
        if m:
            return m.group(1)
        return value if value.strip() else None
    return value


def _dedupe(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _normalize_layers(raw: Any, changes: list[str]) -> list[dict]:
    """Return canonical technical_layer list.  Unknown names are kept verbatim
    (the validator will flag them) so nothing is silently lost."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]
    merged: dict[str, list[str]] = {}
    order: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            name = str(item.get("layer") or item.get("name") or "").strip()
            techs = item.get("technologies") or []
        else:
            name = str(item).strip()
            techs = []
        if not name:
            continue
        canon = canonical_layer(name) or name
        if canon != name:
            changes.append(f"layer alias {name!r} -> {canon!r}")
        if canon not in merged:
            merged[canon] = []
            order.append(canon)
        for t in techs:
            if isinstance(t, str) and t.strip() and t.strip() not in merged[canon]:
                merged[canon].append(t.strip())
    return [{"layer": n, "technologies": merged[n]} for n in order]


def _normalize_domains(raw: Any, layers: list[dict], changes: list[str]) -> list[dict]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]
    out: dict[str, dict] = {}
    order: list[str] = []
    pending_fallback: list[tuple] = []
    for item in raw:
        if isinstance(item, dict):
            name = str(item.get("domain") or item.get("name") or "").strip()
            conf = item.get("confidence", 0.8)
            rationale = item.get("rationale") or LEGACY_RATIONALE
        else:
            name = str(item).strip()
            conf, rationale = 0.8, LEGACY_RATIONALE
        if not name:
            continue
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.8
        conf = min(max(conf, 0.0), 1.0)
        canon = canonical_domain(name)
        if canon is None:
            layer = canonical_layer(name)
            if layer is not None:
                # A technical layer was filed as a domain: move it.
                if not any(l["layer"] == layer for l in layers):
                    layers.append({"layer": layer, "technologies": []})
                    changes.append(f"domain {name!r} moved to technical_layer")
                else:
                    changes.append(f"domain {name!r} dropped (already a technical_layer)")
                # Only substitute a fallback domain when the record would otherwise
                # have no domain at all; sibling-consistent domains already present win.
                pending_fallback.append((LAYER_AS_DOMAIN_FALLBACK.get(layer), layer, rationale, conf))
                continue
            else:
                canon = name  # unknown: leave for the validator
        if canon != name:
            changes.append(f"domain {name!r} -> {canon!r}")
        if canon in out:
            if conf > out[canon]["confidence"]:
                out[canon]["confidence"] = conf
            continue
        out[canon] = {"domain": canon, "confidence": round(conf, 2), "rationale": rationale}
        order.append(canon)
    if not order:
        for canon, layer, rationale, conf in pending_fallback:
            if canon and canon not in out:
                out[canon] = {"domain": canon, "confidence": round(min(conf, 0.6), 2),
                              "rationale": f"Re-filed from technical layer '{layer}' during taxonomy normalization. {rationale}"}
                order.append(canon)
                changes.append(f"domain fallback {canon!r} added for layer {layer!r}")
    return [out[n] for n in order]


def _normalize_vendors(raw: Any, changes: list[str]) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]
    names = []
    for v in raw:
        name = v.get("name") if isinstance(v, dict) else v
        if isinstance(name, str) and name.strip():
            canon = canonical_vendor(name)
            if canon != name.strip():
                changes.append(f"vendor {name!r} -> {canon!r}")
            names.append(canon)
    return _dedupe(names)


def _normalize_products(raw: Any) -> list:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]
    out = []
    for p in raw:
        if isinstance(p, dict):
            if isinstance(p.get("name"), str) and p["name"].strip():
                out.append(p)
        elif isinstance(p, str) and p.strip():
            out.append(p.strip())
    return out


def _str_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]
    return _dedupe([x.strip() for x in raw if isinstance(x, str) and x.strip()])


def _normalize_cwe(raw: Any, changes: list[str]) -> dict:
    """Canonical cwe = {id, name[, additional:[{id,name}]]}."""
    entries: list[dict] = []
    if isinstance(raw, str):
        entries = [{"id": raw, "name": None}]
        changes.append("cwe string -> object")
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                entries.append({"id": item.get("id"), "name": item.get("name")})
            elif isinstance(item, str):
                entries.append({"id": item, "name": None})
        changes.append("cwe list -> primary + additional")
    elif isinstance(raw, dict):
        ids, names = raw.get("id"), raw.get("name")
        if isinstance(ids, list):
            names = names if isinstance(names, list) else [names] * len(ids)
            for i, cid in enumerate(ids):
                entries.append({"id": cid, "name": names[i] if i < len(names) else None})
            changes.append("cwe.id list -> primary + additional")
        else:
            entries.append({"id": ids, "name": names})
            extra = raw.get("additional")
            if isinstance(extra, list):
                for item in extra:
                    if isinstance(item, dict):
                        entries.append({"id": item.get("id"), "name": item.get("name")})
    if not entries:
        return {"id": None, "name": None}
    out = {"id": entries[0]["id"], "name": entries[0]["name"]}
    rest = [e for e in entries[1:] if e.get("id") and e["id"] != out["id"]]
    if rest:
        out["additional"] = rest
    return out


def _normalize_source(raw: Any, cve_id: Any, changes: list[str]) -> dict:
    src = dict(raw) if isinstance(raw, dict) else {}
    for key, val in list(src.items()):
        if isinstance(val, dict) and isinstance(val.get("url"), str):
            src[key] = val["url"]
            changes.append(f"source.{key} object -> url")
    if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
        nvd = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if src.get("nvd") != nvd:
            if src.get("nvd") in (None, ""):
                changes.append("source.nvd filled")
            src["nvd"] = nvd
        cve_org = f"https://www.cve.org/CVERecord?id={cve_id}"
        if src.get("cve_org") != cve_org:
            src["cve_org"] = cve_org
            changes.append("source.cve_org filled")
    return src


def normalize(record: dict) -> tuple[dict, list[str]]:
    """Return (normalized_copy, list_of_changes)."""
    rec = copy.deepcopy(record)
    changes: list[str] = []

    for key in ("published", "last_modified"):
        if key in rec:
            new = _date(rec[key])
            if new != rec[key]:
                changes.append(f"{key} trimmed to date")
                rec[key] = new

    vs = rec.get("vuln_status")
    if vs is not None and vs not in NVD_STATUSES:
        changes.append(f"vuln_status {vs!r} cleared (not an NVD status)")
        rec["vuln_status"] = None

    rec["cwe"] = _normalize_cwe(rec.get("cwe"), changes)
    rec["source"] = _normalize_source(rec.get("source"), rec.get("cve_id"), changes)

    cvss = rec.get("cvss")
    if isinstance(cvss, dict):
        if cvss.get("version") is not None:
            cvss["version"] = str(cvss["version"])
        sev = cvss.get("severity")
        if isinstance(sev, str) and sev != sev.upper():
            cvss["severity"] = sev.upper()
            changes.append("cvss.severity upper-cased")
        if cvss.get("severity") is None and isinstance(cvss.get("score"), (int, float)):
            cvss["severity"] = severity_for_score(float(cvss["score"]))
            changes.append("cvss.severity derived from score")

    tax = rec.get("taxonomy")
    if isinstance(tax, dict):
        layers = _normalize_layers(tax.get("technical_layer"), changes)
        domains = _normalize_domains(tax.get("physical_ai_domain"), layers, changes)
        tax["physical_ai_domain"] = domains
        tax["technical_layer"] = layers
        tax["vendor"] = _normalize_vendors(tax.get("vendor"), changes)
        tax["product"] = _normalize_products(tax.get("product"))
        tax["attack_surface"] = _str_list(tax.get("attack_surface"))
        tax["vulnerability_class"] = _str_list(tax.get("vulnerability_class"))

    rec["cross_domain_tags"] = _str_list(rec.get("cross_domain_tags"))

    mapping = rec.get("mapping_to_pavt")
    if isinstance(mapping, dict):
        prim = mapping.get("primary_domain")
        if isinstance(prim, str):
            canon = canonical_domain(prim)
            if canon is None and canonical_layer(prim):
                canon = LAYER_AS_DOMAIN_FALLBACK.get(canonical_layer(prim))
            if canon and canon != prim:
                mapping["primary_domain"] = canon
                changes.append(f"mapping primary_domain {prim!r} -> {canon!r}")
        sec = mapping.get("secondary_domains")
        if isinstance(sec, list):
            new_sec = []
            for s in sec:
                if not isinstance(s, str):
                    continue
                c = canonical_domain(s)
                if c is None and canonical_layer(s):
                    c = LAYER_AS_DOMAIN_FALLBACK.get(canonical_layer(s))
                if c and c != mapping.get("primary_domain") and c not in new_sec:
                    new_sec.append(c)
            if new_sec != sec:
                mapping["secondary_domains"] = new_sec
                changes.append("mapping secondary_domains canonicalized")

    return rec, changes
