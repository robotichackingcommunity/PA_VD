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

    ac, changed = canonical_attack_chain(rec.get("attack_chain"))
    if changed:
        rec["attack_chain"] = ac
        changes.append("attack_chain canonicalized")
    ac = rec.get("attack_chain")
    if isinstance(ac, dict) and not ac.get("physical_consequence"):
        pwi = (rec.get("impact") or {}).get("physical_world_impact")
        if isinstance(pwi, list) and pwi:
            ac["physical_consequence"] = "; ".join(str(x).strip() for x in pwi if str(x).strip()) or None
            changes.append("physical_consequence derived from impact.physical_world_impact")
        elif isinstance(pwi, str) and pwi.strip():
            ac["physical_consequence"] = pwi.strip()
            changes.append("physical_consequence derived from impact.physical_world_impact")
    # Strip operational payloads from steps: this is a defensive database and the
    # enrichment policy is conceptual-chain-only (no commands, URLs, or payloads).
    if isinstance(ac, dict):
        red = 0
        for key in ("steps",):
            ac[key] = [_redact_payload(x) if isinstance(x, str) else x for x in (ac.get(key) or [])]
        for p_ in ac.get("alternate_paths") or []:
            p_["steps"] = [_redact_payload(x) if isinstance(x, str) else x for x in (p_.get("steps") or [])]
        rc = sum(1 for x in ac.get("steps") or [] if isinstance(x, str) and "[redacted" in x)
        rc += sum(1 for p_ in ac.get("alternate_paths") or [] for x in p_.get("steps") or [] if isinstance(x, str) and "[redacted" in x)
        if rc:
            changes.append(f"attack_chain: redacted operational payload in {rc} step(s)")
    mit, changed = canonical_mitigation(rec.get("mitigation"))
    if changed:
        rec["mitigation"] = mit
        changes.append("mitigation canonicalized")
    if not isinstance(rec.get("enrichment"), dict):
        rec["enrichment"] = {"method": "curated", "reviewed": True}
        changes.append("enrichment block added (curated)")

    # Domains ordered by confidence; mapping_to_pavt.primary_domain follows the top one.
    doms = (rec.get("taxonomy") or {}).get("physical_ai_domain")
    if isinstance(doms, list) and doms and all(isinstance(d, dict) for d in doms):
        ordered = sorted(doms, key=lambda d: -(d.get("confidence") or 0))
        if ordered != doms:
            rec["taxonomy"]["physical_ai_domain"] = ordered
            changes.append("domains reordered by confidence")
        mapping = rec.get("mapping_to_pavt")
        if isinstance(mapping, dict) and mapping.get("primary_domain") != ordered[0]["domain"]:
            old_primary = mapping.get("primary_domain")
            mapping["primary_domain"] = ordered[0]["domain"]
            sec = [d["domain"] for d in ordered[1:]]
            for d in mapping.get("secondary_domains") or []:
                if d not in sec and d != ordered[0]["domain"]:
                    sec.append(d)
            mapping["secondary_domains"] = sec
            changes.append(f"primary_domain {old_primary!r} -> {ordered[0]['domain']!r} (highest confidence)")

    affc = rec.get("affected_configurations")
    if isinstance(affc, list):
        kept = [row for row in affc if not _placeholder_row(row)]
        if len(kept) != len(affc):
            rec["affected_configurations"] = kept
            changes.append(f"affected_configurations: dropped {len(affc) - len(kept)} placeholder row(s)")

    return rec, changes


_PLACEHOLDERS = {"", "n/a", "na", "none", "unspecified", "unknown", "-"}


def _placeholder_row(row) -> bool:
    """True for CNA filler rows such as {"vendor": "n/a", "product": "n/a"}."""
    if not isinstance(row, dict):
        return False
    vendor = str(row.get("vendor") or "").strip().lower()
    product = str(row.get("product") or "").strip().lower()
    return vendor in _PLACEHOLDERS and product in _PLACEHOLDERS


# --- attack_chain / mitigation canonical shapes -------------------------------------------
#
# Legacy curated records used {"paths": [...]} with half a dozen inner layouts and ~20
# different mitigation key sets.  Canonical shapes (what the enrichment prompt emits):
#   attack_chain: {"preconditions": [str], "steps": ["1. ...", ...], "physical_consequence": str,
#                  "name"?: str, "alternate_paths"?: [{"name","steps","physical_consequence"}]}
#   mitigation:   {"patch_available": bool|None, "fixed_version": str|None, "workaround": str|None,
#                  "fix_description": str|None, "references"?: [url], "detection"?: str, "notes"?: [str]}

MITIGATION_CORE = ("patch_available", "fixed_version", "workaround", "fix_description")
_STEP_NUM = re.compile(r"^\s*(\d+)[.)]\s+")


def _step_strings(steps) -> list[str]:
    out: list[str] = []
    for raw in steps or []:
        if isinstance(raw, dict):
            raw = raw.get("description") or raw.get("text") or raw.get("action") or ""
        text = str(raw).strip()
        if not text:
            continue
        text = _STEP_NUM.sub("", text)
        out.append(f"{len(out) + 1}. {text}")
    return out


def _path_name(path: dict) -> str | None:
    for key in ("name", "label", "description", "attack_vector"):
        if isinstance(path.get(key), str) and path[key].strip():
            return path[key].strip()
    return None


def canonical_attack_chain(ac):
    """Return (attack_chain, changed)."""
    if not isinstance(ac, dict):
        return ac, False
    if "paths" not in ac:
        changed = False
        if isinstance(ac.get("steps"), list) and any(isinstance(x, dict) or not _STEP_NUM.match(str(x)) for x in ac["steps"]):
            ac["steps"] = _step_strings(ac["steps"]); changed = True
        for key, default in (("preconditions", []), ("physical_consequence", None)):
            if key not in ac:
                ac[key] = default; changed = True
        return ac, changed
    paths = [x for x in (ac.get("paths") or []) if isinstance(x, dict)]
    if not paths:
        return {"preconditions": [], "steps": [], "physical_consequence": ac.get("physical_consequence")}, True
    primary = paths[0]
    pre = primary.get("prerequisites") or primary.get("preconditions") or ac.get("preconditions") or []
    if isinstance(pre, str):
        pre = [pre]
    pre = [str(x).strip() for x in pre if str(x).strip()]
    if not pre and isinstance(primary.get("attack_vector"), str):
        pre = [primary["attack_vector"].strip()]
    consequence = primary.get("physical_consequence") or ac.get("physical_consequence")
    if not consequence:
        consequence = next((x.get("physical_consequence") for x in paths if x.get("physical_consequence")), None)
    new = {"preconditions": pre, "steps": _step_strings(primary.get("steps")), "physical_consequence": consequence}
    name = _path_name(primary)
    if name:
        new["name"] = name
    alts = []
    for x in paths[1:]:
        alts.append({"name": _path_name(x), "steps": _step_strings(x.get("steps")), "physical_consequence": x.get("physical_consequence")})
    if alts:
        new["alternate_paths"] = alts
    return new, True


def _first_text(*values) -> str | None:
    for v in values:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _join_text(value) -> str | None:
    if isinstance(value, list):
        parts = [str(x).strip() for x in value if str(x).strip()]
        return "; ".join(parts) or None
    return _first_text(value)


def canonical_mitigation(m):
    """Return (mitigation, changed)."""
    if m is None:
        return {k: None for k in MITIGATION_CORE}, True
    if not isinstance(m, dict):
        return m, False
    known = set(MITIGATION_CORE) | {"references", "detection", "notes"}
    if set(m) <= known:
        if all(k in m for k in MITIGATION_CORE):
            return m, False
        for k in MITIGATION_CORE:
            m.setdefault(k, None)
        return m, True
    patch = m.get("patch")
    pd = patch if isinstance(patch, dict) else {}
    pa = m.get("patch_available")
    if not isinstance(pa, bool):
        pa = pd.get("available") if isinstance(pd.get("available"), bool) else None
    if pa is None and isinstance(m.get("vendor_fix"), bool):
        pa = m["vendor_fix"]
    fixed = _first_text(m.get("fixed_version"), m.get("patch_version"), pd.get("version"), pd.get("fixed_version"))
    if not fixed and isinstance(m.get("fix_versions"), list):
        fixed = ", ".join(str(x) for x in m["fix_versions"]) or None
    fix = _first_text(m.get("fix_description"), m.get("official_fix"), m.get("vendor_fix"), m.get("recommendation"),
                      m.get("short_term"), m.get("description"), pd.get("description"), patch,
                      m.get("patch_notes"), m.get("patch_description"))
    workaround = _join_text(m.get("workaround")) or _join_text(m.get("workarounds"))
    refs: list[str] = []
    for key in ("patch_url", "fix_commit", "pull_request", "patch_pr", "reference", "patch_commit"):
        v = m.get(key)
        if isinstance(v, str) and v.startswith("http") and v not in refs:
            refs.append(v)
    if isinstance(pd.get("url"), str) and pd["url"].startswith("http") and pd["url"] not in refs:
        refs.append(pd["url"])
    for v in m.get("references") or []:
        if isinstance(v, str) and v.startswith("http") and v not in refs:
            refs.append(v)
    notes: list[str] = []
    if isinstance(m.get("patch_commit"), str) and not m["patch_commit"].startswith("http"):
        notes.append(f"Fix commit {m['patch_commit']}")
    if _first_text(m.get("long_term")):
        if fix:
            notes.append(f"Long term: {m['long_term'].strip()}")
        else:
            fix = m["long_term"].strip()
    for key in ("long_term_vendor_fixes_needed", "regression_test", "date_mitigation", "patch_notes", "patch_description"):
        v = m.get(key)
        if _first_text(v) and v.strip() != fix:
            notes.append(f"{key.replace('_', ' ').capitalize()}: {v.strip()}")
        elif isinstance(v, list) and v:
            notes.append(f"{key.replace('_', ' ').capitalize()}: {_join_text(v)}")
    if pa is None and (fixed or any(("/commit/" in r or "/pull/" in r) for r in refs)):
        pa = True
    out = {"patch_available": pa, "fixed_version": fixed, "workaround": workaround, "fix_description": fix}
    if refs:
        out["references"] = refs
    if _first_text(m.get("detection")):
        out["detection"] = m["detection"].strip()
    if notes:
        out["notes"] = notes
    return out, True


import re as _re_payload

# Operational fragments that must never appear in a public defensive record.
# This database documents conceptual attack chains only (like NVD/CISA), never
# runnable commands, payloads or attacker infrastructure.
_PAYLOAD_SUBS = [
    (_re_payload.compile(r"`[^`]*`"), "[redacted command]"),
    (_re_payload.compile(r"\$\([^)]*\)"), "[redacted command]"),
    (_re_payload.compile(r"\b(?:wget|curl)\b[^\n]*?https?://\S+"), "[redacted download command]"),
    (_re_payload.compile(r"https?://(?:attacker|evil|malicious|example|target)\S*", _re_payload.I), "[redacted URL]"),
    (_re_payload.compile(r"\b(?:bash|sh)\s+/\S+\.sh[^\n]*"), "[redacted script invocation]"),
    (_re_payload.compile(r"\b(?:nc|ncat|netcat)\s+-\w[^\n]*"), "[redacted command]"),
    (_re_payload.compile(r"\bbase64\s+-d[^\n]*"), "[redacted decoded payload]"),
    (_re_payload.compile(r"\b(?:wget|curl)\b\s+\S+"), "[redacted download command]"),
    (_re_payload.compile(r"/tmp/[\w.\-]+"), "[temp path]"),
    (_re_payload.compile(r"0x[0-9a-fA-F]{4,}"), "[hex value]"),
    (_re_payload.compile(r";\s*#[^\n]*"), ""),
    (_re_payload.compile(r"/bin/sh\S*"), "[shell]"),
]
# A concrete quoted example after "e.g." / "such as" / "payload:" that still looks operational.
_PAYLOAD_EXAMPLE = _re_payload.compile(
    r"(,?\s*(?:e\.g\.?|such as|for example|payload)[:,]?\s*)[\"'][^\"']*[\"']", _re_payload.I)
_PAYLOAD_MARKER = _re_payload.compile(
    r"\$\(|`|\bwget\b|\bcurl\b[^\n]*http|/tmp/|\b(?:bash|sh)\s+/\S+\.sh|;#|base64\s+-d|\bnc\s+-e|/bin/sh|0x[0-9a-fA-F]{4,}")


def contains_payload(text: str) -> bool:
    return bool(_PAYLOAD_MARKER.search(text or ""))


def _redact_payload(text: str) -> str:
    out = _PAYLOAD_EXAMPLE.sub(r"\1[redacted payload example]", text)
    for rx, repl in _PAYLOAD_SUBS:
        out = rx.sub(repl, out)
    out = _re_payload.sub(r"\s{2,}", " ", out).strip()
    out = _re_payload.sub(r"(\[redacted[^\]]*\])(\s*\1)+", r"\1", out)
    if contains_payload(out):
        # Stubborn residue: drop the step body, keep only a leading step number if present.
        m = _re_payload.match(r"\s*(\d+[.)])\s*", out)
        prefix = (m.group(1) + " ") if m else ""
        return prefix + "[step redacted: contained an operational payload]"
    return out
