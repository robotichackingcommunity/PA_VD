"""Lightweight record validator (no third-party dependencies).

validate(record) returns (errors, warnings).  Errors block a commit; warnings
are reported but tolerated.
"""
from __future__ import annotations

import re
from typing import Any

from .records import CVE_RE
from .taxonomy import DOMAINS, LAYERS, SEVERITIES

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CWE_RE = re.compile(r"^(CWE-\d+|NVD-CWE-noinfo|NVD-CWE-Other)$")
CVSS_VERSIONS = {"2.0", "3.0", "3.1", "4.0"}
NVD_STATUSES = {
    "Received", "Awaiting Analysis", "Undergoing Analysis", "Analyzed",
    "Modified", "Deferred", "Rejected",
}


def _is_str(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""


def validate(rec: dict) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    e, w = errors.append, warnings.append

    cve_id = rec.get("cve_id")
    if not (_is_str(cve_id) and CVE_RE.match(cve_id)):
        e(f"cve_id invalid: {cve_id!r}")
    if not _is_str(rec.get("title")):
        e("title missing")
    if not _is_str(rec.get("description")):
        w("description missing")

    src = rec.get("source")
    if not isinstance(src, dict) or not (src.get("nvd") or src.get("cve_org")):
        e("source must be an object with an 'nvd' or 'cve_org' URL")

    pub = rec.get("published")
    if not (_is_str(pub) and DATE_RE.match(pub)):
        e(f"published must be YYYY-MM-DD, got {pub!r}")
    lm = rec.get("last_modified")
    if lm is not None and not (_is_str(lm) and DATE_RE.match(lm)):
        e(f"last_modified must be YYYY-MM-DD, got {lm!r}")

    vs = rec.get("vuln_status")
    if vs is not None and vs not in NVD_STATUSES:
        e(f"vuln_status not an NVD status: {vs!r}")

    cwe = rec.get("cwe")
    if not isinstance(cwe, dict):
        e("cwe must be an object {id, name}")
    else:
        cid = cwe.get("id")
        if cid is None:
            w("cwe.id is null")
        elif not (_is_str(cid) and CWE_RE.match(cid)):
            e(f"cwe.id invalid: {cid!r}")

    cvss = rec.get("cvss")
    if not isinstance(cvss, dict):
        e("cvss must be an object")
    else:
        if str(cvss.get("version")) not in CVSS_VERSIONS:
            e(f"cvss.version invalid: {cvss.get('version')!r}")
        score = cvss.get("score")
        if score is None:
            w("cvss.score missing")
        elif not isinstance(score, (int, float)) or not 0 <= float(score) <= 10:
            e(f"cvss.score out of range: {score!r}")
        sev = cvss.get("severity")
        if sev is None:
            w("cvss.severity missing")
        elif sev not in SEVERITIES:
            e(f"cvss.severity invalid: {sev!r}")
        vec = cvss.get("vector")
        if vec is not None and not (_is_str(vec) and vec.startswith(("CVSS:", "AV:"))):
            e(f"cvss.vector malformed: {vec!r}")

    tax = rec.get("taxonomy")
    if not isinstance(tax, dict):
        e("taxonomy missing")
    else:
        doms = tax.get("physical_ai_domain")
        if not isinstance(doms, list) or not doms:
            e("taxonomy.physical_ai_domain must be a non-empty list")
        else:
            seen = set()
            for d in doms:
                if not isinstance(d, dict):
                    e(f"physical_ai_domain entry must be an object, got {d!r}")
                    continue
                name = d.get("domain")
                if name not in DOMAINS:
                    e(f"physical_ai_domain not in vocabulary: {name!r}")
                if name in seen:
                    e(f"physical_ai_domain duplicated: {name!r}")
                seen.add(name)
                conf = d.get("confidence")
                if not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
                    e(f"physical_ai_domain confidence invalid for {name!r}: {conf!r}")
                if not _is_str(d.get("rationale")):
                    w(f"physical_ai_domain rationale missing for {name!r}")
        layers = tax.get("technical_layer")
        if not isinstance(layers, list) or not layers:
            e("taxonomy.technical_layer must be a non-empty list")
        else:
            seen = set()
            for l in layers:
                if not isinstance(l, dict):
                    e(f"technical_layer entry must be an object, got {l!r}")
                    continue
                name = l.get("layer")
                if name not in LAYERS:
                    e(f"technical_layer not in vocabulary: {name!r}")
                if name in seen:
                    e(f"technical_layer duplicated: {name!r}")
                seen.add(name)
                techs = l.get("technologies")
                if not isinstance(techs, list) or not all(isinstance(t, str) for t in techs):
                    e(f"technical_layer.technologies must be a list of strings for {name!r}")
        vendors = tax.get("vendor")
        if not isinstance(vendors, list) or not vendors or not all(_is_str(v) for v in vendors):
            e("taxonomy.vendor must be a non-empty list of strings")
        products = tax.get("product")
        if not isinstance(products, list):
            e("taxonomy.product must be a list")
        else:
            for p in products:
                if isinstance(p, dict):
                    if not _is_str(p.get("name")):
                        e(f"taxonomy.product object without name: {p!r}")
                elif not _is_str(p):
                    e(f"taxonomy.product entry invalid: {p!r}")
        for key in ("attack_surface", "vulnerability_class"):
            v = tax.get(key)
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                e(f"taxonomy.{key} must be a list of strings")

    ac = rec.get("attack_chain")
    if not isinstance(ac, dict) or not ac:
        e("attack_chain missing")
    else:
        if "paths" in ac:
            e("attack_chain uses legacy 'paths' layout (run normalize)")
        steps = ac.get("steps")
        if not isinstance(steps, list) or not all(isinstance(x, str) for x in steps):
            e("attack_chain.steps must be a list of strings")
        elif len(steps) < 2:
            w("attack_chain has fewer than 2 steps")
        if not isinstance(ac.get("preconditions"), list):
            e("attack_chain.preconditions must be a list")
        if not ac.get("physical_consequence"):
            w("attack_chain.physical_consequence missing")
        try:
            from .normalize import contains_payload
            all_steps = list(steps or []) + [x for p in (ac.get("alternate_paths") or []) for x in (p.get("steps") or [])]
            if any(isinstance(x, str) and contains_payload(x) for x in all_steps):
                e("attack_chain.steps contain an operational payload (run normalize)")
        except Exception:
            pass
    if not isinstance(rec.get("impact"), dict):
        e("impact must be an object")
    if not isinstance(rec.get("security_observations"), dict):
        e("security_observations must be an object")
    tags = rec.get("cross_domain_tags")
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        e("cross_domain_tags must be a list of strings")
    mit = rec.get("mitigation")
    if not isinstance(mit, dict):
        e("mitigation must be an object (run normalize)")
    else:
        for key in ("patch_available", "fixed_version", "workaround", "fix_description"):
            if key not in mit:
                e(f"mitigation.{key} missing")
        if mit.get("patch_available") is not None and not isinstance(mit.get("patch_available"), bool):
            e("mitigation.patch_available must be boolean or null")
        if not any(mit.get(k) for k in ("fixed_version", "workaround", "fix_description")):
            w("mitigation has no actionable content")
    if not isinstance(rec.get("enrichment"), dict) or rec["enrichment"].get("method") not in ("curated", "claude-auto", "manual"):
        e("enrichment.method must be one of curated / claude-auto / manual")
    affc = rec.get("affected_configurations")
    if affc is not None and not isinstance(affc, (list, dict)):
        e("affected_configurations must be a list or object")
    enr = rec.get("enrichment")
    if enr is not None and not isinstance(enr, dict):
        e("enrichment must be an object")
    return errors, warnings
