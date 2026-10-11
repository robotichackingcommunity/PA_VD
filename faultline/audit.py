"""Classification audit: check every record's primary domain and technical layers
against the controlled vocabulary with an LLM, and report likely misclassifications.

Read-only: this never edits records. It writes a full verdict report to
``data/audit_report.json`` and returns a summary. Reuses the cheap/fast gate model
and the parallel-worker + thread-local infrastructure from :mod:`faultline.enrich`.
"""
from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .enrich import call_claude, claude_available, resolve_model
from .records import iter_record_files, load_json
from .taxonomy import DOMAINS, LAYERS

log = logging.getLogger("faultline.audit")

DEFAULT_AUDIT_MODEL = "claude-haiku-5-5"

AUDIT_SYSTEM = (
    "You are a precise classification reviewer for a Physical AI vulnerability database. "
    "You check whether a CVE's assigned domain and technical layers are the best fit from a "
    "fixed vocabulary. Answer with one JSON object only; never include exploit details."
)

AUDIT_TEMPLATE = """Controlled vocabularies (choose ONLY from these):
PHYSICAL_AI_DOMAIN = {{DOMAINS}}
TECHNICAL_LAYER = {{LAYERS}}

Domain meaning in brief:
- Humanoid Robot, Industrial Robot, Mobile Robot & AMR, Drone & Aerial Robotics,
  Service & Companion Robot, Autonomous Vehicle AI: the vulnerable product is that kind of machine.
- Robot Operating Systems & Middleware: ROS/ROS 2, DDS, MoveIt, Nav2, robot middleware/SDKs.
- Physical AI Infrastructure: AI inference/serving, training, MLOps that runs models for physical/embodied systems.
- Embodied AI Agent: agentic/LLM-agent frameworks that act on the world (execute code, control devices/browsers, invoke tools).
- Cross-Domain Components: shared components spanning several of the above with no single best home.

Review this record. Decide whether its CURRENT primary_domain is the best fit, and whether its
CURRENT technical layers are appropriate. Be conservative: only mark wrong when you are confident
a different choice is clearly better. Output ONLY this JSON object:
{"domain_ok": true|false, "best_domain": "<one PHYSICAL_AI_DOMAIN value>",
 "layers_ok": true|false, "suggested_layers": ["<TECHNICAL_LAYER values>"],
 "confidence": 0.0-1.0, "reason": "<one concise sentence>"}

RECORD:
{{REC}}
"""


def _summary(rec: dict) -> dict:
    tx = rec.get("taxonomy") or {}
    return {
        "cve_id": rec.get("cve_id"),
        "title": rec.get("title"),
        "description": (rec.get("description") or "")[:900],
        "vendor": tx.get("vendor"),
        "product": tx.get("product"),
        "current_primary_domain": (rec.get("mapping_to_pavt") or {}).get("primary_domain"),
        "current_domains": [d.get("domain") for d in tx.get("physical_ai_domain", [])],
        "current_layers": [l.get("layer") for l in tx.get("technical_layer", [])],
    }


def build_audit_prompt(rec: dict) -> str:
    return (AUDIT_TEMPLATE
            .replace("{{DOMAINS}}", json.dumps(list(DOMAINS)))
            .replace("{{LAYERS}}", json.dumps(list(LAYERS)))
            .replace("{{REC}}", json.dumps(_summary(rec), ensure_ascii=False, indent=1)))


def audit_one(rec: dict, model: str | None) -> dict[str, Any] | None:
    raw = call_claude(build_audit_prompt(rec), model)
    if not isinstance(raw, dict):
        return None
    out = {
        "cve_id": rec.get("cve_id"),
        "current_domain": (rec.get("mapping_to_pavt") or {}).get("primary_domain"),
        "current_layers": [l.get("layer") for l in (rec.get("taxonomy") or {}).get("technical_layer", [])],
        "domain_ok": bool(raw.get("domain_ok", True)),
        "best_domain": raw.get("best_domain") if raw.get("best_domain") in DOMAINS else None,
        "layers_ok": bool(raw.get("layers_ok", True)),
        "suggested_layers": [l for l in (raw.get("suggested_layers") or []) if l in LAYERS],
        "reason": (raw.get("reason") or "")[:200],
    }
    try:
        out["confidence"] = float(raw.get("confidence"))
    except (TypeError, ValueError):
        out["confidence"] = 0.0
    # A domain flag only counts if the model actually names a different valid domain.
    out["domain_flag"] = (not out["domain_ok"]) and bool(out["best_domain"]) and out["best_domain"] != out["current_domain"]
    out["layer_flag"] = not out["layers_ok"]
    return out


def audit_all(max_records: int | None = None, model: str | None = None, jobs: int = 8,
              min_confidence: float = 0.7, only_domain: str | None = None) -> dict[str, Any]:
    recs = []
    for p in iter_record_files():
        try:
            r = load_json(p)
        except ValueError:
            continue
        if only_domain and (r.get("mapping_to_pavt") or {}).get("primary_domain") != only_domain:
            continue
        recs.append(r)
    if max_records is not None:
        recs = recs[:max_records]
    audit_model = model or DEFAULT_AUDIT_MODEL
    stats = {"audited": 0, "domain_flags": 0, "layer_flags": 0, "undecided": 0, "model": audit_model, "total": len(recs)}
    if not claude_available():
        stats["skipped_no_claude"] = len(recs)
        return stats

    results: list[dict] = []
    lock = threading.Lock()

    def work(rec: dict) -> None:
        v = audit_one(rec, audit_model)
        with lock:
            if v is None:
                stats["undecided"] += 1
                return
            stats["audited"] += 1
            if v["domain_flag"] and v["confidence"] >= min_confidence:
                stats["domain_flags"] += 1
                results.append(v)
            elif v["layer_flag"] and v["confidence"] >= min_confidence:
                stats["layer_flags"] += 1
                results.append(v)
            if stats["audited"] % 100 == 0:
                log.info("audited %d/%d (domain flags %d, layer flags %d)",
                         stats["audited"], len(recs), stats["domain_flags"], stats["layer_flags"])

    jobs = max(1, jobs)
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(work, r) for r in recs]
        for fut in as_completed(futures):
            exc = fut.exception()
            if exc:
                log.error("audit worker crashed: %s", exc)

    from .records import repo_root
    report = repo_root() / "data" / "audit_report.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"stats": stats, "flags": results}, ensure_ascii=False, indent=2), encoding="utf-8")
    stats["report"] = str(report)
    return stats
