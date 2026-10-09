"""Fully automated adjudication of the review queue.

The rule-based classifier files borderline candidates (score 3-5) under
``data/queue/review.json`` for a human to confirm.  This module replaces that
human step with an LLM relevance gate: each candidate is shown to a cheap, fast
model that returns a strict in-scope verdict (no exploit content is generated at
this stage, only a yes/no classification).  Accepted candidates move to the
pending queue for full enrichment; rejected candidates move to the rejected
queue with the model's reason recorded, so every decision is auditable.
"""
from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .discover import QUEUE_FILES, load_queue, save_queue
from .enrich import _ThreadLocalDict, _extract_json, call_claude, claude_available, resolve_model
from .taxonomy import DOMAINS

log = logging.getLogger("faultline.triage")

# A gate verdict is a simple classification, so a small fast model is enough and
# cheap at scale.  Override with --model.
DEFAULT_GATE_MODEL = "claude-haiku-5-5"

_LAST = _ThreadLocalDict()

GATE_SYSTEM = (
    "You are a strict relevance classifier for FaultLine, a Physical AI vulnerability "
    "database. You decide whether a CVE belongs in it. Answer with one JSON object only; "
    "never include exploit details."
)

GATE_TEMPLATE = """FaultLine catalogues vulnerabilities in **Physical AI systems** and the AI \
infrastructure that drives them. A CVE is IN SCOPE only if the vulnerable product is, or is a \
direct component of, one of these and a physical or embodied consequence is plausible:
- a robot, drone/UAV, autonomous vehicle, humanoid, or other embodied/mobile machine;
- robot software stacks or middleware (ROS/ROS 2, DDS, MoveIt, Nav2, PX4/ArduPilot, MAVLink);
- AI inference/serving, training, or MLOps infrastructure that runs models for such systems
  (e.g. an inference server, model loader, or agent framework that issues actions to a robot
  or embodied device), where compromise could reach a physical or embodied system.

OUT OF SCOPE (reject): generic IT/web/enterprise software, CMS/plugins, mobile apps unrelated
to a robot, robotic process automation (RPA), pure-cloud ML with no embodied pathway, a library
whose CVE has no robotics/embodied use, developer tooling, chat/social bots, and anything whose
only link is an incidental keyword ("robot", "drone", "spot", "apollo") unrelated to Physical AI.

Allowed domains (for primary_domain): {{DOMAINS}}

Decide for this CVE. Output ONLY this JSON object:
{"in_scope": true|false, "primary_domain": "<one allowed domain, or null if out of scope>",
 "confidence": 0.0-1.0, "reason": "<one concise sentence>"}

CVE:
{{FACTS}}
"""


def build_gate_prompt(cve_id: str, candidate: dict[str, Any]) -> str:
    # The queued candidate already carries title/description/affected from discovery,
    # so the gate needs no network fetch — a relevance call only needs what the CVE is about.
    affected = candidate.get("affected") or []
    slim = {
        "cve_id": cve_id,
        "title": candidate.get("title"),
        "description": (candidate.get("description") or "")[:1200],
        "vendor_product": [
            {"vendor": a.get("vendor"), "product": a.get("product")}
            for a in affected[:6] if isinstance(a, dict)
        ],
        "classifier_hint": {
            "matched_rules": [m["rule"] for m in candidate.get("matched", [])],
            "proposed_domains": candidate.get("proposed_domains"),
        },
    }
    return GATE_TEMPLATE.replace("{{DOMAINS}}", json.dumps(list(DOMAINS))).replace(
        "{{FACTS}}", json.dumps(slim, ensure_ascii=False, indent=1)
    )


def gate_one(cve_id: str, candidate: dict[str, Any], model: str | None) -> dict[str, Any] | None:
    """Return the verdict dict, or None if the model gave no usable JSON."""
    prompt = build_gate_prompt(cve_id, candidate)
    raw = call_claude(prompt, model)
    verdict = raw if isinstance(raw, dict) else None
    if verdict is None:
        return None
    verdict["in_scope"] = bool(verdict.get("in_scope"))
    try:
        verdict["confidence"] = float(verdict.get("confidence"))
    except (TypeError, ValueError):
        verdict["confidence"] = 0.0
    pd = verdict.get("primary_domain")
    if pd not in DOMAINS:
        verdict["primary_domain"] = None
    return verdict


def triage_review(max_records: int | None = None, model: str | None = None,
                  min_confidence: float = 0.6, jobs: int = 4,
                  dry_run: bool = False) -> dict[str, Any]:
    review = load_queue(QUEUE_FILES["review"])
    gate_model = model or DEFAULT_GATE_MODEL
    stats = {"review": len(review), "accepted": 0, "rejected": 0, "undecided": 0, "model": gate_model}
    targets = list(review)
    if max_records is not None:
        targets = targets[:max_records]
    if not targets:
        return stats
    if dry_run:
        c = targets[0]
        print(build_gate_prompt(c, review[c]))
        return stats
    if not claude_available():
        stats["skipped_no_claude"] = len(targets)
        return stats

    pending = load_queue(QUEUE_FILES["accept"])
    rejected = load_queue(QUEUE_FILES["rejected"])
    lock = threading.Lock()

    def commit(cve_id: str, verdict: dict[str, Any] | None) -> None:
        with lock:
            entry = dict(review.get(cve_id, {}))
            if verdict is None:
                stats["undecided"] += 1
                entry["triage"] = {"error": "no verdict"}
                review[cve_id] = entry
                return
            entry["triage"] = {k: verdict.get(k) for k in ("in_scope", "primary_domain", "confidence", "reason")}
            entry["triage"]["model"] = gate_model
            if verdict["in_scope"] and verdict["confidence"] >= min_confidence:
                if verdict.get("primary_domain") and not entry.get("proposed_domains"):
                    entry["proposed_domains"] = [verdict["primary_domain"]]
                pending[cve_id] = entry
                review.pop(cve_id, None)
                stats["accepted"] += 1
                log.info("ACCEPT %s (%.2f) %s", cve_id, verdict["confidence"], (verdict.get("reason") or "")[:70])
            else:
                rejected[cve_id] = entry
                review.pop(cve_id, None)
                stats["rejected"] += 1
                log.info("reject %s (%.2f) %s", cve_id, verdict["confidence"], (verdict.get("reason") or "")[:70])
            save_queue(QUEUE_FILES["accept"], pending)
            save_queue(QUEUE_FILES["review"], review)
            save_queue(QUEUE_FILES["rejected"], rejected)

    def work(cve_id: str) -> None:
        commit(cve_id, gate_one(cve_id, review[cve_id], gate_model))

    jobs = max(1, jobs)
    if jobs == 1:
        for c in targets:
            work(c)
    else:
        log.info("triaging %d candidate(s) with %d workers (gate model %s)", len(targets), jobs, gate_model)
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = {pool.submit(work, c): c for c in targets}
            for fut in as_completed(futures):
                exc = fut.exception()
                if exc:
                    log.error("%s: gate worker crashed: %s", futures[fut], exc)
    stats["review"] = len(review)
    stats["pending_now"] = len(pending)
    return stats
