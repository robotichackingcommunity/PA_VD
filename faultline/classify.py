"""Rule-based relevance classifier for candidate CVEs.

Produces a transparent score (every matched rule is recorded) plus a proposed
taxonomy to seed enrichment and to let a human audit the decision.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from .taxonomy import DOMAINS, LAYERS


@lru_cache(maxsize=1)
def load_watchlist(path: str | None = None) -> dict:
    p = Path(path) if path else Path(__file__).resolve().parent.parent / "config" / "watchlist.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    for group in ("terms", "negative"):
        for rule in data.get(group, []):
            rule["_re"] = re.compile(rule["pattern"], re.IGNORECASE)
    return data


def candidate_text(facts: dict[str, Any]) -> str:
    parts = [facts.get("title") or "", facts.get("description") or ""]
    for a in facts.get("affected") or []:
        parts.append(f"{a.get('vendor') or ''} {a.get('product') or ''}")
    for cpe in facts.get("cpes") or []:
        bits = cpe.split(":")
        if len(bits) > 4:
            parts.append(f"{bits[3]} {bits[4]}".replace("_", " "))
    for ref in (facts.get("references") or [])[:10]:
        parts.append(ref)
    return "\n".join(parts)


def classify(facts: dict[str, Any], watchlist: dict | None = None) -> dict[str, Any]:
    wl = watchlist or load_watchlist()
    text = candidate_text(facts)
    score = 0
    matched: list[dict] = []
    dom_w: dict[str, int] = {}
    lay_w: dict[str, int] = {}
    for rule in wl["terms"]:
        m = rule["_re"].search(text)
        if not m:
            continue
        hits = len(set(x.lower() for x in rule["_re"].findall(text) if isinstance(x, str)))
        w = rule["weight"]
        if hits > 1:
            w += 1  # several distinct terms from the same family: a little more confidence
        score += w
        matched.append({"rule": rule["label"], "weight": w, "sample": m.group(0)})
        for d in rule.get("domains", []):
            dom_w[d] = dom_w.get(d, 0) + w
        for l in rule.get("layers", []):
            lay_w[l] = lay_w.get(l, 0) + w
    for rule in wl["negative"]:
        m = rule["_re"].search(text)
        if m and rule["weight"]:
            score += rule["weight"]
            matched.append({"rule": rule["label"], "weight": rule["weight"], "sample": m.group(0)})

    th = wl["thresholds"]
    if facts.get("state") == "REJECTED" or facts.get("vuln_status") == "Rejected":
        decision = "rejected"
    elif score >= th["accept"]:
        decision = "accept"
    elif score >= th["review"]:
        decision = "review"
    else:
        decision = "rejected"
    domains = [d for d, _ in sorted(dom_w.items(), key=lambda kv: -kv[1]) if d in DOMAINS][:3]
    layers = [l for l, _ in sorted(lay_w.items(), key=lambda kv: -kv[1]) if l in LAYERS][:3]
    return {
        "score": score,
        "decision": decision,
        "matched": matched,
        "proposed_domains": domains,
        "proposed_layers": layers,
    }


def nvd_backfill_keywords(watchlist: dict | None = None) -> list[str]:
    wl = watchlist or load_watchlist()
    out: list[str] = []
    for rule in wl["terms"]:
        for kw in rule.get("nvd_keywords", []):
            if kw not in out:
                out.append(kw)
    return out
