"""Discover new Physical-AI-relevant CVEs from NVD, MITRE cvelistV5 and GHSA,
score them with the rule classifier and maintain the review queues under
data/queue/."""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .classify import classify, nvd_backfill_keywords
from .records import load_all, repo_root
from .sources import cvelist, ghsa, mitre, nvd
from .sources.facts import merge_facts
from .state import load_state, now_iso, save_state

log = logging.getLogger("faultline.discover")

QUEUE_FILES = {"accept": "pending.json", "review": "review.json", "rejected": "rejected.json"}
MAX_WINDOW_DAYS = 120  # NVD API limit for date-range queries


def queue_dir(root: Path | None = None) -> Path:
    d = (root or repo_root()) / "data" / "queue"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_queue(name: str) -> dict[str, dict]:
    p = queue_dir() / name
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def save_queue(name: str, data: dict[str, dict]) -> None:
    p = queue_dir() / name
    ordered = dict(sorted(data.items(), key=lambda kv: (-(kv[1].get("score") or 0), kv[0])))
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(ordered, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _candidate_entry(facts: dict[str, Any], verdict: dict[str, Any], origin: str) -> dict[str, Any]:
    return {
        "cve_id": facts["cve_id"],
        "score": verdict["score"],
        "decision": verdict["decision"],
        "matched": verdict["matched"],
        "proposed_domains": verdict["proposed_domains"],
        "proposed_layers": verdict["proposed_layers"],
        "title": facts.get("title"),
        "description": (facts.get("description") or "")[:600 if verdict["decision"] != "rejected" else 200],
        "published": facts.get("published"),
        "last_modified": facts.get("last_modified"),
        "vuln_status": facts.get("vuln_status"),
        "cvss": facts.get("cvss")[:2] if facts.get("cvss") else [],
        "affected": facts.get("affected")[:6] if facts.get("affected") else [],
        "references": (facts.get("references") or [])[:8],
        "origin": origin,
        "seen_at": now_iso(),
    }


class Triage:
    """Holds the three queues and routes candidates into them."""

    def __init__(self) -> None:
        self.known = set(load_all().keys())
        self.queues = {k: load_queue(v) for k, v in QUEUE_FILES.items()}
        self.stats = {"seen": 0, "already_in_db": 0, "accept": 0, "review": 0, "rejected": 0, "rescored": 0}
        self._decided: dict[str, str] = {}

    def previously_seen(self, cve_id: str) -> str | None:
        for k, q in self.queues.items():
            if cve_id in q:
                return k
        return None

    def consider(self, facts: dict[str, Any], origin: str) -> None:
        cve_id = facts.get("cve_id")
        if not cve_id:
            return
        self.stats["seen"] += 1
        if cve_id in self.known:
            self.stats["already_in_db"] += 1
            return
        verdict = classify(facts)
        prev = self.previously_seen(cve_id)
        if prev == "accept" and self.queues["accept"][cve_id].get("manual"):
            return  # a human pinned it; do not re-score
        if prev and prev != verdict["decision"] and cve_id not in self._decided:
            self.stats["rescored"] += 1
        for k in QUEUE_FILES:
            self.queues[k].pop(cve_id, None)
        self.queues[verdict["decision"]][cve_id] = _candidate_entry(facts, verdict, origin)
        earlier = self._decided.get(cve_id)
        if earlier:
            self.stats[earlier] -= 1  # same CVE seen from a second source this run: count once
        self._decided[cve_id] = verdict["decision"]
        self.stats[verdict["decision"]] += 1

    def save(self) -> None:
        self.prune()
        for k, name in QUEUE_FILES.items():
            save_queue(name, self.queues[k])

    def prune(self, review_days: int = 90, rejected_days: int = 45) -> None:
        """Keep the queues bounded: old rejected/review entries are re-scored
        if they ever show up again, so dropping them loses nothing."""
        now = datetime.now(timezone.utc)
        for key, days in (("review", review_days), ("rejected", rejected_days)):
            q = self.queues[key]
            for cid in list(q):
                if q[cid].get("manual"):
                    continue
                seen = q[cid].get("seen_at")
                try:
                    age = now - datetime.fromisoformat(seen.replace("Z", "+00:00"))
                except (AttributeError, ValueError):
                    age = timedelta(days=days + 1)
                if age > timedelta(days=days):
                    del q[cid]


# First-run look-back per source when no cursor exists yet.  The NVD window scan
# returns every modified CVE (~3-4k/day, ~5 MB per 1000), so it starts small;
# history is covered by `discover --backfill` instead.
FIRST_RUN_DAYS = {"nvd_window_until": 2, "cvelist_until": 7, "ghsa_until": 7}


def _since(state: dict, key: str, days: int | None) -> datetime:
    now = datetime.now(timezone.utc)
    if days is not None:
        return now - timedelta(days=min(days, MAX_WINDOW_DAYS))
    last = state.get("discovery", {}).get(key)
    if last:
        try:
            dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            return max(dt - timedelta(hours=2), now - timedelta(days=MAX_WINDOW_DAYS))
        except ValueError:
            pass
    return now - timedelta(days=FIRST_RUN_DAYS.get(key, 7))


def discover(days: int | None = None, backfill_terms: bool = False, nvd_window: bool = True) -> dict[str, Any]:
    state = load_state()
    disc = state.setdefault("discovery", {})
    triage = Triage()
    now = datetime.now(timezone.utc)
    report: dict[str, Any] = {"sources": {}}

    # 1. NVD modified-window scan: complete coverage with full data per page.
    if nvd_window:
        since = _since(state, "nvd_window_until", days)
        count = 0
        start = since
        ok = True
        while start < now:
            end = min(start + timedelta(days=MAX_WINDOW_DAYS), now)
            got_any = False
            for facts in nvd.modified_window(_iso(start), _iso(end)):
                got_any = True
                count += 1
                triage.consider(facts, "nvd-window")
                if count % 2000 == 0:
                    log.info("nvd window: %d scanned, accept=%d review=%d", count, triage.stats["accept"], triage.stats["review"])
            if not got_any and (end - start) > timedelta(hours=6):
                ok = False  # most likely an upstream failure; keep the cursor
                log.warning("NVD window %s..%s returned nothing; cursor not advanced", start, end)
                break
            start = end
        report["sources"]["nvd_window"] = {"since": _iso(since), "scanned": count}
        if ok:
            disc["nvd_window_until"] = now_iso()

    # 2. MITRE cvelistV5 delta feed: catches records NVD has not ingested yet.
    since = _since(state, "cvelist_until", days)
    ids = [(cid, kind) for cid, kind, _ in cvelist.changed_since(since, include_updated=False)]
    new_ids = [cid for cid, _ in ids if cid not in triage.known and triage.previously_seen(cid) is None]
    fetched = 0
    log.info("cvelist delta: %d new id(s) since %s, %d not yet seen", len(ids), since.date(), len(new_ids))
    for i, cid in enumerate(new_ids, 1):
        facts = mitre.fetch(cid, cache_ttl=24 * 3600)
        if facts:
            fetched += 1
            triage.consider(facts, "cvelist-delta")
        if i % 100 == 0:
            log.info("cvelist delta: %d/%d fetched, accept=%d review=%d", i, len(new_ids), triage.stats["accept"], triage.stats["review"])
    report["sources"]["cvelist"] = {"since": _iso(since), "new_ids": len(ids), "fetched": fetched}
    disc["cvelist_until"] = now_iso()

    # 3. GHSA: open-source stacks (ROS packages, inference engines, agent frameworks).
    since = _since(state, "ghsa_until", days)
    count = 0
    for facts in ghsa.iter_modified(since.strftime("%Y-%m-%dT%H:%M:%SZ")):
        count += 1
        triage.consider(facts, "ghsa")
    log.info("ghsa: %d advisories scanned since %s", count, since.date())
    report["sources"]["ghsa"] = {"since": _iso(since), "scanned": count}
    disc["ghsa_until"] = now_iso()

    # 4. Optional backfill: NVD keyword searches with no date window.
    if backfill_terms:
        terms = nvd_backfill_keywords()
        per_term: dict[str, int] = {}
        for term in terms:
            n = 0
            for facts in nvd.keyword_search(term):
                n += 1
                triage.consider(facts, f"nvd-keyword:{term}")
            per_term[term] = n
            log.info("backfill %-28s %5d results", term, n)
        report["sources"]["nvd_backfill"] = per_term

    triage.save()
    report["triage"] = triage.stats
    report["queues"] = {k: len(v) for k, v in triage.queues.items()}
    state.setdefault("runs", []).append({"at": now_iso(), "kind": "discover", "report": report})
    state["runs"] = state["runs"][-50:]
    save_state(state)
    log.info("discover done: %s", json.dumps(report["triage"]))
    return report
