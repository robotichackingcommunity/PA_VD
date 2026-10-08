"""MITRE cvelistV5 delta feed — complete list of new / updated CVE IDs."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

from ..http import get_json

DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
DELTA = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def changed_since(since: datetime, include_updated: bool = True) -> Iterator[tuple[str, str, datetime]]:
    """Yield (cve_id, kind, updated_at) for entries newer than `since`.

    kind is 'new' or 'updated'.  deltaLog.json covers roughly the last 30 days
    of hourly deltas; for older gaps the caller should fall back to NVD.
    """
    log = get_json(DELTA_LOG, timeout=300)
    if not isinstance(log, list):
        single = get_json(DELTA, timeout=60)
        log = [single] if isinstance(single, dict) else []
    seen: set[str] = set()
    for entry in log:
        ts = _parse_ts(entry.get("fetchTime", ""))
        if ts is None or ts <= since:
            continue
        kinds = [("new", entry.get("new") or [])]
        if include_updated:
            kinds.append(("updated", entry.get("updated") or []))
        for kind, items in kinds:
            for it in items:
                cid = it.get("cveId")
                if cid and cid not in seen:
                    seen.add(cid)
                    yield cid, kind, _parse_ts(it.get("dateUpdated", "")) or ts


def coverage_start() -> datetime | None:
    """Oldest fetchTime in the delta log (so callers know its reach)."""
    log = get_json(DELTA_LOG, timeout=300)
    if not isinstance(log, list) or not log:
        return None
    stamps = [_parse_ts(e.get("fetchTime", "")) for e in log]
    stamps = [s for s in stamps if s]
    return min(stamps) if stamps else None
