"""Apply normalize() to the whole CVE-json tree, including file-level hygiene:
legacy .pavt.json names, duplicates, filename/cve_id mismatches."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from .normalize import normalize
from .records import RECORD_SUFFIX, iter_record_files, load_json, record_path, records_dir, save_record

log = logging.getLogger("faultline.normalize")


def _richness(rec: dict) -> int:
    return len(json.dumps(rec, ensure_ascii=False))


def normalize_tree(dry_run: bool = False) -> dict:
    stats = {"files": 0, "rewritten": 0, "renamed": 0, "duplicates_removed": 0, "errors": 0, "changes": {}}
    by_id: dict[str, list[tuple[Path, dict]]] = {}
    for p in iter_record_files():
        stats["files"] += 1
        try:
            rec = load_json(p)
        except ValueError as exc:
            log.error("%s: invalid JSON (%s)", p.name, exc)
            stats["errors"] += 1
            continue
        cve_id = rec.get("cve_id") or p.name.split(".")[0]
        rec["cve_id"] = cve_id
        by_id.setdefault(cve_id, []).append((p, rec))

    for cve_id, entries in by_id.items():
        # keep the richest copy when duplicates exist
        entries.sort(key=lambda e: _richness(e[1]), reverse=True)
        keep_path, rec = entries[0]
        for dup_path, _ in entries[1:]:
            log.warning("%s: removing duplicate %s (keeping %s)", cve_id, dup_path.name, keep_path.name)
            if not dry_run:
                dup_path.unlink()
            stats["duplicates_removed"] += 1
        new, changes = normalize(rec)
        target = record_path(cve_id)
        if keep_path != target:
            log.info("%s: renaming %s -> %s", cve_id, keep_path.name, target.name)
            if not dry_run:
                keep_path.unlink()
            stats["renamed"] += 1
            changes = changes + ["renamed"]
        for c in changes:
            key = c.split(":")[0].split(" ")[0]
            stats["changes"][key] = stats["changes"].get(key, 0) + 1
        canonical_text = json.dumps(new, ensure_ascii=False, indent=2) + "\n"
        current_text = keep_path.read_text(encoding="utf-8") if keep_path.exists() else ""
        if changes or canonical_text != current_text or keep_path != target:
            stats["rewritten"] += 1
            if not dry_run:
                save_record(new)
    log.info("normalize done: %s", {k: v for k, v in stats.items() if k != "changes"})
    return stats
