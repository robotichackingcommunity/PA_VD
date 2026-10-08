"""Load / save FaultLine records with one canonical on-disk format."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterator

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
RECORD_SUFFIX = ".pavd.json"
LEGACY_SUFFIXES = (".pavt.json",)


def repo_root() -> Path:
    return Path(os.environ.get("FAULTLINE_ROOT", Path(__file__).resolve().parent.parent))


def records_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "CVE-json"


def record_path(cve_id: str, root: Path | None = None) -> Path:
    return records_dir(root) / f"{cve_id}{RECORD_SUFFIX}"


def iter_record_files(root: Path | None = None) -> Iterator[Path]:
    d = records_dir(root)
    if not d.exists():
        return iter(())
    return iter(sorted(p for p in d.iterdir() if p.suffix == ".json" and p.is_file()))


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def dumps(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, indent=2) + "\n"


def save_record(record: dict, root: Path | None = None) -> Path:
    path = record_path(record["cve_id"], root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(dumps(record), encoding="utf-8")
    os.replace(tmp, path)
    return path


def load_all(root: Path | None = None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in iter_record_files(root):
        rec = load_json(p)
        out[rec.get("cve_id") or p.name] = rec
    return out


def cve_id_from_filename(path: Path) -> str:
    return path.name.split(".")[0]
