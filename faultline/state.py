"""Pipeline state (data/state.json): per-record provenance + discovery cursors."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .records import repo_root


def state_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / "data" / "state.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_state(root: Path | None = None) -> dict:
    p = state_path(root)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            pass
    return {"version": 1, "records": {}, "discovery": {}, "runs": []}


def save_state(state: dict, root: Path | None = None) -> None:
    p = state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def update_state(mutate, root: Path | None = None) -> dict:
    """Load the freshest state from disk, apply `mutate(state)`, save.

    Several pipeline steps (refresh, discover) may run concurrently; each one
    must only write its own keys on top of what is currently on disk instead of
    saving a stale in-memory copy.
    """
    state = load_state(root)
    mutate(state)
    save_state(state, root)
    return state
