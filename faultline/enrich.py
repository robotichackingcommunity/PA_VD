"""Turn queued candidates into full FaultLine records using the Claude Code CLI
(`claude -p`).  Optional: the pipeline succeeds without it; candidates simply
remain queued.  Every generated record is validated and its factual fields are
overwritten from upstream data before it is written."""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .discover import QUEUE_FILES, load_queue, save_queue
from .normalize import normalize
from .records import record_path, save_record
from .refresh import apply_facts, gather_facts
from .sources.facts import pick_advisory
from .schema import validate
from .state import now_iso
from .taxonomy import DOMAINS, LAYERS

log = logging.getLogger("faultline.enrich")
PROMPT_PATH = Path(__file__).with_name("prompts_enrich.md")
CLASSIFICATION_VERSION = "2.0"


def claude_available() -> bool:
    if os.environ.get("FAULTLINE_ENRICH", "1").lower() in ("0", "false", "no"):
        return False
    return shutil.which("claude") is not None


def build_prompt(facts: dict[str, Any], candidate: dict[str, Any]) -> str:
    tpl = PROMPT_PATH.read_text(encoding="utf-8")
    slim = {
        "cve_id": facts["cve_id"],
        "title_from_source": facts.get("title"),
        "description": facts.get("description"),
        "published": facts.get("published"),
        "assigner": facts.get("assigner"),
        "cwe": facts.get("cwes"),
        "cvss": facts.get("cvss"),
        "affected": facts.get("affected"),
        "cpes": (facts.get("cpes") or [])[:10],
        "references": (facts.get("references") or [])[:12],
        "classifier_hint": {
            "matched_rules": [m["rule"] for m in candidate.get("matched", [])],
            "proposed_domains": candidate.get("proposed_domains"),
            "proposed_layers": candidate.get("proposed_layers"),
        },
    }
    return (tpl.replace("{{DOMAINS}}", json.dumps(list(DOMAINS)))
               .replace("{{LAYERS}}", json.dumps(list(LAYERS)))
               .replace("{{FACTS}}", json.dumps(slim, indent=2, ensure_ascii=False)))


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.S)
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except ValueError:
        pass
    m = re.search(r"\{.*\}", text, flags=re.S)
    if m:
        try:
            data = json.loads(m.group(0))
            return data if isinstance(data, dict) else None
        except ValueError:
            return None
    return None


LAST_MODEL_TEXT: dict[str, str] = {}


def call_claude(prompt: str, model: str | None = None, timeout: int = 600) -> dict | None:
    cmd = ["claude", "-p", "--output-format", "json", "--no-session-persistence", "--tools", ""]
    if os.environ.get("ANTHROPIC_API_KEY"):
        cmd.append("--bare")  # CI: API-key auth, skip hooks/keychain
    if model:
        cmd += ["--model", model]
    cmd += ["--system-prompt", "You are a defensive security analyst writing structured enrichment for a public CVE database (like NVD/CISA enrichment). Output only the requested JSON object; never include exploit code or operational attack instructions."]
    cmd += ["--", prompt]  # '--' keeps the variadic --tools from swallowing the prompt
    env = dict(os.environ)
    env.pop("CLAUDECODE", None)  # allow nesting when run from inside a Claude Code session
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.error("claude invocation failed: %s", exc)
        return None
    if proc.returncode != 0:
        log.error("claude exited %s: %s", proc.returncode, (proc.stderr or proc.stdout)[:500])
        return None
    try:
        envelope = json.loads(proc.stdout)
    except ValueError:
        return _extract_json(proc.stdout)
    if isinstance(envelope, dict):
        if isinstance(envelope.get("structured_output"), dict):
            return envelope["structured_output"]
        result = envelope.get("result")
        if isinstance(result, str):
            parsed = _extract_json(result)
            if parsed is None:
                LAST_MODEL_TEXT["text"] = result.strip()[:300]
                log.warning("model returned non-JSON text: %s", result.strip()[:160])
            return parsed
        if isinstance(result, dict):
            return result
    return None


def assemble_record(cve_id: str, generated: dict, facts: dict[str, Any], candidate: dict[str, Any], model: str | None) -> dict:
    """Combine model output with authoritative facts into a record."""
    advisory = pick_advisory(facts.get("references") or [])
    rec: dict[str, Any] = {
        "cve_id": cve_id,
        "type": "vulnerability",
        "title": generated.get("title") or facts.get("title") or cve_id,
        "description": facts.get("description") or generated.get("description") or "",
        "keywords": generated.get("keywords") or [],
        "source": {k: v for k, v in {
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cve_org": f"https://www.cve.org/CVERecord?id={cve_id}",
            "advisory": advisory,
            "github_advisory": facts.get("ghsa_url"),
        }.items() if v},
        "published": facts.get("published"),
        "last_modified": facts.get("last_modified"),
        "vuln_status": facts.get("vuln_status"),
        "reporter": None,
        "cwe": {"id": None, "name": None},
        "cvss": {},
        "taxonomy": generated.get("taxonomy") or {},
        "attack_chain": generated.get("attack_chain") or {},
        "impact": generated.get("impact") or {},
        "mapping_to_pavt": generated.get("mapping_to_pavt") or {},
        "cross_domain_tags": generated.get("cross_domain_tags") or [],
        "security_observations": generated.get("security_observations") or {},
        "mitigation": generated.get("mitigation") or {},
        "enrichment": {
            "method": "claude-auto",
            "model": model or os.environ.get("FAULTLINE_ENRICH_MODEL") or "default",
            "generated_at": now_iso(),
            "classifier_score": candidate.get("score"),
            "classifier_rules": [m["rule"] for m in candidate.get("matched", [])],
            "reviewed": False,
        },
        "pavt_classification_version": CLASSIFICATION_VERSION,
    }
    rec, _ = apply_facts(rec, facts)   # authoritative fields win
    rec, _ = normalize(rec)
    return rec


def enrich_one(cve_id: str, candidate: dict[str, Any], model: str | None, attempts: int = 2) -> tuple[dict | None, list[str]]:
    facts = gather_facts(cve_id)
    if not facts:
        return None, ["no upstream facts"]
    prompt = build_prompt(facts, candidate)
    errors: list[str] = []
    for attempt in range(1, attempts + 1):
        p = prompt if attempt == 1 else prompt + "\n\nPrevious attempt was rejected by the validator: " + "; ".join(errors[:5]) + "\nFix those issues."
        LAST_MODEL_TEXT.clear()
        generated = call_claude(p, model)
        if not generated:
            errors = ["model returned no JSON" + (f": {LAST_MODEL_TEXT['text']}" if LAST_MODEL_TEXT.get("text") else "")]
            continue
        rec = assemble_record(cve_id, generated, facts, candidate, model)
        errors, _ = validate(rec)
        if not errors:
            return rec, []
        log.warning("%s: attempt %d rejected: %s", cve_id, attempt, "; ".join(errors[:3]))
    return None, errors


def enrich_pending(max_records: int = 20, model: str | None = None, dry_run: bool = False, ids: list[str] | None = None) -> dict[str, Any]:
    pending = load_queue(QUEUE_FILES["accept"])
    stats = {"pending": len(pending), "enriched": 0, "failed": 0, "skipped_no_claude": 0}
    targets = [c for c in pending if not ids or c in ids]
    if not targets:
        return stats
    if dry_run:
        c = targets[0]
        facts = gather_facts(c)
        print(build_prompt(facts or {"cve_id": c}, pending[c]))
        return stats
    if not claude_available():
        stats["skipped_no_claude"] = len(targets)
        log.warning("claude CLI not available (or FAULTLINE_ENRICH=0); %d candidate(s) stay queued", len(targets))
        return stats
    failed = load_queue("failed.json")
    for cve_id in targets[:max_records]:
        if record_path(cve_id).exists():
            pending.pop(cve_id, None)
            continue
        rec, errors = enrich_one(cve_id, pending[cve_id], model)
        if rec:
            save_record(rec)
            pending.pop(cve_id, None)
            failed.pop(cve_id, None)
            stats["enriched"] += 1
            log.info("%s: enriched -> %s", cve_id, rec["title"][:80])
        else:
            stats["failed"] += 1
            entry = dict(pending[cve_id])
            entry["last_error"] = errors
            entry["failures"] = entry.get("failures", 0) + 1
            pending[cve_id] = entry
            failed[cve_id] = entry
            log.error("%s: enrichment failed: %s", cve_id, "; ".join(errors[:3]))
        save_queue(QUEUE_FILES["accept"], pending)
        save_queue("failed.json", failed)
    stats["pending"] = len(pending)
    return stats
