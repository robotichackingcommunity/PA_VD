"""FaultLine command-line interface:  python3 -m faultline <command> [options]"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from .http import setup_logging

log = logging.getLogger("faultline")


def cmd_normalize(args) -> int:
    from .normalize_files import normalize_tree
    stats = normalize_tree(dry_run=args.dry_run)
    print(json.dumps(stats, indent=2))
    return 0


def cmd_validate(args) -> int:
    from .records import iter_record_files, load_json
    from .schema import validate
    n_err = n_warn = 0
    for p in iter_record_files():
        try:
            rec = load_json(p)
        except ValueError as exc:
            print(f"ERROR {p.name}: invalid JSON ({exc})")
            n_err += 1
            continue
        if p.name != f"{rec.get('cve_id')}.pavd.json":
            print(f"ERROR {p.name}: filename does not match cve_id {rec.get('cve_id')!r}")
            n_err += 1
        errors, warnings = validate(rec)
        for e in errors:
            print(f"ERROR {p.name}: {e}")
        if args.warnings:
            for w in warnings:
                print(f"WARN  {p.name}: {w}")
        n_err += len(errors)
        n_warn += len(warnings)
    print(f"validate: {n_err} error(s), {n_warn} warning(s)")
    return 2 if n_err else 0


def cmd_refresh(args) -> int:
    from .refresh import refresh_all
    only = set(args.cve) if args.cve else None
    stats = refresh_all(max_age_days=args.max_age_days, limit=args.limit, only=only, force=args.force)
    print(json.dumps(stats))
    return 0


def cmd_discover(args) -> int:
    from .discover import discover
    stats = discover(days=args.days, backfill_terms=args.backfill, nvd_window=not args.no_nvd_window)
    print(json.dumps(stats, indent=2))
    return 0


def cmd_rescore(args) -> int:
    from .discover import rescore
    print(json.dumps(rescore(), indent=2))
    return 0


def cmd_enrich(args) -> int:
    from .enrich import enrich_pending
    stats = enrich_pending(max_records=args.max, model=args.model, dry_run=args.dry_run, ids=args.cve, jobs=args.jobs)
    print(json.dumps(stats, indent=2))
    return 0


def cmd_index(args) -> int:
    from .index import build_all
    stats = build_all()
    print(json.dumps(stats, indent=2))
    return 0


def cmd_sync(args) -> int:
    from .discover import discover
    from .enrich import enrich_pending
    from .index import build_all
    from .normalize_files import normalize_tree
    from .refresh import refresh_all

    summary: dict = {}
    summary["normalize"] = normalize_tree()
    rc = cmd_validate(argparse.Namespace(warnings=False))
    if rc:
        log.error("validation failed before refresh; aborting")
        return rc
    if not args.skip_refresh:
        summary["refresh"] = refresh_all(max_age_days=args.max_age_days, limit=args.refresh_limit)
    if not args.skip_discover:
        summary["discover"] = discover(days=args.days)
    if not args.skip_enrich:
        summary["enrich"] = enrich_pending(max_records=args.max_enrich, model=args.model, jobs=args.jobs)
    summary["normalize_after"] = normalize_tree()
    rc = cmd_validate(argparse.Namespace(warnings=False))
    if rc:
        log.error("validation failed after sync; fix records before committing")
        return rc
    summary["index"] = build_all()
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="faultline", description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("normalize", help="rewrite records into canonical shape")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_normalize)

    p = sub.add_parser("validate", help="schema + vocabulary check (exit 2 on errors)")
    p.add_argument("--warnings", action="store_true", help="also print warnings")
    p.set_defaults(fn=cmd_validate)

    p = sub.add_parser("refresh", help="update authoritative fields from MITRE/NVD/GHSA")
    p.add_argument("--max-age-days", type=int, default=7)
    p.add_argument("--limit", type=int, default=None, help="max records to fetch this run")
    p.add_argument("--force", action="store_true", help="ignore refreshed_at timestamps")
    p.add_argument("--cve", nargs="*", help="only these CVE ids")
    p.set_defaults(fn=cmd_refresh)

    p = sub.add_parser("discover", help="find new candidate CVEs and queue them")
    p.add_argument("--days", type=int, default=None, help="look-back window (default: since last run, max 120)")
    p.add_argument("--backfill", action="store_true", help="also run watchlist keyword searches without a date window")
    p.add_argument("--no-nvd-window", action="store_true", help="skip the full NVD modified-window scan")
    p.set_defaults(fn=cmd_discover)

    p = sub.add_parser("rescore", help="re-classify queued candidates after editing config/watchlist.json (no network)")
    p.set_defaults(fn=cmd_rescore)

    p = sub.add_parser("enrich", help="generate full records for queued candidates with Claude")
    p.add_argument("--max", type=int, default=20)
    p.add_argument("--model", default=None)
    p.add_argument("--jobs", type=int, default=1, help="parallel enrichment workers")
    p.add_argument("--dry-run", action="store_true", help="print the prompt for the first candidate and exit")
    p.add_argument("--cve", nargs="*", help="only these CVE ids")
    p.set_defaults(fn=cmd_enrich)

    p = sub.add_parser("index", help="rebuild index.json, stats.json and README stats")
    p.set_defaults(fn=cmd_index)

    p = sub.add_parser("sync", help="normalize → validate → refresh → discover → enrich → index")
    p.add_argument("--max-age-days", type=int, default=7)
    p.add_argument("--refresh-limit", type=int, default=None)
    p.add_argument("--days", type=int, default=None)
    p.add_argument("--max-enrich", type=int, default=20)
    p.add_argument("--model", default=None)
    p.add_argument("--jobs", type=int, default=1, help="parallel enrichment workers")
    p.add_argument("--skip-refresh", action="store_true")
    p.add_argument("--skip-discover", action="store_true")
    p.add_argument("--skip-enrich", action="store_true")
    p.set_defaults(fn=cmd_sync)

    args = ap.parse_args(argv)
    setup_logging(args.verbose)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
