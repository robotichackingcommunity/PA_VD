"""Stand-alone check of one or more published records against the record schema.

Used two ways, with the same code:
  * by the pipeline's tests, against the records the exporter writes;
  * copied into the public repository as scripts/validate_records.py, where a contributor and the
    pull-request workflow run it on CVE-json/*.pavd.json.

Only the Python standard library and `jsonschema` are needed. Findings are plain strings, one
per problem; an empty list means the record is acceptable to review.
"""
import json
import re
from pathlib import Path
from datetime import date, timedelta
from typing import Any, Dict, Iterable, List, Optional

NAME_RE = re.compile(r'^(CVE-\d{4}-\d{4,})\.pavd\.json$')
# Credentials that must never be published, by the shape each issuer gives them. The list is broad on
# purpose: it covers the common AI, cloud and code-hosting services rather than the ones the project
# uses, so the public copy of this file says nothing about the project's own stack. A shape is only
# listed when its prefix or length makes it unlikely in ordinary CVE text (a URL slug such as
# "sk-hynix-..." must not match).
SECRET_PATTERNS = [
    # AI services
    ('an AI service API key', re.compile(r'\bsk-ant-[A-Za-z0-9_-]{10,}')),                      # Anthropic
    ('an AI service API key', re.compile(r'\bsk-[A-Za-z0-9_-]*[A-Za-z0-9]{20}')),               # OpenAI, DeepSeek, OpenRouter, ...
    ('an AI service API key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}')),                          # Google (Gemini, GCP)
    ('an AI service API key', re.compile(r'\bhf_[A-Za-z0-9]{30,}')),                            # Hugging Face
    ('an AI service API key', re.compile(r'\bgsk_[A-Za-z0-9]{40,}')),                           # Groq
    ('an AI service API key', re.compile(r'\br8_[A-Za-z0-9]{30,}')),                            # Replicate
    ('an AI service API key', re.compile(r'\bxai-[A-Za-z0-9]{40,}')),                           # xAI
    ('an AI service API key', re.compile(r'\bpplx-[A-Za-z0-9]{40,}')),                          # Perplexity
    ('an AI service API key', re.compile(r'\bnvapi-[A-Za-z0-9_-]{40,}')),                       # NVIDIA
    ('an AI service API key', re.compile(r'\blsv2_(?:pt|sk)_[0-9a-f]{32}')),                    # LangSmith
    # Cloud services
    ('a cloud access key', re.compile(r'\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b')),           # AWS access key id
    ('a cloud access key', re.compile(r'(?i)aws_?secret_?access_?key\W{0,5}[A-Za-z0-9/+]{40}')),  # AWS secret key
    ('a cloud access key', re.compile(r'\bGOCSPX-[A-Za-z0-9_-]{28}')),                          # Google OAuth client secret
    ('a cloud access key', re.compile(r'AccountKey=[A-Za-z0-9+/]{86}==')),                      # Azure storage
    ('a cloud access key', re.compile(r'\b[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}')),     # Azure AD client secret
    ('a cloud access key', re.compile(r'\bLTAI[A-Za-z0-9]{12,20}\b')),                          # Alibaba Cloud
    ('a cloud access key', re.compile(r'\bAKID[A-Za-z0-9]{32}\b')),                             # Tencent Cloud
    ('a cloud access key', re.compile(r'\bdo[por]_v1_[a-f0-9]{64}')),                           # DigitalOcean
    # Code hosting, package registries, chat
    ('a service token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}')),                          # GitHub
    ('a service token', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{60,}')),                         # GitHub fine-grained
    ('a service token', re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}')),                             # GitLab
    ('a service token', re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{10,}')),                        # Slack
    ('a service token', re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')),                                # npm
    ('a service token', re.compile(r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}')),               # PyPI
    ('a service token', re.compile(r'\b[rs]k_live_[A-Za-z0-9]{20,}')),                          # Stripe
    ('a webhook URL', re.compile(r'\.webhook\.office\.com/webhookb2/')),                        # Teams (Office 365 connector)
    ('a webhook URL', re.compile(r'\.(?:logic\.azure|api\.powerplatform)\.com/[^\s"]*sig=')),   # Teams Workflows / Power Automate
    ('a webhook URL', re.compile(r'hooks\.slack\.com/(?:services|workflows|triggers)/')),       # Slack
    ('a webhook URL', re.compile(r'discord(?:app)?\.com/api/webhooks/\d+/')),                   # Discord
    # Private keys
    ('a private key block', re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----')),  # PEM, OpenSSH, PGP
    ('a private key block', re.compile(r'PuTTY-User-Key-File-\d')),
]
# Text that must never be published inside a sentence field: markup and active content. A
# `javascript:` URL counts when it is a link target (markdown `](`, an autolink `<`, an attribute `=`)
# or has code right after it; prose that only names the scheme ("blocks javascript: and data: links",
# common in XSS advisories) is accepted.
_MARKUP = re.compile(r'<\s*/?\s*(?:script|iframe|object|embed|svg|img|style|link|meta)\b'
                     r'|(?:\]\(|<|=)\s*["\']?\s*javascript:|javascript:(?=[^\s,.;:)\]\'"])'
                     r'|\bon[a-z]+\s*=', re.I)
_TEXT_KEYS = {'title', 'classification_reason', 'rationale', 'text', 'note', 'fix_description', 'workaround',
              'component'}   # component names are free text while the vocabulary is being tuned


def _texts(node: Any, key: str = '') -> Iterable[str]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _texts(v, k)
    elif isinstance(node, list):
        for v in node:
            yield from _texts(v, key)
    elif isinstance(node, str) and key in _TEXT_KEYS:
        yield node


def _day(value: Any) -> Optional[date]:
    """The date of a YYYY-MM-DD string or of an ISO timestamp (its first ten characters), else None."""
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def date_problem(value: Any, today: str, pr_created: str = None) -> Optional[str]:
    """Why contributed_by.date is not acceptable, or None.

    The date must lie between the day the pull request was opened (`pr_created`, defaulting to
    `today`) and `today`, both in UTC. A maintainer may approve a fork's workflow days after the
    pull request was opened, so the check cannot require today's date. One day of slack on each
    side lets a contributor write the date of their own time zone (UTC-12 to UTC+14).
    """
    end = _day(today)
    start = _day(pr_created) or end
    if end is None:
        return None
    start = min(start, end)
    day = _day(value) if isinstance(value, str) and len(value) == 10 else None
    if day is not None and start - timedelta(days=1) <= day <= end + timedelta(days=1):
        return None
    opened = f"the pull request was opened {start.isoformat()} and today is {end.isoformat()} (UTC)"
    return f"contributed_by.date {value!r} must be the date the pull request was opened or later, up to today: {opened}"


def validate_text(name: str, text: str, schema: Dict[str, Any],
                  pr_author: str = None, pr_number: int = None, today: str = None,
                  pr_created: str = None) -> List[str]:
    """Problems with one record file, given its file name and raw text.

    pr_author / pr_number are given by the pull-request workflow. When present, contributed_by
    must be a community record naming exactly that account and that pull request. When `today`
    is given, its date must lie between `pr_created` (the day the pull request was opened) and
    `today` (see date_problem). A record may not claim to be a VicOne record in a pull request.
    """
    import jsonschema

    problems: List[str] = []
    match = NAME_RE.match(name)
    if not match:
        problems.append(f'file name {name!r} must be CVE-YYYY-N.pavd.json')
    try:
        record = json.loads(text)
    except ValueError as exc:
        return problems + [f'not valid JSON: {exc}']
    if not isinstance(record, dict):
        return problems + ['the top level must be a JSON object']

    validator = jsonschema.Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path)):
        where = '/'.join(str(p) for p in error.absolute_path) or '(top level)'
        problems.append(f'{where}: {error.message[:200]}')

    cve_id = record.get('cve_id')
    if match and cve_id != match.group(1):
        problems.append(f'cve_id {cve_id!r} does not match the file name {match.group(1)!r}')
    mitre_id = ((record.get('mitre_data') or {}).get('cveMetadata') or {}).get('cveId')
    if mitre_id != cve_id:
        problems.append(f'mitre_data.cveMetadata.cveId {mitre_id!r} does not match cve_id {cve_id!r}')
    if 'meta' in record:
        problems.append("'meta' is internal and must not be published")

    if pr_author is not None or pr_number is not None:
        by = record.get('contributed_by')
        if not isinstance(by, dict) or by.get('source') != 'community':
            problems.append("contributed_by.source must be 'community' in a pull request")
        else:
            if pr_author is not None and str(by.get('github', '')).lower() != str(pr_author).lower():
                problems.append(f"contributed_by.github {by.get('github')!r} is not the pull request author {pr_author!r}")
            if pr_number is not None and by.get('pull_request') != int(pr_number):
                problems.append(f"contributed_by.pull_request {by.get('pull_request')!r} is not this pull request ({pr_number})")
            if today is not None:
                wrong_date = date_problem(by.get('date'), today, pr_created)
                if wrong_date:
                    problems.append(wrong_date)

    for label in dict.fromkeys(label for label, pattern in SECRET_PATTERNS if pattern.search(text)):
        problems.append(f'contains {label}')
    for sentence in _texts(record.get('judgments')):
        if _MARKUP.search(sentence):
            problems.append(f'markup or active content in text: {sentence[:80]!r}')
            break
    return problems


def validate_folder(folder: Path, schema: Dict[str, Any]) -> Dict[str, List[str]]:
    """{file name: problems} for every record file under folder/CVE-json that has problems."""
    out: Dict[str, List[str]] = {}
    records = Path(folder) / 'CVE-json'
    for path in sorted(records.glob('*.json')) if records.is_dir() else []:
        problems = validate_text(path.name, path.read_text(encoding='utf-8'), schema)
        if problems:
            out[path.name] = problems
    return out


def main(argv: List[str] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description='Validate Physical AI record files against the schema.')
    parser.add_argument('files', nargs='+', type=Path, help='record files (CVE-json/CVE-YYYY-N.pavd.json)')
    parser.add_argument('--pr-author', help='GitHub login of the pull request author (used by the workflow)')
    parser.add_argument('--pr-number', type=int, help='pull request number (used by the workflow)')
    parser.add_argument('--pr-created', help="when the pull request was opened, YYYY-MM-DD or an ISO timestamp (the workflow passes created_at); the earliest accepted contributed_by.date")
    parser.add_argument('--today', help='the latest accepted contributed_by.date, YYYY-MM-DD (defaults to the current UTC date when --pr-author is used)')
    parser.add_argument('--schema', type=Path, default=Path(__file__).resolve().parent.parent / 'schema' / 'pavd-record.schema.json')
    args = parser.parse_args(argv)
    schema = json.loads(args.schema.read_text(encoding='utf-8'))
    today = args.today
    if today is None and (args.pr_author or args.pr_number):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    failed = 0
    for path in args.files:
        problems = validate_text(path.name, path.read_text(encoding='utf-8'), schema,
                                 pr_author=args.pr_author, pr_number=args.pr_number, today=today,
                                 pr_created=args.pr_created)
        for problem in problems:
            print(f'{path}: {problem}')
        failed += bool(problems)
    print(f'{len(args.files) - failed} of {len(args.files)} record(s) valid')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
