# FaultLine data pipeline redesign (2026-10-09)

## Problem

Audit of the 307 records in `CVE-json/` on 2026-10-09 found:

1. **Classification field mix-ups.** Five records put a *technical layer* into
   `taxonomy.physical_ai_domain` (`AI/ML Runtime / Inference`,
   `Distribution / Supply Chain`, `Mobile Companion App`). The Explorer builds
   its domain filter from that field, which is why it shows
   "AI/ML Runtime / Inference (1)". The real count for that layer is 39
   (plus 2 records that spell it differently).
2. **Two shapes for `technical_layer`**: plain strings (majority) and
   `{layer, technologies}` objects. Any count that keys on the raw value
   splits one layer into many buckets (that is how the README reached "7").
3. **Free-form layer names** outside the documented vocabulary
   (`Safety Systems`, `Flight Controller / Firmware`, `AI / ML Inference
   Engine`, 12 variants in total).
4. **Vendor name drift**: 5 spellings of PX4, 3 of MOOS, 2 of ECOVACS,
   3 of Open Robotics.
5. **Hygiene**: one duplicate CVE (`CVE-2026-26741` as both `.pavd` and
   `.pavt`), three `.pavt.json` filenames, `vuln_status` strings such as
   "NVD data unavailable (HTTP 429 during fetch)", one record with no
   `published` date.
6. **No automation.** Records were produced one by one with an LLM command;
   nothing refreshes CVSS/status drift and nothing discovers new CVEs.

## Goals

- Correct, controlled taxonomy with the counts derivable by one function.
- Records stay current with NVD / MITRE / GHSA automatically.
- New Physical-AI-relevant CVEs are discovered, triaged and (optionally)
  enriched automatically.
- One command (`./update.sh`) does everything and pushes; a scheduled GitHub
  Actions workflow runs the same command nightly.
- Stdlib-only Python 3.10+, no pip dependencies, so it runs anywhere.
- Never commit invalid data: schema validation gates every write.

## Non-goals

- Rewriting existing human/LLM-written enrichment text (attack chains etc.).
- A new front-end. The Explorer gets a technical-layer filter and counts only.

## Controlled vocabulary (`faultline/taxonomy.py`)

**Domains (10, unchanged):** Humanoid Robot · Industrial Robot · Mobile Robot
& AMR · Drone & Aerial Robotics · Service & Companion Robot · Autonomous
Vehicle AI · Embodied AI Agent · Robot Operating Systems & Middleware ·
Physical AI Infrastructure · Cross-Domain Components.

**Technical layers (9, as documented in README):** Hardware / Firmware ·
Robot OS / Development Tools · Middleware / Communication Layer · Network /
Connectivity · Mobile Companion App · AI/ML Runtime / Inference · AI/ML
Training Pipeline · Physical AI Infrastructure / MLOps · Distribution /
Supply Chain.

Alias tables map every observed variant onto the vocabulary; an unmapped
value is a validation error, not a silent new bucket. Vendor aliases map the
drifted spellings onto one canonical vendor name.

Canonical record shape after normalization:

```json
"technical_layer": [{"layer": "<vocab>", "technologies": ["..."]}]
"physical_ai_domain": [{"domain": "<vocab>", "confidence": 0.0-1.0, "rationale": "..."}]
"vendor": ["<canonical>"]
```

Mis-filed domains are moved: the layer goes to `technical_layer` (if not
already there) and the domain is replaced by the sibling-consistent domain
(`Distribution / Supply Chain` → `Physical AI Infrastructure`,
`AI/ML Runtime / Inference` → `Physical AI Infrastructure`,
`Mobile Companion App` on the Unitree Go2 app → `Mobile Robot & AMR`, the
domain its sibling Go2 records use).

## Data sources (`faultline/sources/`)

| Source | Used for | Limits / auth |
|---|---|---|
| MITRE CVE Services `https://cveawg.mitre.org/api/cve/{id}` | CNA description, CNA CVSS, CWE, references, affected products, dates; primary refresh source | none documented; we still cap at 4 req/s with retry |
| MITRE cvelistV5 delta feed (`cves/deltaLog.json` on GitHub) | discovery of new/updated CVE IDs (complete, hourly) | raw.githubusercontent, no auth |
| NVD 2.0 API | `vulnStatus`, NVD CVSS (3.1 / 4.0), CPE configurations; keyword discovery as a second net | 5 req/30 s, or 50 req/30 s with `NVD_API_KEY` |
| GitHub Security Advisories API | GHSA id, CVSS/CWE when NVD has none, ecosystem data; discovery for open-source stacks | 60/h anon, 5000/h with `GITHUB_TOKEN` |

All fetchers share one HTTP helper: timeouts, exponential backoff on
429/5xx, per-host token-bucket rate limiting, on-disk cache in
`data/cache/` (ignored by git) keyed by URL, and they return `None` on
final failure instead of raising, so one bad upstream never aborts a run or
writes placeholder strings into records.

## Pipeline (`faultline/cli.py`, subcommands)

1. `normalize` — rewrite every record into canonical shape (aliases,
   object-form layers, de-dupe, `.pavt` → `.pavd`), idempotent.
2. `validate` — schema + vocabulary check; non-zero exit on any error.
3. `refresh` — for each record older than `--max-age-days` (default 7):
   pull MITRE + NVD (+ GHSA if a GHSA link exists) and update only the
   *authoritative* fields: `description` (only if the record has none),
   `published`, `last_modified`, `vuln_status`, `cvss` (score/severity/
   vector/source, keep `cvss_4_0_estimated` and `ssvc` untouched), `cwe`,
   `source.nvd/cve_org/github_advisory`, `affected_configurations` (append
   CPE-derived rows when missing). Per-record provenance is written to
   `data/state.json`, never into the record. `--limit N` bounds the run.
4. `discover` — since `state.last_discovery`:
   a. cvelistV5 delta → candidate IDs → fetch MITRE record → rule classifier.
   b. NVD `keywordSearch` + `lastModStartDate` per watchlist term.
   c. GHSA `modified>=` page scan, keyword filter.
   Rule classifier (`faultline/classify.py`) scores each candidate against
   `config/watchlist.json` (vendor/product/keyword → domain, layer, weight).
   Score ≥ `accept` → `data/queue/pending.json`; between `review` and
   `accept` → `data/queue/review.json`; below → `data/queue/rejected.json`
   (kept so the same ID is not re-scored every night). Every decision has
   the matched terms recorded so a human can audit it.
5. `enrich` — optional. For each pending candidate, call `claude -p` with a
   strict prompt (vocabulary + JSON schema + the MITRE/NVD facts) and validate
   the output; invalid output is retried once then left in the queue. Caps:
   `--max N` per run (default 20). Skipped cleanly when `claude` is not on
   PATH or `FAULTLINE_ENRICH=0`; candidates then wait in the queue and the run
   still succeeds. Facts (ids, dates, CVSS, CWE) in the generated record are
   overwritten from the fetched data, so the model cannot hallucinate them.
6. `index` — write `index.json` (adds `layers`, `cwe`, `last_modified`),
   `stats.json` (counts by domain/layer/severity/vendor/year) and rewrite the
   README coverage block between `<!-- stats:start -->` / `<!-- stats:end -->`.
7. `sync` — 1→6 in order, stop on validation failure.

`update.sh` = `python3 -m faultline sync "$@"` then `git add -A`, commit with
a generated summary, and `git push` unless `--no-push`. GitHub Actions
(`.github/workflows/update.yml`) runs `./update.sh` nightly with
`NVD_API_KEY`, `GITHUB_TOKEN` and optional `ANTHROPIC_API_KEY` secrets.

## Explorer changes

- `index.html`: add a "Technical Layer" filter group, show `(n)` counts next
  to every filter option, add a stats strip under the header.

## Testing

`tests/` with `unittest` (stdlib): taxonomy aliasing, normalization of all
observed shapes, validator rejects bad vocab, classifier on known positive /
negative descriptions, index/stats counts on fixture records, source parsers
on recorded JSON fixtures (no network in tests).

## Error handling principles

- Upstream failure → skip + log + non-fatal; data unchanged.
- Validation failure → run aborts before commit; exit code 2.
- Push failure → exit code 3 with the git error; local commit stays.
- All logs to stderr with a one-line summary at the end (counts refreshed /
  discovered / enriched / errors) so a CI log tells the story at a glance.
