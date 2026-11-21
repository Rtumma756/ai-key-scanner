# aiscan — AI API leaked-key scanner

**Provider-agnostic** (13+ AI providers, registry-based — adding a
provider is one entry) and **deployment-agnostic** (scan a local repo,
git history, public internet sources, or plug it into a business for a
remediation report). One engine, every mode.

## Try it in 30 seconds — zero setup, zero credentials

```bash
git clone https://github.com/<you>/aiscan.git
cd aiscan
python3 aiscan.py scan internet --demo   # bundled fake leaks — no network, no token
python3 aiscan.py selftest               # precision/recall scorecard on fixtures
```

No install, no token, no network for the demo. Python 3.10+, standard
library only, no external dependencies.

## Installation

Requires Python 3.11+. Standard library only — no third-party
dependencies, so the install is seconds and there is nothing to audit
beyond the scanner itself.

```bash
git clone https://github.com/<you>/aiscan.git
cd aiscan
pip install -e .        # editable install from the repo
aiscan --help           # installed console command
aiscan selftest         # precision/recall scorecard on fixtures
```

The encrypted vault is the only feature that needs anything beyond
the standard library (`cryptography`, for AES-256-GCM). It is an
optional extra — scanning, reporting, the CI action and the
pre-commit hook all run stdlib-only:

```bash
pip install -e ".[vault]"   # only if you use `aiscan vault ...`
```

A full `aiscan selftest` exercises the vault scorecard, so it needs
the `[vault]` extra installed; without it the vault checks report the
missing package instead of passing.

Without installing, `python3 aiscan.py ...` works exactly the same
from the repo root.

## Try it on your own code

```bash
# Scan a directory tree (your own code)
python3 aiscan.py scan local ~/myrepo

# ...and its git history (deleting a file does not delete the secret)
python3 aiscan.py scan local ~/myrepo --git-history

# Markdown remediation report
python3 aiscan.py scan local ~/myrepo --format md --output report.md
```

## CI — GitHub Action and pre-commit hook

KeySentry is an **add-on layer, not a replacement** for your existing
secret scanners (gitleaks, TruffleHog, GitHub secret scanning, …). It
catches what slips past them — AI-specific API keys from 13 providers
— including leaks outside the pipeline. Reports are **masked-only**
(prefix4-masked values + SHA-256 fingerprints); no raw key is ever
logged or uploaded, and verification stays off, so no found key is
ever sent to a provider API.

### GitHub Action

`action.yml` at the repo root is a composite action: it installs the
scanner, scans the checked-out repo, writes a masked-only JSON report
(`keysentry-report.json`), uploads it as the `keysentry-report`
artifact, and fails the step only when `fail-on` is met.

```yaml
# .github/workflows/keysentry-scan.yml
jobs:
  keysentry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history, so deleted secrets are checked too
      - uses: <owner>/aiscan@v1
        with:
          paths: "."
          fail-on: "high"   # critical | high | medium | low | none
```

Inputs: `paths` (default `"."`), `fail-on` (default `"high"`),
`github-token` (optional; reserved for a future code-search mode —
the local scan does not call the GitHub API), `config` (optional;
reserved, not yet supported by the CLI). Outputs: `findings-file`
(path to the masked JSON report) and `finding-count`.

A working example lives at `.github/workflows/keysentry-scan.yml` —
it uses the local action (`uses: ./`) so this repo dogfoods it;
customers replace `./` with the published action ref.

### Pre-commit hook

Scan staged files before they are committed:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/<you>/aiscan
    rev: v0.1.0
    hooks:
      - id: keysentry-scan
        args: [--fail-on, high]   # or: critical | medium | low | none
```

The hook (`.pre-commit-hooks.yaml`, entry `scripts/pre-commit-hook`)
uses an installed `aiscan` on PATH when available and falls back to
the hook repo's own `aiscan.py`. Same behavior as the Action: masked
output only, fails only when the threshold is met.

## Modes

| Mode | Command | What it scans |
|---|---|---|
| Business | `scan local <path> [--git-history]` | Your own repos/code |
| Internet | `scan internet --query <pattern>` | Live GitHub code search (your own key fingerprint/prefix) |
| Internet | `scan internet --preset mcp\|notebook` | `.mcp.json` files / `.ipynb` notebooks on GitHub |
| Internet | `scan internet --demo` | Bundled fake dataset — no token, no network |
| Trial | `scan dockerhub\|gists\|npm\|pypi\|pastebin\|stackoverflow\|commoncrawl` | Public images, gists, packages, pastes, questions, web archive |

Every scan prints a metrics scorecard (items scanned, candidates,
findings by provider) — see [Metrics](#metrics).

**Free tiers only.** Every source runs on free public access — no paid
API keys, no paid plans, no paid tiers of any service. Sources that
only work behind a paywall (FOFA / Shodan / Censys, Pastebin PRO
search) are documented in `sources/roadmap.md` as not implemented,
with the reason.

## Quick start (full)

```bash
# Business mode: scan a directory tree
python3 aiscan.py scan local tests/fixtures

# ...and its git history (a deleted file does not delete the secret)
python3 aiscan.py scan local tests/fixtures --git-history

# Markdown remediation report
python3 aiscan.py scan local tests/fixtures --format md --output report.md

# Internet mode: bundled FAKE dataset (no token, no network)
python3 aiscan.py scan internet --demo

# Internet mode: live GitHub code search (your own pattern, your token)
GITHUB_TOKEN=ghp_... python3 aiscan.py scan internet --query "sk-or-v1-" --max-pages 1

# Internet mode: presets for high-yield leak surfaces
GITHUB_TOKEN=ghp_... python3 aiscan.py scan internet --preset mcp       # .mcp.json files
GITHUB_TOKEN=ghp_... python3 aiscan.py scan internet --preset notebook  # .ipynb files

# Trial sources (free tiers, bounded caps — see `scan <source> --help`)
python3 aiscan.py scan dockerhub --query openai --max-images 2
python3 aiscan.py scan gists --max-gists 5
python3 aiscan.py scan npm --query openai --max-packages 3
python3 aiscan.py scan pypi --query openai --max-packages 3
python3 aiscan.py scan pastebin --max-pastes 5
python3 aiscan.py scan stackoverflow --query "OPENAI_API_KEY" --max-questions 5
python3 aiscan.py scan commoncrawl --url-pattern "example.com/*" --max-records 3

# Reliability scorecard (precision/recall on fixtures)
python3 aiscan.py selftest
python3 aiscan.py selftest --live   # also runs the live GitHub smoke test
python3 aiscan.py metrics          # fixture scorecard + run metrics

# Full bounded live trial across every source (writes results/TRIAL_RUN.md)
python3 trial_run.py
```

## How it works

| Layer | What it does |
|---|---|
| `sources/` | Local filesystem (respects `.gitignore`, skips binaries/lockfiles), `git log -p` history, GitHub code search API (pagination + rate-limit backoff), demo dataset, Docker Hub images (config ENV first, layers capped at 50 MB/image), public gists, npm/PyPI tarballs (capped at 10 MB/package), Pastebin public archive, Stack Overflow API, Common Crawl index sample |
| `detectors/` | Registry of 15 provider detectors (regex) + Shannon-entropy fallback for generic `api_key`/`token`/`secret` assignments (threshold ~4.5) |
| `verifiers/` | Read-only probes only (model-list/balance endpoints). 200 = live, 401 = dead, 429 = valid but no quota. OFF by default |
| `reporters/` | Terminal table, JSON, Markdown remediation report (grouped by severity, with a checklist) |
| `metrics.py` | Per-run metrics: items/lines/bytes scanned, candidates, findings after dedup, breakdowns by provider/type/severity, verification outcomes, API requests, rate-limit events; fixture precision/recall scorecard |
| `savings.py` | Potential-savings estimate (conservative / expected / worst-case) from public API pricing and documented abuse costs — same model as `results/DISCOVERY_INTELLIGENCE.md`. Split into **candidate** savings (all findings, unconfirmed) and **owner-verified** savings (only keys the owner confirmed live). Labelled as an estimate everywhere; no key is ever tested |

## Potential savings (estimate)

Every scan estimates the money **not** spent because the keys were found
before they could be abused — shown in the terminal table, the metrics
scorecard, the Markdown report, and the JSON output
(`potential_savings_estimate`). The model multiplies keys found ×
probability of abuse × daily abuse cost at public list prices × days
undetected, across three scenarios (conservative 10% / 5M tokens/day /
7 days; expected 25% / 25M / 30 days; worst-case 50% / 100M / 30 days),
plus an assumed $2,500 incident-response cost per abused key. It is an
**estimate, not a verified loss**: no key is tested, billing status is
unknown, and free-tier keys would cost far less. Full model, pricing
sources and abuse evidence: `results/DISCOVERY_INTELLIGENCE.md`.

### Candidate vs owner-verified savings

"Real-looking" only proves a key matches a documented format and sits in
real code/config context — it does not prove the key is live or has paid
billing. So every report shows the estimate twice, using the same model:

- **Potential (candidate) savings** — the model run over **all**
  findings. Unconfirmed; treat it as an upper bound.
- **Owner-verified savings** — the same model run over only the findings
  whose fingerprint the owner has marked verified. Until any key is
  verified this side is **$0**, with an honest note saying so.

### How the owner marks a key verified

A finding is identified by its **fingerprint** — the first 16 hex chars
of the SHA-256 of the key, printed in every report (`fingerprint` in
JSON/Markdown, e.g. `54329e534487d1bd`). A fingerprint reveals nothing
about the key itself, so it is safe to handle and store. Mark a
fingerprint verified **only** for a key you own and have confirmed live
— by checking your provider console, or by an authorized read-only
`--verify` probe on your own assets. Never mark strangers' keys
verified.

```bash
# Mark one key verified (stored in ~/.aiscan/verified-fingerprints.json)
python3 aiscan.py verified add 54329e534487d1bd
python3 aiscan.py verified list
python3 aiscan.py verified remove 54329e534487d1bd

# Use it in a scan (default file, or pass any JSON list / {"fingerprints": [...]} file)
python3 aiscan.py scan local ./myrepo --verified-fingerprints ~/.aiscan/verified-fingerprints.json
```

Fingerprints in the file that match no finding in a scan are reported as
unmatched (stale entry or typo), never counted. The verified file is a
plain JSON list; `verified add` also accepts `--file PATH` to manage a
different one.

## Metrics

Every scan prints a metrics scorecard (stderr) by default, includes a
Metrics section in Markdown reports, embeds `metrics` in JSON reports,
and writes `<output>.metrics.json` next to any `--output` report.
`--no-metrics` suppresses the scorecard; `--metrics-file PATH` writes
the metrics JSON there instead.

```text
Metrics — mode: local:tests/fixtures
  Duration: 0.01s
  Items scanned: 4 (files: 4)
  Lines scanned: 33  Bytes scanned: 2067
  Candidates: 17  Duplicates removed: 1  Findings: 16
  By provider: OpenAI 3, Anthropic 1, Google Gemini 1, Groq 1, ...
  By severity: high 12, medium 4
  API requests: 0  Rate-limit events: 0
```

`python3 aiscan.py metrics` prints the fixture precision/recall
scorecard (recall / precision / decoy hits) plus the run metrics —
the numbers for a business demo: how many keys detected, from where,
of which providers.

## Continuous scanning

Two loops, one ledger (`results/coverage_ledger.json` — one record per
query, fingerprints only, never full keys):

```bash
python3 aiscan.py continuous sweep [--demo]    # re-sweep the 23 seed queries; alert only on NEW or ROTATED keys
python3 aiscan.py continuous expand [--demo] [--count 5]  # run the next unrun queries; shard anything over GitHub's 1,000-result cap
python3 aiscan.py continuous coverage          # ledger table + totals
python3 aiscan.py continuous stress [--demo] [--minutes 120]  # loop sweep+expand until the budget is spent
```

- **Sweep** re-runs the known areas and dedups by SHA-256 fingerprint, so
  a second identical sweep reports 0 new. A key is "rotated" when the same
  file + provider shows a different fingerprint.
- **Expand** works the enumerated query space (seed queries + every
  provider prefix × file qualifier, 132 queries). A query whose
  `total_count` exceeds 1,000 is split by appending qualifiers
  (`language:Python`, `extension:py`, …) until each shard is under the cap;
  the shards run instead of the parent.
- **Stress** appends one JSON line per iteration to
  `results/stress_log.jsonl` (queries run, API calls, files scanned, new,
  rotated, rate-limit hits, errors, elapsed) and a final summary line.
  The ledger is saved after every iteration, so a killed run resumes
  cleanly. A rejected token (401) stops the run with a summary instead of
  crashing. Only totals are kept in RAM across iterations.
- **"Covered"** means every query in the known space has been run and every
  over-cap query sharded under 1,000 — not all of GitHub (395M public
  repos, growing 230/min, against a **10 req/min** code-search limit).
  Live mode needs `GITHUB_TOKEN` or `--token`; `--demo` runs the whole
  thing offline on the bundled FAKE dataset. Verification stays OFF.

Detectors cover OpenAI (project / service-account / legacy), Anthropic,
Google Gemini, Groq, OpenRouter, DeepSeek, xAI, Mistral, Cohere, Together AI,
Perplexity, Hugging Face and Replicate.

## Safety rules (baked in, not optional)

- **Redaction everywhere.** Findings are shown masked only
  (default first 4 chars `...` rest hidden). The full key never appears in terminal,
  JSON or Markdown output — enforced by a runtime guard that aborts output
  if a full secret would be written. `--mask-mode ends` hides the first 5
  and last 3 chars and shows the middle instead — that exposes most of a key,
  so use it only for keys you own, never for strangers' keys in shared reports.
- **Verification is off by default** and uses read-only probes only. It
  must only run on keys you own or are authorized to test. It never
  generates text and never spends credits.
- **Internet mode never invents a query.** You supply your own key
  fingerprint/prefix, org name, or a test pattern. No bulk sweeping of
  arbitrary public keys, no validation of keys you do not own.
- **Dedup** by SHA-256 of the candidate string, so one key in ten places
  is one finding.

## Encrypted vault (admin-only unmask)

The vault is where a finding's **unmasked** key lives — encrypted at rest,
admin-only to open. Everything else (terminal, JSON/Markdown reports,
metrics, logs) stays masked, always. It exists so a business scanning its
**own** code can keep a leaked key on file long enough to rotate it, instead
of losing the exact value the moment the report is printed.

**Setup** — needs the `cryptography` package (`pip install cryptography`):

```bash
python3 aiscan.py vault init          # set the admin passphrase (never stored)
```

Vault file defaults to `~/.aiscan/vault.json`, audit log to
`~/.aiscan/vault-audit.jsonl` (override with `--vault-file` / `--audit-file`,
or `AISCAN_VAULT_FILE` / `AISCAN_VAULT_AUDIT_FILE`). The passphrase comes
from an interactive prompt, or `AISCAN_VAULT_PASS` for automation. Lose the
passphrase and the vault cannot be opened — there is no recovery.

**Commands**

```bash
python3 aiscan.py scan local ~/myrepo --vault     # store findings from YOUR code
python3 aiscan.py scan internet --demo --vault    # store DEMO (fake) findings
python3 aiscan.py vault list                      # masked only, no passphrase needed
python3 aiscan.py vault reveal vlt_abc123         # admin passphrase; audit-logged
python3 aiscan.py vault audit                     # append-only audit log
python3 aiscan.py vault rotate vlt_abc123         # mark rotated after rotation
python3 aiscan.py vault expire vlt_abc123         # mark expired
python3 aiscan.py vault purge                     # drop rotated/expired entries >30 days
echo -n "sk-..." | python3 aiscan.py vault store --provider OpenAI --file .env
```

**How it is keyed** — AES-256-GCM; the vault key is derived from the admin
passphrase with PBKDF2-HMAC-SHA256 (600,000 iterations) and a per-vault
random salt. Each entry gets its own random 12-byte nonce. A stored
encrypted verifier rejects a wrong passphrase before any entry is touched.
Vault file mode is 0600 and writes are atomic.

**Admin model** — there is one admin: whoever holds the passphrase.
Listing is masked and needs no passphrase. Revealing needs the passphrase
and writes an audit entry (who/when/which finding — never the key). Every
store / reveal / rotate / expire / purge is audit-logged the same way.

**Scope boundary (enforced, not just documented)** — the vault only accepts
keys from scans you own or are authorized to handle (`scan local`, demo
data, or a manual `vault store` you type yourself). `--vault` on a live
internet scan is **refused** (`error: refusing --vault for live internet
findings`). Keys found on the public internet that belong to strangers are
never vaulted in full — they stay masked-only. Do not vault any finding
from `results/TRIAL_RUN_3.json`.

## Live demo

See `demo/DEMO_SCRIPT.md` and run `bash demo/run_demo.sh`. It includes a
"plant your own honeytoken" section: the reliable, repeatable live demo
that does not depend on strangers' keys. The demo now includes a metrics
step (fixture scorecard + a bounded live source scan) so the audience
sees detection counts live.

## Trial run

`python3 trial_run.py` runs a bounded live trial across every
implemented source (small caps: 1 page / ~5 items per source) and
writes `results/TRIAL_RUN.md` and `results/trial_run.json` — a results
table with candidates found, findings after dedup, and breakdowns by
provider and by source, plus the metrics scorecard. Caps used, rate
limits, and auth failures are recorded honestly. All findings redacted.

## Contributing and feedback

aiscan is a prototype and it gets better from real-world feedback. See
[FEEDBACK.md](FEEDBACK.md) for what is most useful. The short version:

- **Missed a key?** Open a *missed detection* issue: provider, file
  type, and the key **masked** (first 4 chars `...` rest hidden) — never the
  full key.
- **False positive?** Open a *false positive* issue: what was flagged
  and what it actually is.
- **Bug?** Open a *bug report* with the command you ran and the error.
- **New provider or source?** A detector is one entry in
  `detectors/registry.py`; a source is one file in `sources/` plus a
  CLI subcommand. Pull requests welcome.

**Privacy:** aiscan runs locally and uploads nothing. The only network
calls it ever makes are the ones you explicitly trigger: a source fetch
(GitHub search, Docker Hub, npm, PyPI, Pastebin, Stack Overflow,
Common Crawl) or a read-only verification probe (`--verify`, off by
default, only for keys you own). Findings are never sent anywhere.

## Limitations

- GitHub code search needs a token and is rate-limited (30 code-search
  requests/min authenticated); the scanner backs off and reports instead
  of crashing.
- Regex + entropy detection has false negatives (custom formats, split or
  obfuscated secrets, binary files) and false positives (entropy-only
  findings). A clean result is not a safety guarantee.
- Verification is implemented for OpenAI, Groq, OpenRouter and Gemini
  only; other providers report `unsupported`.
- The live smoke test (`selftest --live`) needs `GITHUB_TOKEN`; without
  one it records "skipped".
- Pastebin has no free search API: the source samples the public archive
  listing only (recent pastes, no keyword search — that needs PRO).
- Common Crawl sampling is deliberately tiny (default 3 records);
  full-scale use needs batch processing.
- Kaggle/Colab notebooks and CI build logs are not implemented — see
  `sources/roadmap.md` for what each would need.
