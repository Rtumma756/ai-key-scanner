# KeySentry — Scheduled Sweeps, Usage Limits & Abuse Guardrails

How open findings get re-checked on a schedule, and what stops one
caller from burning the free tier. Built 2026-11-21.

## 1. Vercel cron sweep (web app)

### Schedule — Hobby's most frequent

`vercel.json` (in `~/workspace/key-sentry/`) declares one cron:

```json
{ "crons": [{ "path": "/api/cron/sweep", "schedule": "0 2 * * *" }] }
```

**Why daily at 02:00 UTC:** on the Vercel Hobby plan a cron job may run
**at most once per day** — any expression that would run more often
fails the deployment ("Hobby accounts are limited to daily cron jobs").
The run may also fire at **any point within the scheduled hour**
(02:00–02:59 UTC), not at 02:00 sharp. So `0 2 * * *` is the most
frequent free-tier schedule available; hourly or sub-daily sweeps need
Pro, or an external scheduler calling the same route (see §2). Pro and
Enterprise allow up to once per minute. Vercel's cron jobs run only on
production deployments and are not retried on failure.

### The route: GET /api/cron/sweep

Auth: `Authorization: Bearer <CRON_SECRET>` — `CRON_SECRET` is a
Vercel env var (set it in Project → Settings → Environment Variables;
Vercel sends the same bearer token when it fires the cron). If
`CRON_SECRET` is unset the route answers 503; a wrong/missing token
answers 401. It never runs unauthenticated.

What one run does (all fingerprint-only — no raw keys, no provider
calls):

1. Loads open matches — status `new` + `acknowledged`, max **50 per
   run**, most recently seen first.
2. Groups matches by (repo, file) and fetches each file once from
   `raw.githubusercontent.com` (unauthenticated, `main` then `master`,
   **5 s timeout per fetch**, files over 2 MB skipped).
3. Scans the file with the existing TS detectors (`lib/scan.ts`) and
   compares SHA-256 fingerprints of the findings with the watched
   fingerprint.
4. Still present → `last_seen` is refreshed via `recordMatch`.
   Absent → the match is **left as-is, never auto-resolved**: a missing
   fingerprint can also mean the file moved, was renamed, or the branch
   changed. A human resolves it in the Findings dashboard.

The run is time-boxed to ~50 s of fetching so it stays inside the
60 s Hobby function limit (`maxDuration = 60`); matches not reached in
time are reported as `skipped`, not as errors.

Response (JSON):

```json
{
  "checked": 12,
  "stillPresent": 9,
  "gone": 2,
  "errors": 1,
  "skipped": 0,
  "details": [
    { "fingerprint": "c826852ab88147ba", "repo": "owner/repo",
      "file": "config.py", "line": 14, "result": "still-present",
      "note": "last_seen refreshed" }
  ]
}
```

`result` is one of `still-present`, `gone`, `error`, `skipped`, with a
human-readable `note` in every case.

## 2. Scheduled CLI sweep (Linux box / GitHub Actions)

For anything the Vercel cron cannot do — the Python CLI's internet
sweep and liveness re-check — run
`scripts/scheduled_sweep.sh` (in `~/workspace/ai-key-scanner/`).
It runs, in order, each step even if an earlier one failed:

1. `python3 aiscan.py continuous sweep` — re-sweeps the coverage
   ledger's seed queries on GitHub code search; alerts (masked only)
   on NEW or ROTATED keys. Ledger: `results/coverage_ledger.json`.
2. `python3 fresh_liveness_all.py` — re-fetches each known key's file
   from public GitHub (unauthenticated, read-only) and re-runs the
   detectors; a key counts as still exposed only if a detected value
   has the identical SHA-256 fingerprint. Writes
   `results/FRESH_LIVENESS_ALL.md` + `.json`.
3. `python3 fingerprint_watch.py pull` + `check` — pulls the watched
   fingerprint list from the web API (hashes only) and records
   sightings from the latest classified batch as matches
   (`POST /api/matches`), so they appear in the Findings dashboard.

Exit code: 0 when every step that ran succeeded, 1 when any step
failed, 2 when required configuration is missing.

### Credentials it needs

| Variable | Needed for | Notes |
|---|---|---|
| `GITHUB_TOKEN` | Step 1 (code search) | **Required** — script exits 2 without it. Fine-grained token, public repos read-only. Never commit it. |
| `KEYSENTRY_ADMIN_PASS` | Step 3 (POST /api/matches) | Same `VAULT_ADMIN_PASS` as the web app. If unset, step 3 runs as `--dry-run`: matches are printed, nothing is recorded. |
| `KEYSENTRY_URL` | Step 3 (web app base URL) | Optional; defaults to the live Vercel URL. |

Nothing else. No provider API keys, ever — no found key is tested
against any provider.

### Scheduling — Linux crontab

Daily 02:30 UTC (after the Vercel cron):

```cron
30 2 * * *  cd /path/to/ai-key-scanner && GITHUB_TOKEN=<token> KEYSENTRY_ADMIN_PASS=<pass> ./scripts/scheduled_sweep.sh >> results/logs/sweep.log 2>&1
```

Put the secrets in the cron environment or a secrets store, not in
the crontab line itself where the box is shared.

### Scheduling — GitHub Actions

`.github/workflows/keysentry-scan.yml` runs on push/PR; for a
scheduled sweep add a workflow like this (secrets in the repo's
Settings → Secrets and variables → Actions):

```yaml
name: KeySentry scheduled sweep

on:
  schedule:
    - cron: "30 2 * * *"   # daily 02:30 UTC
  workflow_dispatch:       # allow a manual run

permissions:
  contents: read

jobs:
  sweep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Scheduled sweep
        env:
          GITHUB_TOKEN: ${{ secrets.AISCAN_GITHUB_TOKEN }}
          KEYSENTRY_ADMIN_PASS: ${{ secrets.KEYSENTRY_ADMIN_PASS }}
          KEYSENTRY_URL: https://key-sentry-inky.vercel.app
        run: ./scripts/scheduled_sweep.sh
      - name: Upload sweep outputs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sweep-outputs
          path: |
            results/FRESH_LIVENESS_ALL.md
            results/FRESH_LIVENESS_ALL.json
            results/coverage_ledger.json
```

Or call the Vercel route directly from any scheduler (e.g. for a
more frequent sweep than Hobby's daily cron allows):

```bash
curl -s "https://key-sentry-inky.vercel.app/api/cron/sweep" \
  -H "Authorization: Bearer $CRON_SECRET"
```

### Open gap in the CLI path

The continuous sweep (step 1) prints its new/rotated detections but
does **not** write a results JSON, so step 3 checks the latest
`results/CLASSIFY_*.json` batch instead of the sweep's own output. A
sweep run's fresh detections therefore do not flow into the
fingerprint watch check until they are classified into a batch.
Wiring sweep output into a JSON that `fingerprint_watch.py check`
can consume is open work.

## 3. Findings dashboard (web app)

`app/page.tsx` — **Findings** section, below Fingerprint monitoring.
It fetches `GET /api/matches` (all matches) and renders:

- Summary header: open (new + acknowledged), new, resolved, total.
- Filters: status (`new` / `acknowledged` / `resolved` / all),
  provider (dropdown of providers present in the matches), and text
  search over repo, file, and fingerprint.
- Per finding: fingerprint, provider, repo, `file:line`, first/last
  seen, status, assignee.
- Actions (admin passphrase, same pattern as the Vault section —
  entered once, reused for these calls): **Acknowledge**,
  **Resolve** (both `PATCH /api/matches`), **Assign**
  (`POST /api/matches/assign`, free-text team-member name, empty
  clears), and **History** (expands the status/assignment history for
  that finding, from `GET /api/matches/history?id=…`; the assign
  response also carries the updated history). If a match object
  carries a `history` array it is rendered; otherwise the row just
  says no history is recorded yet.

## 4. Usage limits (daily counters, Postgres)

`lib/usage.ts` — table `usage_counters`
(`key TEXT, day DATE, count INTEGER, PRIMARY KEY (key, day)`),
one row per counter per UTC day. Helpers: `checkLimit(key, maxPerDay)`
/ `recordUsage(key)`. A breach answers **429** naming the limit, with
`Retry-After` set to seconds until midnight UTC.

| Limit | Default | Env var |
|---|---|---|
| Fingerprints added per day | 20 | `KEYSENTRY_MAX_FINGERPRINTS_PER_DAY` |
| Matches recorded per day | 500 | `KEYSENTRY_MAX_MATCHES_PER_DAY` |

Enforced in `POST /api/fingerprints` and `POST /api/matches`, after
the admin-passphrase check (so unauthenticated callers cannot burn
the quota or probe the limit) and counted only after the operation
succeeds. Defaults fit a free pilot; raise them with the env vars in
Vercel when the pilot grows.

## 5. Abuse guardrails (rate limiting)

`lib/rate-limit.ts` — lightweight per-IP token bucket, in-memory.
**It resets on cold start and does not share counts across Vercel
function instances: pilot-grade control, not a WAF.** Exact
multi-instance enforcement would need the buckets in Postgres (same
shape as `usage_counters`) or a dedicated rate-limit service.

| Routes | Limit |
|---|---|
| Mutating API routes (`/api/fingerprints`, `/api/matches`) — POST / PATCH / DELETE | 60 requests/minute per IP |
| GET routes | 120 requests/minute per IP |

Over the limit the route answers **429** with a `Retry-After` header
(in seconds). The client IP is the leftmost entry of
`X-Forwarded-For` (set by Vercel), falling back to `X-Real-IP`.

Applied in: `app/api/fingerprints/route.ts` (GET/POST/DELETE),
`app/api/matches/route.ts` (POST), and the new
`app/api/matches/history/route.ts` (GET).

**Not yet applied** (open): `POST /api/matches/assign`,
`GET /api/matches/export`, `GET /api/posture`, and the
`/api/vault/*` routes — those route files are owned by other builders
or out of this change's scope; the same one-line
`checkRateLimit(req, …)` call at the top of each handler covers them.

## 6. What is still open

- **No user accounts.** Everything above is workspace-global with a
  single admin passphrase. Per-workspace / per-plan enforcement,
  teams, and roles need accounts first (see COMMERCIAL-STATUS.md
  item 7).
- **Vercel cron is daily-only on Hobby** (and fires anywhere within
  the hour). Sub-daily sweeps need Pro or the external-scheduler
  call in §2.
- **Sweep → fingerprint-check handoff** (§2, open gap): the
  continuous sweep does not emit a results JSON for
  `fingerprint_watch.py check`.
- **Rate limiting on the remaining routes** (§5): assign, export,
  posture, vault.
- **In-memory rate-limit state** (§5): resets on cold start, not
  shared across instances.
