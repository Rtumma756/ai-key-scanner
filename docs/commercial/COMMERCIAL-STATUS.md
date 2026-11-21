# KeySentry — Commercial Status

Status tracker for the commercialization build (business mode,
subscriptions). Updated 2026-11-21.

Builders are running in parallel on the items below. This file is written
by the docs agent, which cannot verify builders' work. Every item is
marked **in progress, unverified by docs** unless the "already true" line
says otherwise with a source the docs agent checked directly.

## The 8 build items

### 1. Fingerprint monitoring
- **Status:** in progress, unverified by docs.
- **Already true:** fingerprints are computed in the CLI today — SHA-256,
  first 16 hex — and the CLI accepts an owner-verified fingerprints file
  (`--verified-fingerprints`). The web vault deduplicates entries by
  fingerprint.
- **Email alerts (built 2026-11-21, unverified by docs):** the web app
  now sends a fingerprint-match email as well as the Slack-compatible
  webhook when a NEW match is recorded — Resend API first
  (`RESEND_API_KEY`), plain SMTP fallback (`SMTP_*`, nodemailer),
  recipients from `KEYSENTRY_ALERT_EMAIL`; `lib/email.ts` +
  `lib/alerts.ts` in `~/workspace/key-sentry`, CLI mirror
  `email_alert.py` (stdlib only) with tests in
  `tests/test_email_alerts.py`. Email alerts are a Starter-tier
  feature per `PRICING.md` (Yes on Starter, Team, and Business).
  Full setup, test procedure, and the one-line CLI wiring for
  `fingerprint_watch.py` are in `docs/commercial/EMAIL-ALERTS.md`.
- **Still open:** registering fingerprints for monitoring and alerting
  when one appears in public code is not verified as live. **No
  SMTP/Resend credential exists yet** — supplying one in Vercel env
  vars (plus redeploy) is a documented next step for the user, so no
  email can be sent until then; nothing was deployed in this work.

### 2. GitHub Action + pre-commit hook
- **Status:** in progress, unverified by docs.
- **Already true:** the CLI scans a local directory and git history
  (`scan local <path> [--git-history]`), which is what an Action or hook
  would call.
- **Still open:** no Action or pre-commit hook has been verified by docs.

### 3. Repo connection
- **Status:** in progress, unverified by docs.
- **Already true:** local scans and the web scanner work without any repo
  connection.
- **Still open:** connecting a customer's own repos (as opposed to
  scanning a local checkout) is not verified as live.

### 4. Owner verification
- **Status:** in progress, unverified by docs.
- **Already true:** the CLI has a `--verified-fingerprints` mechanism and
  the vault has a `rotate` action; owner-verified savings to date are $0.
- **Still open:** a customer-facing flow for an owner to confirm or rotate
  a key is not verified as live.

### 5. Team basics
- **Status:** built 2026-11-21, not deployed; verified by builder via
  `npm run build` (all three new routes compile) and
  `python3 -m pytest tests/test_team.py` (21 passed). Live-database
  behaviour is NOT verified — no DB is reachable from the build
  machine, and nothing was deployed.
- **Already true:** matches can be assigned to a team member
  (`POST /api/matches/assign`, admin only; free-text name, max 100
  chars, empty clears; returns the match plus its history), every
  status change is recorded in a `match_status_history` table
  (acknowledge/resolve, re-open on re-sighting, and assignment
  changes; `getMatchHistory(matchId)`), per-repo posture is served at
  `GET /api/posture` (counts only, no passphrase: totals, open/
  resolved, by provider, open-age buckets <7d / 7–30d / >30d, oldest
  open match, plus a global summary with open rate), matches export at
  `GET /api/matches/export?format=csv|json` (admin only, filename
  `keysentry-matches-YYYYMMDD.csv|.json`), and the CLI gained
  `fingerprint_watch.py assign` and `posture` subcommands
  (`--export csv|json`; base URL from `KEYSENTRY_BASE_URL` or
  `KEYSENTRY_URL`; passphrase from `KEYSENTRY_ADMIN_PASS` or
  `--admin-pass`, never stored). All of it stays inside the
  passphrase-admin model — no auth provider, no user accounts.
- **Still open:** user accounts are an OPEN decision (no auth
  provider chosen; assignees are free-text names, `changed_by`
  defaults to `'admin'`); the assign/posture/export routes have not
  been exercised against the live Neon database; no team UI exists
  yet (API + CLI only); prices are still not set (see PRICING.md).

### 6. Confidence scoring
- **Status:** in progress, unverified by docs.
- **Already true:** the CLI selftest produces a precision/recall
  scorecard on fixtures, and findings carry a `detected_via` field
  (regex / context / entropy).
- **Still open:** a per-finding confidence score shown to customers is
  not verified as live.

### 7. Scheduled sweeps + dashboard + accounts/limits
- **Status:** built 2026-11-21 (dashboard, sweeps, limits, rate limiting),
  awaiting docs verification.
- **Already true:** the web app is live at
  https://key-sentry-inky.vercel.app, with a vault backed by Neon
  Postgres. The CLI has bounded trial sources (Docker Hub, gists, npm,
  PyPI, Pastebin, Stack Overflow, Common Crawl).
- **Built 2026-11-21 (this change):**
  - Findings dashboard in the web app (`app/page.tsx`, Findings
    section): summary header (open / new / resolved / total), filters
    for status, provider, and text search over repo / file /
    fingerprint, per-finding fingerprint, provider, repo, `file:line`,
    first/last seen, status, assignee, and acknowledge / resolve /
    assign / history actions (admin passphrase, same pattern as the
    Vault section). History comes from `GET /api/matches/history?id=…`
    and from the assign response.
  - Scheduled sweeps: Vercel cron (`vercel.json`, `0 2 * * *` —
    daily is the most frequent Hobby schedule) calling new route
    `GET /api/cron/sweep` (Bearer `CRON_SECRET`, max 50 open matches
    per run, 5 s per raw fetch, never auto-resolves, returns
    `{ checked, stillPresent, gone, errors }`); plus a scheduled-CLI
    path, `scripts/scheduled_sweep.sh` (continuous sweep + liveness
    re-check + fingerprint watch check), documented with cron and
    GitHub Actions examples in
    `docs/commercial/SCHEDULED-SWEEPS.md`. Credentials needed: a
    GitHub token for code search, the admin passphrase for posting
    matches, `CRON_SECRET` for the Vercel route — nothing else.
  - Usage limits (`lib/usage.ts`, Postgres `usage_counters` table):
    fingerprints added 20/day
    (`KEYSENTRY_MAX_FINGERPRINTS_PER_DAY`), matches recorded 500/day
    (`KEYSENTRY_MAX_MATCHES_PER_DAY`), enforced in the two POST routes
    after the admin check, 429 naming the limit. Tests:
    `tests/usage-limits.test.mjs`.
  - Abuse guardrails (`lib/rate-limit.ts`, in-memory per-IP token
    bucket): mutating API routes 60/min/IP, GET routes 120/min/IP,
    429 with `Retry-After`; applied in the fingerprints and matches
    routes. Tests: `tests/rate-limit.test.mjs`. `npm test` passes
    (13 checks); `npm run build` passes.
- **Still open:** no user accounts — single admin-passphrase
  workspace, so the usage limits above are workspace-global, not
  per-workspace or per-plan; full per-workspace plan enforcement
  needs accounts. Rate limiting is not yet applied to
  `/api/matches/assign`, `/api/matches/export`, `/api/posture`, or
  `/api/vault/*`, and the in-memory bucket resets on cold start and
  is not shared across instances (pilot-grade, not a WAF). Vercel
  cron is daily-only on Hobby (fires anywhere within the hour), so
  sub-daily sweeps need Pro or an external scheduler calling
  `/api/cron/sweep`. The continuous sweep does not yet emit a results
  JSON for `fingerprint_watch.py check`, so the scheduled script
  checks the latest classified batch instead.

### 8. Packaging + docs + policy + disclosure
- **Status:** in progress — this docs set is the docs half.
- **Already true:** this directory now holds `SECURITY.md`,
  `QUICKSTART.md`, `PILOT-GUIDE.md`, `RESPONSIBLE-DISCLOSURE.md`,
  `PRICING.md`, `EMAIL-ALERTS.md`, and this file. The CLI README (340 lines), `FEEDBACK.md`,
  and the three issue templates (bug report, false positive, missed
  detection) already exist.
- **Still open:** packaging is unverified by docs; the gaps named in
  `SECURITY.md` (no security contact address, no web-app retention
  period, no incident-response owner) and in `PRICING.md` (no prices set)
  are still open.

## What is already true overall (verified by docs)

- CLI scans local repos and git history; internet mode sweeps public
  GitHub code search; 612 distinct real-looking keys found so far, all
  confirmed still exposed by unauthenticated raw re-fetch.
- Masking is prefix4 by default; fingerprints are SHA-256 first 16 hex;
  strangers' keys are never tested against a provider; live internet
  findings are never vaulted.
- Owner-verified savings: $0. Candidate savings on the 612 keys:
  $7,103.07 / $376,955.44 / $3,010,248.90
  (conservative / expected / worst-case).
- Web app live at https://key-sentry-inky.vercel.app; vault empty,
  owner-verified savings $0.
