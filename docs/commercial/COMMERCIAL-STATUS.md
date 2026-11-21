# KeySentry — Commercial Status

Status tracker for the commercialization build (business mode,
subscriptions). Updated 2026-11-21, after the comprehensive-platform
build (Pillars 1, 2, 7 + freemium layer model + exact free-tier caps +
Premium / Premium Plus tiers).

**Verification state (all local, Nov 21, 2026):** `python3 -m pytest`
**173 passed** in `~/workspace/ai-key-scanner`; `npm run build` clean
and `npm test` **8 suites / 96 checks** in `~/workspace/key-sentry`
(rate-limit 7, usage-limits 6, vibe-scan 15, audit 23, agents 14,
plans 12, caps 10, billing 9). MCP selftest 15/15, fingerprint selftest
10/10. **Nothing in this build is pushed or deployed** — remote HEADs
unchanged (CLI `efc3370`, web `b3bfe74`); the live app still runs the
Nov 21, 1:00 a.m. deploy.

## Corrected figures (Nov 21 human review)

- **604 distinct real-looking keys** (was 612; 8 demo/sample/test rows
  reclassified — see `results/REVIEW_24_DISPUTED.md`). Candidate savings
  **$7,006.83 / $371,799.20 / $2,968,998.90** (conservative / expected /
  worst-case). Owner-verified savings: **$0**.
- Score policy (proposed, undecided): ≥80 = billable confirmed leak
  (467 of 660 stress rows), 50–79 = needs review, <50 = excluded from
  headline counts.

## Pillar 1 — Agent identity (built Nov 21, local only)

- MCP config scanner (`agents/`, CLI `aiscan.py agents inventory|map`):
  parses `.mcp.json`, Claude Code settings, Cursor rules into an agent
  inventory (name, type, config path, credentials by provider +
  fingerprint, never the raw value).
- Agent → credential → repo → owner mapping: CLI command + web dashboard
  view (`app/agents/`); a fingerprint can be tagged with its agent.
- KeySentry MCP server, read-only (`mcp_server.py`, stdio JSON-RPC):
  exposure check, fingerprint check, posture summary. Never returns raw
  keys — masked/fingerprint results only. 100/day query quota on Free
  (see Caps).
- Tests: `tests/test_agents.py` (15), `tests/agents.test.mjs` (14).

## Pillar 2 — Vibe-code security scanner (built Nov 21, local only)

- Web repo-URL scan (`app/vibe/`, `POST /api/vibe-scan`): paste a public
  repo URL, get a security report — leaked secrets via the existing
  detectors + confidence scores, OWASP-style checks, exposed database
  configs. No install, no account. Caps: 100 files / 200 KB each /
  5 MB total; GitHub 403 → clear 502.
- Shareable report page (`app/vibe/[id]`): public link, masked-only
  findings; free list shows the latest 2 per type, links stay live.
- Plain-language fix suggestions per finding, for non-developers.
- Reuses `detectors/registry.py`, `confidence.py`, and the GitHub Action
  pattern — no duplicated detection logic. Detector patterns are
  exported to the web app by `scripts/export_detector_patterns.py`
  (15 patterns; regen diff identical).
- Tests: `tests/test_vibe.py` (12), `tests/vibe-scan.test.mjs` (15).

## Pillar 3 — Agent audit trail (built Nov 21, local only)

- Canonical event schema (shared by Pillars 1+2): event_id, event_type,
  timestamp, prev_hash, event_hash = SHA-256 over the canonical JSON,
  genesis `"0"*64`, principal_id, parent_agent_id, session_id, policy_id,
  ticket_of_record, model_run_id, agent id/version/model, tool,
  resource, arg_keys (KEY NAMES ONLY), decision {allow, policy, reason},
  outcome, correlation_id. Attempts are logged, not only successes.
- Redaction before write (`lib/audit-redact.ts`, `audit/`): allowlist
  only — tokens, secrets, and raw arguments never reach the log.
  Smuggle tests try to sneak secrets through (5 scenarios, all pass).
- Hash-chained append-only log, CLI + web, with a verify command that
  recomputes the chain per event. Joint check passed: Pillar 2 findings
  + Pillar 1 MCP calls in one log, 8 events, chain intact; tampering
  one field → `CHAIN BROKEN — first bad index 1`.
- Timeline view in the dashboard (`app/audit/`): per agent, per run,
  decision attached.
- Five detections: tool-set drift, cost spike (3.0× trailing hourly
  mean, min 10), confidence-floor breach (floor 0.7), cross-tenant
  access (`tenant:` prefix), sub-agent fan-out (>5 children/3600s).
  Alerts, not just logs.
- Compliance export: SOC 2 / ISO 27001 control mapping, EU AI Act
  Article 12 report, SIEM-friendly JSON export. Retention: hot 30d /
  warm 90d / cold 7y (pilot: 90 days).
- Tests: `tests/test_audit.py` (38), `tests/audit.test.mjs` (23).
- Known limits: DB ingest not verified end-to-end (no live DB; routes
  503 by design without one); concurrent web ingests could fork the
  chain (needs a serializing lock before production); web list
  filtering is in-JS (pilot-scale only); no web retention job (CLI
  only); no cold-expiry deletion.

## Freemium layer model (built Nov 21, local only)

- Plan definitions in code, one source of truth:
  `docs/commercial/plans.json` (canonical, v2) → `lib/plans.json`
  (via `scripts/sync_plans.py`, verified identical) → `plans.py`
  (CLI, with built-in fallback) + `lib/plans.ts` (web). Full ladder:
  **Free $0 / Maker $19 / Starter $49 / Premium $99 / Team $149 /
  Premium Plus $299 / Business $499 / Enterprise custom** — all prices
  proposed, to be validated by pilots; implemented as data, not
  hardcoded logic.
- Free vs commercial split: free = one-repo audits/reports, 5
  fingerprint checks, one-agent timeline, read-only MCP queries;
  commercial = monitoring, alerts, team workflow, remediation, full
  audit log, detections, compliance export, API.
- Server-side enforcement (`lib/plan-enforcement.ts`, `lib/usage.ts`;
  CLI `plans.py` gates). A limit hit shows an upgrade prompt naming
  the next tier, its price, and exactly what it unlocks — never a dead
  end, never a silent block. Free users are never locked out of what
  they already had; upgrading only adds capabilities.
- Billing stub (`lib/billing.ts`, `app/api/billing/`): checkout +
  webhook route code using Stripe env-var placeholders
  (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`,
  `STRIPE_PRICE_MAKER` / `_STARTER` / `_PREMIUM` / `_TEAM` /
  `_PREMIUM_PLUS` / `_BUSINESS`), plan state per workspace. No Stripe
  SDK, no connection, no real keys. Checkout without env → 503
  `billing_not_connected` with setup instructions; the pay layer can
  start charging the moment Stripe is connected, the free layer keeps
  working untouched.
- Tests: `tests/test_plans.py` (incl. the 2 Premium/Premium Plus
  tests), `tests/plans.test.mjs` (12), `tests/billing.test.mjs` (9).
  Webhook signature known-good vector passes; tampered / wrong-secret /
  stale / malformed fail.

## Exact free-tier caps (built Nov 21, local only)

Source of truth: `docs/commercial/FREE-TIER-CAPS.md` (PDF-editor model,
2 free uses/day, reset midnight UTC). Full detail + per-resource
next-tier choices in `docs/commercial/CAPS-INTEGRATION.md`.

- Daily caps (midnight UTC): web repo scan 2/day, Agent Identity Audit
  2/day, MCP read-only queries 100/day, dashboard saves 2/day.
- Persistent caps: 5 fingerprints total (manual check 1×/day each, no
  auto-monitoring on Free), audit timeline 1 agent + last 7 days,
  shareable reports latest 2 per type (links stay live), GitHub Action
  dashboard history latest run only, 1 team seat, no email/Slack
  alerts on Free.
- CLI local scans stay unlimited (runs on the user's machine) — only
  the dashboard save is capped. Anonymous users get the same 2/day web
  caps, tracked by hashed IP (SHA-256 first 16 hex, never raw IP).
- Counter shown everywhere: "1 of 2 free scans used today" (CLI
  `plan counters` + `agents inventory|map` display, web
  `CounterBadge.tsx`). Cap hit → upgrade prompt naming exactly what
  the next tier unlocks + "come back tomorrow, it works again."
- **Cap-hit test (verified live, Nov 21):** free user at 2/2 scans →
  3rd scan denied with "Free plan allows up to 2 vibe-code scans per
  day (you have used 2 today). Upgrade to Maker ($19/mo) to unlock
  unlimited vibe-code scans. Come back tomorrow, it works again (free
  caps reset at midnight UTC)." Under-cap scan allowed, no message.
  Counter display verified live against a stub counters endpoint
  ("1 of 2 free audits used today"; at 2/2 the Starter prompt shows);
  `--json` output stays pure JSON.
- Upgrade paths (price-ordered ladder): a Premium cap hit names Team
  (MCP 5,000/day → Team; 60-day history → Team); a Premium Plus cap
  hit names Business (180-day history, 25 seats → Business). One
  exception the data forces: Premium seats (5) cannot lift at Team
  (also 5) → Premium Plus (25).
- No surface yet (declared, not enforced): GitHub Action dashboard
  history (no Action-runs table), team seats (no accounts/invites),
  CLI dashboard saves (no CLI command POSTs to the dashboard), Fix PRs
  (Maker feature, no PR-creation code).
- Tests: `tests/test_caps.py` (13), `tests/caps.test.mjs` (10).
- **Not verified live:** the route-level 3rd-scan → 429 (no Postgres
  reachable from the build machine, so the DB-backed path can't run
  here). Verified by construction: `npm run build` type-checks the
  wiring, and the 429 shape, `resetsAt`, and upgrade prompt are
  covered by the pure-helper tests. Needs a deployed-app check.

## Earlier commercial build (rounds 1–2, deployed Nov 21, 1:00 a.m.)

Fingerprint monitoring (hashes-only, webhook alerts), confidence
scoring 0–100, GitHub Action + pre-commit hook + pip packaging
(`aiscan` 0.1.0), repo connection via PAT + owner-authorized
verification (`--i-own-these-keys`), team basics (assign / posture /
export), findings dashboard, nightly 2 a.m. sweep (`CRON_SECRET` set),
usage + rate limits, email alerts (Resend/SMTP, wired, no credentials
yet), commercial docs. Deployed as web `b3bfe74` + CLI `efc3370`
(dogfood Action run #2 green, 0 findings, 13s). That deployed code
predates the Pillars/layer/caps build in this file.

## Still needs the user

- **Deploy** the local build (push both repos, manual Vercel Create
  Deployment from main — push-triggered deploys have been unreliable —
  then the deployed-app checks: route-level 3rd-scan → 429, DB-backed
  audit ingest, counters endpoint).
- **Stripe:** connect Stripe (keys + 6 Price IDs in Vercel) and confirm
  the proposed prices ($19 / $49 / $99 / $149 / $299 / $499 / custom)
  or set real ones. Until then the pay layer cannot charge.
- **Email alerts:** Resend API key (or SMTP) + the address alerts go
  to (+ verified sender).
- **Accounts decision:** keep the single admin-passphrase model for
  the pilot, or build real team accounts/roles.
- **Score-policy decision:** ≥80 confirmed / 50–79 review / <50
  excluded (proposed, undecided).
- **Pilot go-ahead + invitees:** Sravan (Sravan08@gmail.com) named
  pilot #1; invite drafted and HELD at the user's tap — do not send
  unless re-raised.
- **Slack webhook URL** (optional; `KEYSENTRY_ALERT_WEBHOOK` unset).
- Docs gaps (not invented): no security contact address, no web-app
  retention period, no incident-response owner.

## What is already true overall

- CLI scans local repos and git history; internet mode sweeps public
  GitHub code search; **604 distinct real-looking keys** found so far,
  all confirmed still exposed by unauthenticated raw re-fetch.
- Masking is prefix4 by default; fingerprints are SHA-256 first 16 hex;
  strangers' keys are never tested against a provider, never
  ends-masked, never unmasked, never vaulted.
- Owner-verified savings: $0. Candidate savings on the 604 keys:
  $7,006.83 / $371,799.20 / $2,968,998.90
  (conservative / expected / worst-case).
- Web app live at https://key-sentry-inky.vercel.app (deployed build
  `b3bfe74`); vault empty, owner-verified savings $0.
- Example/test keys only through the existing `is_example_key` filter;
  it was not weakened. `results/` and `fingerprints.json` stay
  gitignored; local daily-counter state (`.key-sentry-*.json`) is now
  gitignored too.
