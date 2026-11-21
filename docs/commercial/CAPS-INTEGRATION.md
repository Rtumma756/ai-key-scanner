# CAPS-INTEGRATION.md — wiring the free-tier caps (FREE-TIER-CAPS.md)

Short doc for the coordinator: the caps build is done (CLI + web), but
`aiscan.py` is NOT edited by this build (another agent owns it). This
file records what was built, every next-tier choice, and the exact
insertion points where the coordinator applies the `aiscan.py` wiring.
Line numbers are for the `aiscan.py` in the repo at the time of writing
(Nov 21, 2026) — verify them before editing; the anchors (function
names) are stable.

Source of truth: `docs/commercial/FREE-TIER-CAPS.md` (PDF-editor model:
2 free uses/day, reset at midnight UTC). Nothing in this build invents
a cap or a surface: where a cap has no enforcement surface yet, it is
listed as such in §7 instead of being silently skipped.

## 1. What already exists (this build)

### Plan definitions — `docs/commercial/plans.json` (v2) + `plans.py` + `lib/plans.ts`

- **Maker tier added** ($19/mo, between Free and Starter): 5 apps,
  unlimited vibe-code scans, vibe monitoring, fix PRs, 30-day audit
  history. Proposed — validate by pilots; if it does not convert, kill
  it, do not discount Starter.
- **Free web scan cap is now 2/day** (`scans_per_day`: 2, was 10 in the
  layer model). Starter's `scans_per_day` is now unlimited (null) —
  Maker already has unlimited scans, so Starter cannot be lower.
- **New resources** (all in `plans.json`, mirrored in the `plans.py`
  fallback and `lib/plans.ts` `PlanLimits`): `audits_per_day` (Free 2,
  Maker 2, Starter+ unlimited), `mcp_queries_per_day` (Free 100,
  Maker+ unlimited), `dashboard_saves_per_day` (Free 2, Maker+
  unlimited), `shareable_reports` (Free 2, Maker+ unlimited),
  `audit_timeline_days` (Free 7, Maker/Starter 30, Team 90, Business
  2555 = 7 years, Enterprise unlimited), `seats` (Free/Maker/Starter 1,
  Team 5, Business+ unlimited), `fingerprint_checks_per_day` (Free/
  Maker 1, Starter+ unlimited).
- **New feature** `fix_prs` (Maker and up). No enforcement surface yet
  — declared only; see §7.
- **Per-resource `next_tier` + `upgrade_unlocks`** on the daily-cap
  resources, plus `daily_limit_message_template` and
  `daily_cap_suffix` ("Come back tomorrow, it works again (free caps
  reset at midnight UTC)."). `check_daily_cap` / `daily_cap_message` /
  `daily_cap_upgrade` (both sides) build the denial from these: limit
  sentence + upgrade (tier, price, unlocks) + suffix. Never a bare
  error, never a dead end.
- **Legacy note:** `scans_per_day` is now the web vibe-scan daily cap
  (label "vibe-code scans per day"). `vibe_reports` is legacy and
  superseded by `shareable_reports`; its values are kept (Free 1,
  Maker/Starter 5, Team+ unlimited) and nothing enforces it.

### CLI daily counters — `plans.py`

- Local state file `.key-sentry-usage.json` next to `plans.py`
  (`{"date": "YYYY-MM-DD", "counters": {...}}`). A state file from
  another UTC date rolls over to empty counters — the midnight-UTC
  reset. `utc_today(now)` accepts a fake date for tests.
- `daily_used(resource)`, `record_daily_use(resource)`,
  `check_daily_cap_today(plan, resource)` (allowed when used < limit),
  `format_counter(used, limit, label, plan_name)` — "1 of 2 free scans
  used today" — and `format_allowance` for non-daily allowances.
- `python3 plans.py counters` prints today's counters for the local
  plan. `plans.py show` is unchanged.
- Per-fingerprint counters use the key `fingerprint_check:<16-hex>`.

### `fingerprint_watch.py` `check` — ALREADY WIRED (this build)

- After the existing >5 plan gate: the watched list is split into
  fresh vs already-checked-today (`_split_daily_fingerprint_checks`).
  A re-check prints the daily-cap prompt (Starter, $49/mo, automatic
  fingerprint monitoring) + "come back tomorrow, it works again", and
  the match results still display for every watched fingerprint.
- Fresh checks are recorded only for non-dry runs — `--dry-run` is a
  preview and consumes nothing, so the existing dry-run tests are
  unaffected and no state file is written by them.
- Counter line on every check: "fingerprint checks today: N of M
  fingerprint(s) checked (1x/day each on Free)."

### `mcp_server.py` — ALREADY WIRED (this build)

- 100/day query counter in a local daily state file
  `.key-sentry-mcp-usage.json` (same `{"date", "queries"}` shape,
  UTC-day rollover). Limit comes from `plans.py` when importable
  (Maker+: unlimited), else the Free fallback of 100. `--usage-file`
  (or `KEYSENTRY_MCP_USAGE_FILE`) points the counter at another file
  — tests should use it so the repo-root counter is not touched
  (see §7 follow-up: `test_agents.py`'s `_spawn_server` does not pass
  it yet, so a full pytest run writes 4 queries to the repo-root
  file; harmless — under the cap, rolls over tomorrow — but the file
  should be gitignored with the other `.key-sentry-*.json` state).
- Enforced in `call_tool` (known tools only — `initialize`,
  `tools/list`, `ping` are not queries). Every tool result carries
  `"usage": {"queries_used_today": N, "queries_limit_per_day": 100}`.
  The 101st query returns an error naming Maker ($19/mo) + "come
  back tomorrow, it works again", with the usage metadata intact
  (`handle_request` now dumps the full result dict for tool errors,
  not just the error string).
- `python3 mcp_server.py --selftest` covers the quota (100 allowed,
  101st errors, rollover).

### Web enforcement — `lib/usage.ts` + `lib/plan-enforcement.ts`

- `lib/usage.ts`: `USAGE_KEY_VIBE_SCANS` / `USAGE_KEY_DASHBOARD_SAVES`
  / `USAGE_KEY_AUDITS`; `scopeKeyForRequest(req)` → `ip:<sha256-16 of
  the client IP>` (a raw IP is NEVER stored — see
  `hashClientIp` in `lib/usage-policy.ts`); `getDailyCount` /
  `recordDailyCount` / `getDailyCounts` — Postgres `usage_counters`
  first, process-local in-memory fallback when no DB is configured
  (same caveat as `lib/rate-limit.ts`: resets on cold start).
- `lib/plan-enforcement.ts`: `resolveWorkspacePlanId()` (any failure
  → Free) and `enforceDailyCap(workspace, plan, resource,
  counterKey)` — reads the count, never records; returns
  `{allowed, limit, used, resetsAt, message, upgrade}`.
- `lib/usage-policy.ts` (pure, plain-node importable — extended by
  this build because the caps tests need to import the helpers, per
  that file's own convention): `hashClientIp`, `resetsAtUtc`,
  `MemoryDailyCounters` (+ the `memoryDailyCounters` singleton),
  `capHitResponse` (429 with `{error, used, limit, resetsAt,
  upgrade}` + `Retry-After` to midnight UTC).
- Routes:
  - `POST /api/vibe-scan`: 2/day scan cap + 2/day dashboard-save cap
    (one web operation = one scan + one save, so both counters move
    together, recorded only after the save succeeds). 429 on a hit.
    Success response carries `usage.vibe_scans` /
    `usage.dashboard_saves` (`{used, limit, resetsAt}`). The old
    10/day `KEYSENTRY_MAX_VIBE_SCANS_PER_DAY` env override is gone —
    the limit now comes from the plan.
  - `POST /api/agents`: 2/day audit cap (Starter: unlimited).
    429 on a hit; 201 carries `usage.audits`.
  - `GET /api/audit`: free restriction — one agent (the newest
    event's agent) + last 7 days; paid tiers use their own limits.
    Response is `{events: <allowed subset>, restricted:
    {allowedAgent, windowDays, excludedAgents, excludedOlder},
    upgrade: <prompt or null>}`. A 2nd agent names Team ($149/mo,
    full timeline); older events only name Maker ($19/mo, 30 days).
  - `GET /api/vibe-scan` (new list endpoint): latest 2 reports per
    type on Free (`latestReportsForPlan`, `lib/plans.ts`); the SELECT
    lives in the route file because `lib/vibe-reports-db.ts` is
    outside this build's ownership — the coordinator can move it into
    a `listVibeReports()` helper there later. Direct GET by id is a
    separate, unmodified route: links stay live.
  - `GET /api/cron/sweep`: skips free workspaces entirely (no
    auto-monitoring on Free) and returns the standard zeroed summary
    shape plus `skippedFree: true`, the reason, and the Starter
    upgrade prompt.
  - `GET /api/usage/counters` (new): today's used/limit per resource
    for the workspace or hashed IP; no auth needed for anonymous.
    `mcp_queries.used` is null — the MCP server counts locally and
    the web app cannot see those queries.
  - `lib/alerts.ts`: free workspaces get no email/Slack alerts.
    `sendMatchAlert(match, plan?)` resolves the plan when omitted
    (Free on any failure) and, on Free, logs a would-have-alerted
    note (function log: fingerprint + provider + location + upgrade
    prompt) and returns false — the match is still recorded,
    `alerted` is false. The matches route was NOT edited (outside
    this build's ownership); it calls `sendMatchAlert(match)` with no
    plan, so the gate currently resolves the plan itself — the route
    can pass the resolved plan later for one fewer DB read.

### Counter display — `app/components/CounterBadge.tsx`

- "1 of 2 free scans used today" (via `formatCounter` /
  `formatAllowance` in `lib/plans.ts` — same wording as the CLI).
- Wired into `app/vibe/page.tsx` (scans badge + upgrade note on a
  429), `app/agents/page.tsx` (audits badge), `app/audit/page.tsx`
  (timeline allowance badge: "1 of 1 agents on the audit timeline ·
  Last 7 days of events" + upgrade note), and the `app/page.tsx`
  banner area (scans + audits + dashboard saves row under the
  upgrade banner). All fetches are best-effort: a failed counters
  fetch hides the badges, never an error.

## 2. Per-resource next-tier choices (every one, with the reason)

| Resource (cap hit on Free) | Next tier | Price | Unlocks copy | Why this tier |
|---|---|---|---|---|
| `scans_per_day` (2/day) | Maker | $19/mo | unlimited vibe-code scans | Doc: "Maker: unlimited scans". Maker is the vibe-coder tier. |
| `mcp_queries_per_day` (100/day) | Maker | $19/mo | unlimited MCP server queries | Vibe/agent surface → Maker (task mapping). |
| `dashboard_saves_per_day` (2/day) | Maker | $19/mo | unlimited dashboard saves | Same save surface as scans → Maker. |
| `shareable_reports` (latest 2) | Maker | $19/mo | unlimited shareable reports | Report surface → Maker. |
| `audits_per_day` (2/day) | Starter | $49/mo | unlimited agent identity audits | Doc: "Starter: unlimited audits". Maker keeps 2/day. |
| `fingerprint_checks_per_day` (1×/day each) | Starter | $49/mo | automatic fingerprint monitoring — re-checks as often as you like | Re-checks are monitoring; monitoring lifts at Starter. |
| `fingerprints` (5 total) | Starter | $49/mo | fingerprint monitoring | Layer-model route, unchanged. |
| `audit_timeline_days` (7) | Maker (Free) / Team (Maker) | $19 / $149 | up to 30 / 90 days of audit history | Dynamic: next tier that raises the day limit. Beyond 30 days → Team (90d) / Business (7y), per the task mapping. |
| `audit_timeline_agents` (1) | Team | $149/mo | the full audit timeline for every agent, not just one | Only Team+ has `full_audit_timeline`. |
| `seats` (1) | Team | $149/mo | 5 team seats | Task mapping. Team seats = 5 is a starting proposal, not in the caps doc — validate. |
| `repos` (1) | Maker | $19/mo | up to 5 repos | Dynamic: first tier above Free with more repos. |
| `vibe_reports` (legacy, 1) | Maker | $19/mo | up to 5 vibe-code reports | Dynamic; legacy, superseded by `shareable_reports`. |

## 3. Insertion points in `aiscan.py` (for the coordinator)

`plans.py` is already imported best-effort as `_plans` in `aiscan.py`
(same pattern as `fingerprint_watch.py`). Every snippet below prints
the prompt and keeps the free capability working — never a silent
block, never a dead end. Guard every use with `if _plans is None`
(the CLI must still run if `plans.py` is absent).

### 1. `plan counters` subcommand — `build_parser()`, line 992

After the `plan` group (`plan_p = sub.add_parser("plan", ...)` at
line 992; `plan_show` / `plan_set` wired at lines ~995–1001, via
`cmd_plan_show` at line 799 which delegates to `_plans.main`):

```python
plan_counters = plan_sub.add_parser("counters", help="print today's "
                                    "daily-cap counters")
plan_counters.set_defaults(func=lambda args: _plans.main(["counters"]))
```

`plans.py counters` already exists (prints "N of M free scans used
today" for the local plan). No new `plans.py` work needed.

### 2. Counter display after a local scan — `cmd_scan_local()`, line 468

Local scans are UNLIMITED (they run on the user's machine) — there
is no gate here and no scan counter to show. The cap that applies to
a scan is the **dashboard save** (2/day), and `aiscan.py` has no
dashboard-save path today (no POST to `/api/vibe-scan`, no
`--dashboard` flag — verified by grep). When that flag lands, gate
it at the save point (after `_emit(...)`, lines 508–510, before the
function returns at line ~513):

```python
if getattr(args, "dashboard", False) and _plans is not None:
    _plan_id = _plans.load_local_plan()
    _allowed, _msg, _used, _limit = _plans.check_daily_cap_today(
        _plan_id, "dashboard_saves_per_day")
    if not _allowed:
        print(_msg)  # upgrade prompt; the local scan result still stands
    else:
        _plans.record_daily_use("dashboard_saves_per_day")
        print(_plans.format_counter(_used + 1, _limit, "dashboard saves"))
        # ... POST the result to /api/vibe-scan here ...
```

Until that flag exists, print nothing extra in `cmd_scan_local` —
the unlimited local scan is the product promise, not a cap to
display.

### 3. Counter display after inventory / mapping — `cmd_agents_inventory()`, line 725, and `cmd_agents_map()`, line 756

These produce the JSON that gets POSTed to `/api/agents` — the
Agent Identity Audit, capped at 2/day on Free and enforced
server-side. The CLI cannot know the server-side count, so the
display fetches it (best-effort, never fatal) after the summary
print. In `cmd_agents_inventory`, after the summary `print` at line
739 (and before the per-agent loop); in `cmd_agents_map`, after the
summary `print` at line 766. Same snippet in both, with the local
plan for the limit:

```python
if _plans is not None:
    import urllib.request  # stdlib only, same as fingerprint_watch.py
    try:
        with urllib.request.urlopen(
                f"{_web_base_url()}/api/usage/counters",
                timeout=5) as resp:
            _counters = json.loads(resp.read().decode("utf-8"))
        _audits = _counters["counters"]["audits"]
        print("  " + _plans.format_counter(
            _audits["used"], _audits["limit"], "audits"))
        if _audits["used"] >= (_audits["limit"] or 0):
            print("  " + _plans.daily_cap_message(
                _plans.load_local_plan(), "audits_per_day",
                _audits["used"]))
    except Exception:
        pass  # counters endpoint unreachable: inventory still prints
```

`_web_base_url()` does not exist yet — the coordinator adds it
(`KEYSENTRY_URL` env, default `https://key-sentry-inky.vercel.app`,
same as `fingerprint_watch.py base_url()`). The `--json` paths
(lines 736–738 and 763–765) print machine-readable output and must
NOT gain a counter line — the counter goes to stderr there, or is
skipped for `--json`.

## 4. What is enforced, and what is "no surface yet"

| Cap (FREE-TIER-CAPS.md) | Status | Where |
|---|---|---|
| Web repo scan 2/day | Enforced | `POST /api/vibe-scan` (plan-driven, hashed-IP scope) |
| Agent Identity Audit 2/day | Enforced | `POST /api/agents` (plan-driven, hashed-IP scope) |
| Fingerprints 5 total | Enforced (pre-existing) | `fingerprint_watch.py check` >5 gate + web fingerprints route |
| Fingerprint 1×/day each, manual only | Enforced (CLI) | `fingerprint_watch.py check` (this build); web has no per-check surface |
| Audit timeline 1 agent + 7 days | Enforced | `GET /api/audit` restriction (subset + prompt) |
| MCP queries 100/day | Enforced (CLI) | `mcp_server.py` quota |
| CLI local scans unlimited | Enforced by design | No gate in `cmd_scan_local`; see §3.2 |
| Dashboard saves 2/day | Enforced (web); **no surface yet (CLI)** | Web `POST /api/vibe-scan`; no CLI command POSTs scan results to the dashboard — see §3.2 |
| Shareable reports latest 2/type, links live | Enforced | `GET /api/vibe-scan` list; direct GET by id untouched |
| GitHub Action unlimited on public repos | Enforced by design (nothing to cap) | CLI just runs |
| GitHub Action dashboard history, latest run only | **No surface yet** | No Action-runs table or endpoint exists; nothing records Action runs in the dashboard today |
| Email/Slack alerts: none on free | Enforced | `lib/alerts.ts` gate (suppressed + would-have-alerted log) |
| Team seats 1 user | **No surface yet** | No accounts / team invites exist; the limit is defined in `plans.json` (1 free / 5 team) and will bind when seats land |
| Anonymous 2/day web caps, hashed IP | Enforced | `scopeKeyForRequest` + `hashClientIp` (SHA-256 first 16 hex); no raw IP is stored anywhere |
| Free account keeps the same caps | Enforced by design | No account system exists; the counters endpoint and all caps are plan-based, not account-based |
| Fix PRs (Maker) | **No surface yet** | Feature declared in `plans.json` only; no PR-creation code exists |

## 5. How to verify

```bash
# CLI
cd ~/workspace/ai-key-scanner
python3 -m pytest tests/test_caps.py tests/test_plans.py -q
python3 plans.py counters
python3 mcp_server.py --selftest
python3 fingerprint_watch.py selftest

# Web
cd ~/workspace/key-sentry
node tests/caps.test.mjs
node tests/plans.test.mjs
npm run build
npm test
```

Live checks (need the deployed app + a database; not run in this
build): 3rd vibe scan in a day → 429 with
`{used: 2, limit: 2, resetsAt, upgrade: {tier: "Maker", price:
"$19/mo"}}` and "come back tomorrow, it works again"; `GET
/api/usage/counters` shows "1 of 2 free scans used today" after one
scan; `GET /api/vibe-scan` shows the latest 2 reports while
`/api/vibe-scan/<id>` still returns a rolled-off one.
