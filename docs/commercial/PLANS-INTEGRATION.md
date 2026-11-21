# PLANS-INTEGRATION.md — wiring `plans.py` into `aiscan.py`

Short doc for the coordinator: `plans.py` (CLI plan definitions) is
built and importable, but `aiscan.py` is NOT edited by the Layer Model
build (another agent owns it). These are the exact insertion points
where the coordinator applies the wiring. Line numbers are for the
`aiscan.py` in the repo at the time of writing (Nov 21, 2026) — verify
them before editing; the anchors (function names) are stable.

## What already exists

- `plans.py` — `get_plan()`, `feature_allowed(plan, feature)`,
  `check_limit(plan, resource, used) -> (allowed, message)`,
  `upgrade_message(plan, feature)`, `load_local_plan()` (reads
  `.key-sentry-plan.json`, defaults to Free). Import it at the top of
  `aiscan.py` with a best-effort guard, exactly like
  `fingerprint_watch.py` does:
  ```python
  try:
      import plans as _plans
  except ImportError:
      _plans = None
  ```
- `fingerprint_watch.py` `check` — ALREADY WIRED (this build): `--plan`
  flag + plan gate that prints the upgrade prompt and still checks the
  first N fingerprints. Pattern to copy for the points below: gate,
  print the prompt, keep the free capability working — never a silent
  block, never a dead end.

## Insertion points in `aiscan.py`

### 1. `plan` subcommand — `build_parser()`, line 802

Add after the `agents` group ends and before the `metrics` parser
(line 931: `mt = sub.add_parser("metrics", ...)`):

```python
plan_p = sub.add_parser("plan", help="Show or set the local plan "
                        "(dev/testing only; real plan state comes "
                        "from billing)")
plan_sub = plan_p.add_subparsers(dest="plan_cmd", required=True)
plan_show = plan_sub.add_parser("show", help="print the current plan "
                                "+ limits")
plan_show.set_defaults(func=lambda args: _plans.main(["show"]))
plan_set = plan_sub.add_parser("set-plan", help="set the local dev plan")
plan_set.add_argument("tier", choices=["free", "starter", "team",
                     "business", "enterprise"])
plan_set.set_defaults(func=lambda args: _plans.main(["set-plan", args.tier]))
```

Guard every use with `if _plans is None: print(...); return 2` — the
CLI must still run if `plans.py` is absent.

### 2. One-repo scan gate — `cmd_scan_local()`, line 463

After the path check (`if not os.path.exists(args.path)`, lines
464–466), before `metrics = RunMetrics(...)` (line 469):

```python
plan = _plans.load_local_plan() if _plans else "free"
allowed, msg = _plans.check_limit(plan, "repos", 1)  # one repo per run
if not allowed:
    print(msg)  # upgrade prompt; the scan still runs — Free includes 1 repo
```

Free includes 1 repo, so this gate only fires for future multi-repo
runs. Do NOT block the scan on a denied check: print the prompt and
continue.

### 3. Agent inventory / mapping gates — `cmd_agents_inventory()`, line 700, and `cmd_agents_map()`, line 729

Pillar 1 paid boundary: the full agent → credential → repo → owner
mapping across many repos is Team; the one-repo inventory is Free.

- In `cmd_agents_inventory`, before scanning: check
  `feature_allowed(plan, "full_audit_timeline")` is NOT the gate —
  inventory itself stays free. Gate the *multi-repo* form only (when a
  future `--repos` / multi-path flag lands): print
  `upgrade_message(plan, "full_audit_timeline")` and continue with the
  first repo.
- In `cmd_agents_map`, before emitting the mapping: if the mapping
  spans more than 1 repo, print
  `upgrade_message(plan, "full_audit_timeline")` and emit the first
  repo's mapping only.

### 4. Vibe-code report gate — `vibe_scan.py`, `main()`, line 263

Owned by the Pillar 2 agent — do NOT edit here, document only. When
that agent wires it: after `scan_repo()` returns, count reports with
`check_limit(plan, "vibe_reports", n_reports)`. Free allows 1
one-repo report; over that, print the prompt from
`upgrade_message(plan, "vibe_monitoring")` and still emit the first
report.

### 5. MCP server — `mcp_server.py` — NO GATE

Read-only queries ("are my keys exposed?", "what do I own?") are Free
by design (`mcp_read_only` in plans.json). Nothing to wire; the audit
events the server emits are the Pillar 3 trail, not a paid gate.

## Web side (already wired by this build)

- `lib/plans.ts` + `lib/plan-enforcement.ts` (wraps `lib/usage.ts`),
  `lib/billing.ts` (Stripe stub), `lib/billing-db.ts`
  (`workspace_plans`), routes under `app/api/billing/`
  (checkout / webhook / plan), `app/components/UpgradeBanner.tsx`
  wired into `app/page.tsx` when the workspace plan is Free.
- Sync rule: edit `docs/commercial/plans.json`, then run
  `python3 scripts/sync_plans.py` — `key-sentry/lib/plans.json` is
  generated, never hand-edited. `tests/test_plans.py` fails on drift.

## Rules for every gate (both sides)

1. Unknown/missing plan state defaults to Free; free features work.
2. A denied commercial feature prints/shows an upgrade prompt naming
   the next tier + price + what it unlocks — never a crash, never a
   silent block, never a dead end.
3. The free capability that was already working keeps working at its
   free limit (e.g. first 5 fingerprints, first repo, first report).
