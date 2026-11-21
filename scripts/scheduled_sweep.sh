#!/usr/bin/env bash
# scheduled_sweep.sh — KeySentry scheduled CLI sweep (business mode).
#
# Runs the three scheduled jobs that the Vercel Hobby cron cannot do
# (it is limited to one run per day and cannot run the Python CLI):
#   1. Continuous internet sweep — re-sweeps the coverage ledger's seed
#      queries on GitHub code search and alerts (masked only) on NEW or
#      ROTATED keys.
#   2. Liveness re-check — re-fetches the current file for every known
#      real-looking key and reports which are still exposed.
#   3. Fingerprint watch check — pulls the watched-fingerprint list from
#      the web app and records any sightings in it as matches
#      (POST /api/matches), so they show up in the Findings dashboard.
#
# Credentials it needs (nothing else — no provider API keys, ever):
#   GITHUB_TOKEN         GitHub token for code search (step 1). Required:
#                        the script exits 2 without it. Fine-grained token,
#                        public repos read-only is enough. Never commit it;
#                        export it in the cron environment or a secrets store.
#   KEYSENTRY_ADMIN_PASS Admin passphrase (same VAULT_ADMIN_PASS as the web
#                        app) for step 3's POST /api/matches. If unset,
#                        step 3 runs as --dry-run: matches are printed but
#                        nothing is recorded.
#   KEYSENTRY_URL        Web app base URL (optional; defaults to the live
#                        Vercel URL inside fingerprint_watch.py).
#
# Optional:
#   RESULTS_FILE         Scan-results JSON for step 3 (default: the newest
#                        results/CLASSIFY_*.json). NOTE: the continuous sweep
#                        in step 1 prints its new/rotated detections but does
#                        not yet write a results JSON, so step 3 checks the
#                        latest classified batch instead. Wiring sweep output
#                        into a JSON that `fingerprint_watch.py check` can
#                        consume is open work.
#
# Scheduling — Linux crontab (daily 02:30 UTC, after the Vercel cron):
#   30 2 * * *  cd /path/to/ai-key-scanner && GITHUB_TOKEN=<token> \
#                KEYSENTRY_ADMIN_PASS=<pass> ./scripts/scheduled_sweep.sh \
#                >> results/logs/sweep.log 2>&1
# Or GitHub Actions — see docs/commercial/SCHEDULED-SWEEPS.md for a
# ready-to-paste scheduled workflow.
#
# Exit code: 0 when every step that ran succeeded, 1 when any step
# failed, 2 when required configuration (GITHUB_TOKEN) is missing.
# Each step runs even if an earlier one failed, so one bad step does
# not silently cancel the rest; failures are listed in the summary.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failures=0

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

run_step() {
    local name="$1"
    shift
    log "step: ${name}"
    if "$@"; then
        log "ok: ${name}"
    else
        local code=$?
        log "FAILED: ${name} (exit ${code})"
        failures=$((failures + 1))
    fi
}

# --- configuration -------------------------------------------------------
if [ -z "${GITHUB_TOKEN:-}" ]; then
    log "error: GITHUB_TOKEN is not set. The continuous sweep needs a GitHub token for code search."
    log "Set it in the cron environment (fine-grained token, public repos read-only)."
    exit 2
fi

if [ -z "${KEYSENTRY_ADMIN_PASS:-}" ]; then
    log "warning: KEYSENTRY_ADMIN_PASS is not set — fingerprint matches will be dry-run only (printed, not recorded)."
    CHECK_DRY_RUN="--dry-run"
else
    CHECK_DRY_RUN=""
fi

# Newest classified batch for the fingerprint check (see header note).
RESULTS_FILE="${RESULTS_FILE:-$(ls -t results/CLASSIFY_*.json 2>/dev/null | head -n 1)}"

log "KeySentry scheduled sweep starting in ${ROOT}"

# --- step 1: continuous internet sweep ------------------------------------
# Re-sweeps the ledger's seed queries; alerts only on NEW or ROTATED keys
# (masked values + fingerprints only). Ledger: results/coverage_ledger.json.
run_step "continuous sweep" \
    python3 aiscan.py continuous sweep

# --- step 2: liveness re-check --------------------------------------------
# Re-fetches each known key's file from public GitHub (unauthenticated,
# read-only) and re-runs the detectors; a key counts as still exposed
# only if a detected value has the identical SHA-256 fingerprint.
# Writes results/FRESH_LIVENESS_ALL.md + .json. Never tests a key
# against any provider.
run_step "liveness re-check" \
    python3 fresh_liveness_all.py

# --- step 3: fingerprint watch check --------------------------------------
# Pull the watch list from the web API (hashes only), then match the
# latest classified batch against it and POST sightings to /api/matches.
if [ -n "${RESULTS_FILE}" ] && [ -f "${RESULTS_FILE}" ]; then
    run_step "fingerprint pull" \
        python3 fingerprint_watch.py pull --out fingerprints.json
    if [ -f fingerprints.json ]; then
        # shellcheck disable=SC2086 — CHECK_DRY_RUN is empty or one flag.
        run_step "fingerprint check (${RESULTS_FILE})" \
            python3 fingerprint_watch.py check ${CHECK_DRY_RUN} \
                --fingerprints fingerprints.json "${RESULTS_FILE}"
    else
        log "FAILED: fingerprint pull did not produce fingerprints.json; skipping check."
        failures=$((failures + 1))
    fi
else
    log "note: no results/CLASSIFY_*.json found — skipping fingerprint check (nothing classified to check yet)."
fi

# --- summary ---------------------------------------------------------------
if [ "${failures}" -eq 0 ]; then
    log "scheduled sweep finished: all steps ok"
    exit 0
else
    log "scheduled sweep finished: ${failures} step(s) failed"
    exit 1
fi
