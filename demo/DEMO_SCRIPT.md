# aiscan — Live Business Demo Script

Presenter guide for showing the AI API leaked-key scanner to business users.
Runtime: ~10 minutes. Nothing on screen ever shows a full key (masked form
only), and verification is read-only and only ever runs on keys the
presenter owns.

## Setup (before the audience arrives)

1. `cd` into the project directory.
2. Optional but recommended for Step 2: export a GitHub personal access
   token (classic, no scopes needed for public code search):
   `export GITHUB_TOKEN=ghp_...`
   Without it, Step 2 falls back to the bundled fake dataset.
3. Run `./demo/run_demo.sh` (or `bash demo/run_demo.sh`).

## Step 1 — Business mode: scan your own code (2 min)

**Say:** "This is the mode a team plugs into their own repos. It scans the
working tree — and, with one flag, the whole git history, because deleting
a file does not delete the secret from history."

**Run:** `python3 aiscan.py scan local tests/fixtures`

**Audience should see:** 16 findings across 12+ providers, each masked
(`sk-proj-...a9b0`), with file and line. Point out:
- The `.mcp.json` hits — AI agent configs are a new leak surface.
- The `.env` hits — Mistral, Together and Cohere caught by entropy, not
  by a fixed prefix.
- The decoys file produced zero findings — UUIDs, hashes and
  `your-api-key-here` are not flagged.

**Then:** `python3 aiscan.py scan local tests/fixtures --format md --output demo/last-demo-report.md`

**Say:** "Every finding ships with remediation: revoke at the provider
console, purge git history, move the secret to env vars, enable push
protection." Open the Markdown report and show the checklist.

## Step 2 — Metrics: how reliable is the detector? (3 min)

**Say:** "Before you trust a scanner, ask for its numbers. Here is the
precision/recall scorecard on planted fixtures — and the same metrics
block on a bounded live source, so you see the counts, not just claims."

**Run:** `python3 aiscan.py metrics`

**Audience should see:** Expected 16, got 16, recall 100%, precision
100%, decoy hits 0 — plus the run metrics (items/lines/bytes scanned,
candidates, duplicates removed, findings by provider and severity).

**Then, live:** `python3 aiscan.py scan dockerhub --query hello-world --max-images 1`

**Say:** "Same engine, one public Docker Hub image. Watch the Metrics
block at the end: items scanned, candidates, findings by provider, API
requests, rate-limit events. That block is what a business user gets
after every scan — detection counts, from where, of which providers."

## Step 3 — Internet mode: live GitHub code search (3 min)

**Say:** "Same engine, public sources. This is how you answer: is one of
our keys already out there? You search for your own key fingerprint,
prefix, or org name — the tool never invents a query."

**Run:** `GITHUB_TOKEN=... python3 aiscan.py scan internet --query "sk-or-v1-" --max-pages 1`

**Audience should see:** live results flowing through the same pipeline —
detectors, classification, dedup, redaction. Verification stays OFF:
nobody's key is tested without authorization.

**If there is no token:** the script runs `scan internet --demo` instead
and says so on screen — the bundled fake dataset demonstrates the same
flow with no credentials and no network.

**If GitHub rate-limits (30 code-search requests/min):** the scanner
backs off and says so instead of crashing. Mention this if it happens —
it is a feature, not a failure.

## Step 4 — The honeytoken: plant your own canary (5 min, the closer)

This is the reliable, repeatable live demo. It does not depend on
strangers' keys existing.

**Before the demo (or live, if you have time):**
1. Create a throwaway API key at any provider (or use a clearly fake
   canary string shaped like a key, e.g. an OpenRouter-style prefix you
   control). If it is a real key, set its permissions to minimum and
   plan to revoke it right after the demo.
2. Commit it to a **public repository you control** in a visible file
   (e.g. `canary.txt`), push, and wait a few minutes for GitHub's code
   search index to pick it up.
3. Live on stage, run:
   `python3 aiscan.py scan internet --query "<your canary prefix>" --max-pages 1`
4. The audience watches the scanner find the canary in your repo, masked.
5. **Immediately revoke/rotate the canary key** and show the revocation
   page. Say: "From commit to detection took minutes. That is the window
   you are defending."

**Say at the close:** "A leaked AI key is usually spent within minutes,
and most leaked keys are still valid years later. This tool finds them
before the people who would spend them do — and tells you exactly how to
kill each one."

## Safety lines (say at least once)

- "Keys on screen are always masked. The full key never appears in any
  output file."
- "Verification is read-only — a model-list probe, never a generation
  call — and only for keys we own."
- "Internet mode searches for patterns you supply. It does not sweep
  arbitrary public keys."
