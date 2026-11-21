#!/usr/bin/env bash
# aiscan live demo — runs the demo steps in sequence.
# Usage: bash demo/run_demo.sh
#   DEMO_NOPAUSE=1  skip the "press Enter" pauses (e.g. for CI)
#   DEMO_QUERY="..." override the live internet query (default: sk-or-v1-)
set -u
cd "$(dirname "$0")/.."

pause() {
  if [ -z "${DEMO_NOPAUSE:-}" ]; then
    read -r -p "Press Enter to continue... " _ || true
  fi
}

echo "=================================================================="
echo " aiscan — AI API leaked-key scanner: live demo"
echo " Keys are shown MASKED only. Verification is read-only and only"
echo " ever runs on keys you own. Internet mode searches only for the"
echo " pattern you supply."
echo "=================================================================="
echo

echo "### Step 1 — Business mode: scan your own code (sample repo)"
echo "Command: python3 aiscan.py scan local tests/fixtures"
echo
python3 aiscan.py scan local tests/fixtures
echo
echo "What you just saw: 16 findings across 12+ AI providers, decoys"
echo "ignored, every key masked. Now the remediation report:"
python3 aiscan.py scan local tests/fixtures --format md \
  --output demo/last-demo-report.md
echo "(Markdown remediation report: demo/last-demo-report.md)"
pause
echo

echo "### Step 2 — Metrics: how reliable is the detector?"
echo "Command: python3 aiscan.py metrics"
echo
python3 aiscan.py metrics
echo
echo "That is the precision/recall scorecard on planted fixtures: 100%"
echo "recall, 100% precision, zero decoys flagged. Now the same metrics"
echo "on a bounded LIVE source — one public Docker Hub image:"
echo "Command: python3 aiscan.py scan dockerhub --query hello-world --max-images 1"
echo
python3 aiscan.py scan dockerhub --query hello-world --max-images 1
echo
echo "Watch the Metrics block at the end: items scanned, candidates,"
echo "findings by provider, API requests, rate-limit events — the numbers"
echo "you would show a business user."
pause
echo

echo "### Step 3 — Internet mode: live GitHub code search"
if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "No GITHUB_TOKEN set — running the bundled FAKE demo dataset instead"
  echo "(set GITHUB_TOKEN to run a real live search)."
  echo "Command: python3 aiscan.py scan internet --demo"
  echo
  python3 aiscan.py scan internet --demo
else
  QUERY="${DEMO_QUERY:-sk-or-v1-}"
  echo "Command: python3 aiscan.py scan internet --query \"$QUERY\" --max-pages 1"
  echo "(Verification stays OFF — no key is tested.)"
  echo
  python3 aiscan.py scan internet --query "$QUERY" --max-pages 1
fi
pause
echo

echo "### Step 4 — Honeytoken (presenter-led)"
echo "To close the demo live: plant a canary key in a public repo YOU"
echo "control, run:"
echo "  python3 aiscan.py scan internet --query \"<your canary prefix>\""
echo "watch it get found, then REVOKE the canary immediately."
echo "Full instructions: demo/DEMO_SCRIPT.md (Step 4)."
echo
echo "Demo complete."
