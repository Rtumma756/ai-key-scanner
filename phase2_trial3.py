#!/usr/bin/env python3
"""Phase 2 of trial 3: deeper pages + filename-qualified queries, aiming to
push the REAL-LOOKING live count to 10+ (phase 1 found 21 total candidates
but only 8 real-looking; the rest are README/SETUP placeholders).

New angles:
  - Deeper pages (4-6) of the two highest-yield patterns (sk-proj-,
    sk-ant-api03-) via GitHubSource start_page.
  - Filename-qualified searches (.env / config / .py / .js) which surface
    real committed keys rather than documentation examples.
  - One more retry of the mcp preset (failed twice on transient errors).

Token from env only; never written, printed, or included in any output.
Merges into results/TRIAL_RUN_3.json/.md and recomputes the aggregate
(including the placeholder/real-looking split).
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import trial_run3  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(ROOT, "results")
JSON_PATH = os.path.join(RESULTS_DIR, "TRIAL_RUN_3.json")
MD_PATH = os.path.join(RESULTS_DIR, "TRIAL_RUN_3.md")

# (label, query, max_pages, max_items, start_page)
PHASE2 = [
    ("openai-project-p4-6", "sk-proj-", 3, 90, 4),
    ("anthropic-p4-6", "sk-ant-api03-", 3, 90, 4),
    ("dotenv-openai", 'filename:.env "sk-proj-"', 3, 90, 1),
    ("dotenv-anthropic", 'filename:.env "sk-ant-api03-"', 3, 90, 1),
    ("dotenv-groq", 'filename:.env "gsk_"', 3, 90, 1),
    ("dotenv-gemini", 'filename:.env "AIza"', 2, 60, 1),
    ("py-openai", 'extension:py "sk-proj-"', 3, 90, 1),
    ("js-anthropic", 'extension:js "sk-ant-api03-"', 2, 60, 1),
    ("config-openai", 'filename:config.py "sk-proj-"', 2, 60, 1),
    ("mcp-preset-retry", 'filename:.mcp.json "sk-"', 3, 90, 1),
]


def recompute(result: dict) -> None:
    findings = result["findings"]
    n_placeholder = sum(
        1 for f in findings if trial_run3._is_placeholder_shaped(f))
    result["aggregate"] = {
        "total_findings_before_dedup": len(findings),
        "total_findings_after_dedup": len(findings),
        "cross_pattern_duplicates": 0,
        "live_detections": len(findings),
        "placeholder_shaped": n_placeholder,
        "real_looking": len(findings) - n_placeholder,
        "by_provider": dict(Counter(f["provider"] for f in findings)),
        "by_source": dict(Counter(f["source"] for f in findings)),
        "by_severity": dict(Counter(f["severity"] for f in findings)),
    }


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is not set.", file=sys.stderr)
        return 2
    with open(JSON_PATH, encoding="utf-8") as f:
        result = json.load(f)
    seen = {f["fingerprint_sha256_16"] for f in result["findings"]}
    for label, query, max_pages, max_items, start_page in PHASE2:
        m, findings, status, note = trial_run3._run_pattern(
            label, query, token, max_pages, max_items,
            start_page=start_page)
        print(f"[{status}] {label} (q={query!r} p{start_page}): "
              f"{m['findings']} findings, {m['items_scanned']} items, "
              f"{m['api_requests']} API calls"
              + (f" — {note}" if note else ""), file=sys.stderr)
        result["per_pattern"] = [
            e for e in result["per_pattern"] if e["pattern"] != label]
        result["per_pattern"].append({
            "pattern": label, "query": query, "status": status,
            "metrics": m,
            "findings": [f.public_dict() for f in findings],
            "note": note,
        })
        new = 0
        for f in findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                result["findings"].append(f.public_dict())
                new += 1
        print(f"  -> {new} new unique findings", file=sys.stderr)
        time.sleep(2)
    recompute(result)
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    with open(MD_PATH, "w", encoding="utf-8") as f:
        f.write(trial_run3.render_markdown(result))
    agg = result["aggregate"]
    print(f"\nLIVE DETECTIONS: {agg['live_detections']} "
          f"(real-looking: {agg['real_looking']}, "
          f"placeholder-shaped: {agg['placeholder_shaped']})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
