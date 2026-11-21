#!/usr/bin/env python3
"""Retry the three patterns that failed with transient network errors in
trial 3, and merge any new findings into results/TRIAL_RUN_3.json/.md.

Token from env only; never written, printed, or included in any output.
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

RETRY = [
    ("groq", "gsk_", 3, 90),
    ("perplexity", "pplx-", 3, 90),
    ("mcp-preset", 'filename:.mcp.json "sk-"', 3, 90),
]


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is not set.", file=sys.stderr)
        return 2
    with open(JSON_PATH, encoding="utf-8") as f:
        result = json.load(f)
    seen = {f["fingerprint_sha256_16"] for f in result["findings"]}
    for label, query, max_pages, max_items in RETRY:
        m, findings, status, note = trial_run3._run_pattern(
            label, query, token, max_pages, max_items)
        print(f"[{status}] {label} (q={query!r}): {m['findings']} findings, "
              f"{m['items_scanned']} items, {m['api_requests']} API calls"
              + (f" — {note}" if note else ""), file=sys.stderr)
        # Replace the old per-pattern entry with the retry outcome.
        result["per_pattern"] = [
            e for e in result["per_pattern"] if e["pattern"] != label]
        result["per_pattern"].append({
            "pattern": label, "query": query, "status": status,
            "metrics": m,
            "findings": [f.public_dict() for f in findings],
            "note": note + (" (retry)" if note else "retry"),
        })
        new = 0
        for f in findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                result["findings"].append(f.public_dict())
                new += 1
        print(f"  -> {new} new unique findings", file=sys.stderr)
        time.sleep(2)
    # Recompute aggregate.
    unique = result["findings"]
    result["aggregate"] = {
        "total_findings_before_dedup": len(unique),
        "total_findings_after_dedup": len(unique),
        "cross_pattern_duplicates": 0,
        "live_detections": len(unique),
        "by_provider": dict(Counter(f["provider"] for f in unique)),
        "by_source": dict(Counter(f["source"] for f in unique)),
        "by_severity": dict(Counter(f["severity"] for f in unique)),
    }
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    with open(MD_PATH, "w", encoding="utf-8") as f:
        f.write(trial_run3.render_markdown(result))
    print(f"\nLIVE DETECTIONS (after retry): "
          f"{result['aggregate']['live_detections']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
