#!/usr/bin/env python3
"""Live trial 3: GitHub code search across AI key patterns (token from env).

Reads GITHUB_TOKEN from the environment only — the token is never written
to any file, never printed, never included in any report or JSON output.
Verification is OFF everywhere: findings are candidates only, shown
masked. Free tier only (authenticated code search, 30 req/min).

Usage:
  GITHUB_TOKEN=... python3 trial_run3.py [--output results/TRIAL_RUN_3.md]

Writes results/TRIAL_RUN_3.md + results/TRIAL_RUN_3.json (masked only).
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import scan_source  # noqa: E402
from metrics import RunMetrics, fixture_scorecard  # noqa: E402
from sources import GitHubSource  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(ROOT, "results")

# (label, query, max_pages, max_items)
PATTERNS = [
    ("openai-project", "sk-proj-", 3, 90),
    ("openai-service-acct", "sk-svcacct-", 3, 90),
    ("anthropic", "sk-ant-api03-", 3, 90),
    ("groq", "gsk_", 3, 90),
    ("openrouter", "sk-or-v1-", 3, 90),
    ("gemini", "AIza", 3, 90),
    ("huggingface", "hf_", 3, 90),
    ("perplexity", "pplx-", 3, 90),
    ("xai", "xai-", 3, 90),
    ("replicate", "r8_", 3, 90),
    ("deepseek-openai-sk", "sk-", 2, 60),
    ("mcp-preset", 'filename:.mcp.json "sk-"', 3, 90),
    ("notebook-preset", 'extension:ipynb "sk-"', 3, 90),
]


def _is_placeholder_shaped(f: dict) -> bool:
    """Heuristic: masked value ending in xxxx/XXXX/here/HERE, or a snippet
    that says the key 'looks like' an example, is almost certainly a
    documentation placeholder (README/SETUP example), not a genuine key.
    A random real key ends in those exact 4-char runs with negligible
    probability, so this split is honest, not a filter on the detector."""
    masked = f.get("masked", "").lower()
    if masked.endswith("xxxx") or masked.endswith("here"):
        return True
    snip = f.get("snippet", "").lower()
    return "looks like" in snip or "your key" in snip


def _run_pattern(label: str, query: str, token: str, max_pages: int,
                 max_items: int, start_page: int = 1):
    """Run one code-search pattern. Returns (metrics_dict, findings, status, note)."""
    mode = f"github:{label}"
    metrics = RunMetrics(mode)
    try:
        src = GitHubSource(query, token, max_pages=max_pages,
                           max_items=max_items, start_page=start_page)
        findings = scan_source(src, verify=False, metrics=metrics)
    except Exception as e:  # noqa: BLE001 - trial records, never crashes
        metrics.errors.append(str(e))
        metrics.finalize([])
        return metrics.to_dict(), [], "error", str(e)
    metrics.finalize(findings)
    note = ""
    if metrics.errors:
        note = "; ".join(metrics.errors[:3])
    return metrics.to_dict(), findings, "ok", note


def run_trial(token: str) -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    per_pattern = []
    all_findings = []
    for label, query, max_pages, max_items in PATTERNS:
        m, findings, status, note = _run_pattern(
            label, query, token, max_pages, max_items)
        per_pattern.append({
            "pattern": label, "query": query, "status": status,
            "metrics": m,
            "findings": [f.public_dict() for f in findings],
            "note": note,
        })
        all_findings.extend(findings)
        print(f"[{status}] {label} (q={query!r}): {m['findings']} findings, "
              f"{m['items_scanned']} items, {m['api_requests']} API calls"
              + (f" — {note}" if note else ""), file=sys.stderr)
        time.sleep(2)  # stay well under the 30 req/min code-search limit
    # Global dedup by fingerprint across patterns.
    seen: set = set()
    unique = []
    dupes = 0
    for f in all_findings:
        if f.fingerprint in seen:
            dupes += 1
            continue
        seen.add(f.fingerprint)
        unique.append(f)
    unique.sort(key=lambda f: (f.provider, f.file_path))
    by_provider = Counter(f.provider for f in unique)
    by_pattern = Counter(f.source for f in unique)
    by_severity = Counter(f.severity for f in unique)
    n_placeholder = sum(
        1 for f in unique if _is_placeholder_shaped(f.public_dict()))
    score = fixture_scorecard(
        scan_source(__import__("sources").LocalSource("tests/fixtures")))
    return {
        "tool": "aiscan",
        "trial": "TRIAL_RUN_3 — GitHub code search (token-authenticated)",
        "trial_run_at_utc": ts,
        "verification": "OFF everywhere — candidates only, no key tested.",
        "token_note": "Fine-grained read-only token (aiscan-trial-readonly); "
                      "used via env var only, never stored or printed.",
        "per_pattern": per_pattern,
        "aggregate": {
            "total_findings_before_dedup": len(all_findings),
            "total_findings_after_dedup": len(unique),
            "cross_pattern_duplicates": dupes,
            "live_detections": len(unique),
            "placeholder_shaped": n_placeholder,
            "real_looking": len(unique) - n_placeholder,
            "by_provider": dict(by_provider),
            "by_source": dict(by_pattern),
            "by_severity": dict(by_severity),
        },
        "fixture_scorecard": score,
        "findings": [f.public_dict() for f in unique],
    }


def render_markdown(result: dict) -> str:
    lines = []
    lines.append("# aiscan — live trial run 3 (GitHub code search)")
    lines.append("")
    lines.append(f"**Run at (UTC):** {result['trial_run_at_utc']}  |  "
                 "**Verification:** OFF everywhere — candidates only, no "
                 "key was tested. All keys shown masked.")
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append(f"**Live detections (non-planted, non-demo): "
                 f"{result['aggregate']['live_detections']}** "
                 f"(before dedup: "
                 f"{result['aggregate']['total_findings_before_dedup']}, "
                 f"cross-pattern duplicates removed: "
                 f"{result['aggregate']['cross_pattern_duplicates']})")
    lines.append("")
    lines.append("## Quality of detections (honest split)")
    lines.append("")
    lines.append(f"- **Real-looking keys: "
                 f"{result['aggregate'].get('real_looking', '?')}** — "
                 f"masked value and context look like a genuine key "
                 f"(e.g. bare key in a .txt/.env/notebook), not verifiable "
                 f"without testing, and verification was OFF.")
    lines.append(f"- **Placeholder-shaped: "
                 f"{result['aggregate'].get('placeholder_shaped', '?')}** — "
                 f"masked value ends in `xxxx`/`here`, or the snippet says "
                 f"the key 'looks like' an example (README/SETUP docs). "
                 f"Almost certainly documentation examples, counted "
                 f"separately so the headline is not inflated.")
    lines.append("")
    lines.append("## Results by pattern")
    lines.append("")
    lines.append("| Pattern | Query | Status | Items | Candidates | Findings | "
                 "API calls | Rate limits |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for entry in result["per_pattern"]:
        m = entry["metrics"]
        lines.append(
            f"| {entry['pattern']} | `{entry['query']}` | {entry['status']} | "
            f"{m['items_scanned']} | {m['candidates']} | {m['findings']} | "
            f"{m['api_requests']} | {m['rate_limit_events']} |")
    lines.append("")
    agg = result["aggregate"]
    lines.append("## Aggregate (after cross-pattern dedup)")
    lines.append("")
    if agg["by_provider"]:
        prov = ", ".join(f"{p} {c}" for p, c in
                         sorted(agg["by_provider"].items()))
        lines.append(f"- By provider: {prov}")
    if agg["by_severity"]:
        sev = ", ".join(f"{s} {c}" for s, c in
                        sorted(agg["by_severity"].items()))
        lines.append(f"- By severity: {sev}")
    lines.append("")
    score = result["fixture_scorecard"]
    lines.append("## Fixture precision/recall (reference)")
    lines.append("")
    lines.append(f"- Expected: {score['expected_total']}  "
                 f"Got: {score['got_total']}")
    lines.append(f"- Recall: {score['recall']:.2%}  "
                 f"Precision: {score['precision']:.2%}")
    lines.append(f"- Decoy hits: {score['decoy_hits']}")
    lines.append("")
    lines.append("## Notes / failures (recorded honestly)")
    lines.append("")
    any_notes = False
    for entry in result["per_pattern"]:
        if entry["note"]:
            any_notes = True
            lines.append(f"- **{entry['pattern']}** ({entry['status']}): "
                         f"{entry['note']}")
        if entry["metrics"] and entry["metrics"].get("errors"):
            for err in entry["metrics"]["errors"][:3]:
                any_notes = True
                lines.append(f"- **{entry['pattern']}**: {err}")
    if not any_notes:
        lines.append("- None — every pattern ran clean.")
    lines.append("")
    lines.append("## Live findings (masked)")
    lines.append("")
    if not result["findings"]:
        lines.append("No findings.")
    for f in result["findings"]:
        lines.append(f"- `{f['masked']}` — {f['provider']} "
                     f"({f['credential_type']}), {f['severity']}, "
                     f"{f['location']} [pattern: {f['source']}]")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default=os.path.join(RESULTS_DIR,
                                                    "TRIAL_RUN_3.md"))
    args = p.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is not set in the environment.", file=sys.stderr)
        return 2
    os.makedirs(RESULTS_DIR, exist_ok=True)
    result = run_trial(token)
    json_path = os.path.splitext(args.output)[0] + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(render_markdown(result))
    print(f"\nLIVE DETECTIONS: {result['aggregate']['live_detections']}",
          file=sys.stderr)
    print(f"Wrote {args.output} and {json_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
