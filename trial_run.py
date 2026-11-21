#!/usr/bin/env python3
"""Bounded live trial across every implemented aiscan source.

Runs each source with small caps (1 page / ~5 items), collects the same
metrics as a normal scan, and writes a results table to
``results/TRIAL_RUN.md`` (plus ``results/trial_run.json``).

Free tiers only — no paid services. GitHub code search is skipped
without GITHUB_TOKEN (recorded honestly, not faked). No verification
anywhere: findings are candidates only, shown masked.

Usage:
  python3 trial_run.py [--output results/TRIAL_RUN.md]
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import SEVERITY_RANK  # noqa: E402
from engine import scan_source  # noqa: E402
from metrics import RunMetrics, fixture_scorecard  # noqa: E402
from sources import (  # noqa: E402
    CommonCrawlSource, DemoSource, DockerHubSource, GistSource,
    LocalSource, NpmSource, PastebinSource, PypiSource,
    StackOverflowSource,
)

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(ROOT, "results")


def _run(name: str, make_source, mode: str):
    """Run one source, return (metrics_dict, findings, status, note)."""
    metrics = RunMetrics(mode)
    try:
        src = make_source()
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


def run_trial() -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    token = os.environ.get("GITHUB_TOKEN")
    trials = [
        ("local fixtures", lambda: LocalSource("tests/fixtures"),
         "local:tests/fixtures"),
        ("demo dataset", lambda: DemoSource(), "internet:demo"),
        ("dockerhub", lambda: DockerHubSource("hello-world", max_images=2),
         "dockerhub:hello-world"),
        ("gists", lambda: GistSource(token, max_gists=5), "gists:public"),
        ("npm", lambda: NpmSource("openai", max_packages=3), "npm:openai"),
        ("pypi", lambda: PypiSource("openai", max_packages=3), "pypi:openai"),
        ("pastebin", lambda: PastebinSource(max_pastes=5), "pastebin:archive"),
        ("stackoverflow",
         lambda: StackOverflowSource("OPENAI_API_KEY", max_questions=5),
         "stackoverflow:OPENAI_API_KEY"),
        ("commoncrawl",
         lambda: CommonCrawlSource("example.com/*", max_records=3),
         "commoncrawl:example.com/*"),
    ]
    per_source = []
    all_findings = []
    for name, make_source, mode in trials:
        m, findings, status, note = _run(name, make_source, mode)
        per_source.append({
            "source": name, "mode": mode, "status": status,
            "metrics": m,
            "findings": [f.public_dict() for f in findings],
            "note": note,
        })
        all_findings.extend(findings)
        print(f"[{status}] {name}: {m['findings']} findings, "
              f"{m['items_scanned']} items, {m['api_requests']} API calls"
              + (f" — {note}" if note else ""), file=sys.stderr)
    # GitHub code search: free tier needs a token; skip honestly without one.
    if token:
        m, findings, status, note = _run(
            "github code search",
            lambda: __import__("sources").GitHubSource(
                "sk-or-v1-", token, max_pages=1, max_items=5),
            "internet:github:sk-or-v1-")
        per_source.append({
            "source": "github code search", "mode": "internet:github:sk-or-v1-",
            "status": status, "metrics": m,
            "findings": [f.public_dict() for f in findings], "note": note,
        })
        all_findings.extend(findings)
    else:
        per_source.append({
            "source": "github code search", "mode": "internet:github",
            "status": "skipped",
            "metrics": None, "findings": [],
            "note": "No GITHUB_TOKEN in environment — code search needs a "
                    "free GitHub token. Not faked; run with a token to "
                    "include it.",
        })
        print("[skipped] github code search: no GITHUB_TOKEN",
              file=sys.stderr)

    # Global dedup across sources (same key in two sources = one finding).
    seen, unique = set(), []
    dupes = 0
    for f in all_findings:
        if f.fingerprint in seen:
            dupes += 1
            continue
        seen.add(f.fingerprint)
        unique.append(f)
    unique.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.provider,
                               f.file_path))
    from collections import Counter
    by_provider = Counter(f.provider for f in unique)
    by_source = Counter(f.source for f in unique)
    by_severity = Counter(f.severity for f in unique)

    # Fixture scorecard (precision/recall on the planted fixtures).
    # A dedicated scan: LocalSource yields paths relative to the fixture
    # root (e.g. "app.py"), so filter by source instead of path prefix.
    score = fixture_scorecard(scan_source(LocalSource("tests/fixtures")))
    return {
        "tool": "aiscan",
        "trial_run_at_utc": ts,
        "caps": {
            "dockerhub_max_images": 2,
            "gists_max": 5,
            "npm_max_packages": 3,
            "pypi_max_packages": 3,
            "pastebin_max_pastes": 5,
            "stackoverflow_max_questions": 5,
            "commoncrawl_max_records": 3,
            "github_max_items": 5,
        },
        "verification": "OFF everywhere — candidates only, no key tested.",
        "per_source": per_source,
        "aggregate": {
            "total_findings_before_dedup": len(all_findings),
            "total_findings_after_dedup": len(unique),
            "cross_source_duplicates": dupes,
            "by_provider": dict(by_provider),
            "by_source": dict(by_source),
            "by_severity": dict(by_severity),
        },
        "fixture_scorecard": score,
        "findings": [f.public_dict() for f in unique],
    }


def render_markdown(result: dict) -> str:
    lines = []
    lines.append("# aiscan — live trial run")
    lines.append("")
    lines.append(f"**Run at (UTC):** {result['trial_run_at_utc']}  |  "
                 "**Verification:** OFF everywhere — candidates only, no "
                 "key was tested. All keys shown masked.")
    lines.append("")
    lines.append("## Caps used")
    lines.append("")
    for k, v in result["caps"].items():
        lines.append(f"- `{k}`: {v}")
    lines.append("")
    lines.append("## Results by source")
    lines.append("")
    lines.append("| Source | Status | Items | Candidates | Findings | "
                 "API calls | Rate limits |")
    lines.append("|---|---|---|---|---|---|---|")
    for entry in result["per_source"]:
        m = entry["metrics"]
        if m is None:
            lines.append(f"| {entry['source']} | {entry['status']} | - | - | "
                         f"- | - | - |")
            continue
        lines.append(
            f"| {entry['source']} | {entry['status']} | "
            f"{m['items_scanned']} | {m['candidates']} | {m['findings']} | "
            f"{m['api_requests']} | {m['rate_limit_events']} |")
    lines.append("")
    agg = result["aggregate"]
    lines.append("## Aggregate (after cross-source dedup)")
    lines.append("")
    lines.append(f"- Findings before dedup: "
                 f"{agg['total_findings_before_dedup']}")
    lines.append(f"- Findings after dedup: "
                 f"{agg['total_findings_after_dedup']} "
                 f"(cross-source duplicates removed: "
                 f"{agg['cross_source_duplicates']})")
    if agg["by_provider"]:
        prov = ", ".join(f"{p} {c}" for p, c in
                         sorted(agg["by_provider"].items()))
        lines.append(f"- By provider: {prov}")
    if agg["by_source"]:
        src = ", ".join(f"{s} {c}" for s, c in
                        sorted(agg["by_source"].items()))
        lines.append(f"- By source: {src}")
    if agg["by_severity"]:
        sev = ", ".join(f"{s} {c}" for s, c in
                        sorted(agg["by_severity"].items()))
        lines.append(f"- By severity: {sev}")
    lines.append("")
    score = result["fixture_scorecard"]
    lines.append("## Fixture precision/recall")
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
    for entry in result["per_source"]:
        if entry["note"]:
            any_notes = True
            lines.append(f"- **{entry['source']}** ({entry['status']}): "
                         f"{entry['note']}")
        if entry["metrics"] and entry["metrics"].get("errors"):
            for err in entry["metrics"]["errors"][:3]:
                any_notes = True
                lines.append(f"- **{entry['source']}**: {err}")
    if not any_notes:
        lines.append("- None — every source ran clean.")
    lines.append("")
    lines.append("## Findings (masked)")
    lines.append("")
    if not result["findings"]:
        lines.append("No findings.")
    for f in result["findings"]:
        lines.append(f"- `{f['masked']}` — {f['provider']} "
                     f"({f['credential_type']}), {f['severity']}, "
                     f"{f['location']} [source: {f['source']}]")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="trial_run",
        description="Bounded live trial across every aiscan source.")
    p.add_argument("--output", default=os.path.join(RESULTS_DIR, "TRIAL_RUN.md"),
                   help="Markdown report path (default results/TRIAL_RUN.md)")
    args = p.parse_args(argv)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    result = run_trial()
    md = render_markdown(result)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(md)
    json_path = os.path.splitext(args.output)[0] + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(f"Wrote {args.output}")
    print(f"Wrote {json_path}")
    agg = result["aggregate"]
    print(f"Aggregate: {agg['total_findings_after_dedup']} findings "
          f"after dedup across {len(result['per_source'])} sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
