#!/usr/bin/env python3
"""Score the findings in a results/*.json classification file.

Reads a classification report (STRESS_606_CLASSIFICATION.json,
CLASSIFY_FRESH_41.json, CLASSIFY_10MIN_11.json, ...), scores every row
with confidence.score_finding(), and writes a scored copy
``<stem>.scored.json`` next to it. The original file is NEVER modified.

Corroboration context comes from the other dated reports in the same
directory: a fingerprint seen in several reports, or confirmed still
exposed in FRESH_LIVENESS_ALL.json, scores higher. Only masked values
and fingerprints are read or written; no raw key is ever involved.

Usage:
    python3 score_results.py results/STRESS_606_CLASSIFICATION.json
    python3 score_results.py results/STRESS_606_CLASSIFICATION.json \
        results/CLASSIFY_FRESH_41.json [--as-of 2026-11-21]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from confidence import (build_corpus_context, context_for_fingerprint,
                        score_finding)  # noqa: E402

# Dated reports that count as corroboration sources (same directory as the
# file being scored). Files that do not exist are skipped.
CORROBORATION_FILES = (
    "STRESS_606_CLASSIFICATION.json",
    "CLASSIFY_FRESH_41.json",
    "CLASSIFY_10MIN_11.json",
    "FRESH_LIVENESS_ALL.json",
)


def _rows_of(report: dict) -> list:
    rows = report.get("keys") or report.get("rows") or []
    return [r for r in rows if isinstance(r, dict)]


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def distribution(scores: list[int]) -> dict:
    buckets = {"high (>=80)": 0, "medium (50-79)": 0, "low (<50)": 0}
    for s in scores:
        if s >= 80:
            buckets["high (>=80)"] += 1
        elif s >= 50:
            buckets["medium (50-79)"] += 1
        else:
            buckets["low (<50)"] += 1
    buckets["total"] = len(scores)
    return buckets


def score_file(path: str, corpus_context: dict, as_of: str | None) -> dict:
    """Score one report file; returns (scored_report_dict, out_path)."""
    report = _load_json(path)
    rows = _rows_of(report)
    scored_rows = []
    scores = []
    for row in rows:
        fp = row.get("fingerprint") or row.get("fingerprint_sha256_16")
        ctx = context_for_fingerprint(corpus_context, fp, as_of=as_of)
        score, evidence = score_finding(row, context=ctx)
        new_row = dict(row)
        new_row["confidence"] = score
        new_row["confidence_evidence"] = evidence
        scored_rows.append(new_row)
        scores.append(score)
    out = dict(report)
    out["confidence_method"] = (
        "confidence.score_finding (static only: format, usage context, "
        "file type, liveness duration, cross-report corroboration; "
        "placeholders capped at ~0). Corpus rows carry no snippet, so "
        "usage-context signals cannot fire and scores are a lower bound "
        "on what a live scan would give.")
    out["confidence_summary"] = distribution(scores)
    if rows:
        out["confidence_summary"]["mean"] = round(sum(scores) / len(scores), 1)
        out["confidence_summary"]["median"] = sorted(scores)[len(scores) // 2]
    # Preserve the original row list under its original key name.
    if "keys" in report:
        out["keys"] = scored_rows
    elif "rows" in report:
        out["rows"] = scored_rows
    else:
        out["scored_rows"] = scored_rows
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+",
                        help="results/*.json classification file(s) to score")
    parser.add_argument("--as-of", default=None,
                        help="reference date YYYY-MM-DD for exposure age "
                             "(default: today)")
    args = parser.parse_args(argv)

    for path in args.files:
        if not os.path.isfile(path):
            print(f"error: no such file: {path}", file=sys.stderr)
            return 2
        results_dir = os.path.dirname(os.path.abspath(path))
        # Corroboration: every dated report in the same directory.
        corpus_reports = []
        for name in CORROBORATION_FILES:
            candidate = os.path.join(results_dir, name)
            if os.path.isfile(candidate):
                try:
                    corpus_reports.append(_load_json(candidate))
                except (OSError, ValueError) as exc:
                    print(f"warning: skipping {candidate}: {exc}",
                          file=sys.stderr)
        corpus_context = build_corpus_context(corpus_reports)

        scored = score_file(path, corpus_context, args.as_of)
        stem, _ext = os.path.splitext(path)
        out_path = f"{stem}.scored.json"
        if os.path.abspath(out_path) == os.path.abspath(path):
            print(f"error: refusing to overwrite {path}", file=sys.stderr)
            return 2
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(scored, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
        summary = scored["confidence_summary"]
        print(f"{os.path.basename(path)} -> {os.path.basename(out_path)}")
        print(f"  scored: {summary['total']}  "
              f"high>=80: {summary['high (>=80)']}  "
              f"50-79: {summary['medium (50-79)']}  "
              f"<50: {summary['low (<50)']}  "
              f"mean: {summary.get('mean')}  median: {summary.get('median')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
