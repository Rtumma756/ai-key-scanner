#!/usr/bin/env python3
"""Merge masked-only aiscan JSON reports into a single report.

Each input is a report produced by `aiscan scan local --format json`
(masked values + SHA-256 fingerprints only — aiscan's JSON reporter
aborts if a full secret would ever be written). The merged report
recomputes the summary counts and concatenates the findings lists;
nothing is unmasked at any point.

Usage:
  merge_reports.py <report1.json> [<report2.json> ...] -o <merged.json>
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Merge masked-only aiscan JSON reports into one.")
    p.add_argument("reports", nargs="+",
                   help="Masked-only JSON report file(s) to merge.")
    p.add_argument("-o", "--output", required=True,
                   help="Path to write the merged JSON report.")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    findings: list = []
    by_severity: dict[str, int] = {}
    verified_live = 0
    modes: list[str] = []

    for path in args.reports:
        try:
            with open(path, encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, ValueError) as e:
            print(f"error: cannot read report {path}: {e}", file=sys.stderr)
            return 2
        batch = payload.get("findings", [])
        if not isinstance(batch, list):
            print(f"error: malformed report {path}: 'findings' is not "
                  f"a list", file=sys.stderr)
            return 2
        findings.extend(batch)
        for sev, n in payload.get("summary", {}).get("by_severity", {}).items():
            by_severity[sev] = by_severity.get(sev, 0) + int(n)
        verified_live += int(payload.get("summary", {}).get("verified_live", 0))
        modes.append(str(payload.get("mode", "?")))

    merged = {
        "tool": "aiscan",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "; ".join(dict.fromkeys(modes)),
        "verification_enabled": False,
        "verification_note": "Verification was off.",
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "verified_live": verified_live,
        },
        "findings": findings,
        "merged_from": args.reports,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(json.dumps(merged, indent=2) + "\n")
    print(f"Merged {len(args.reports)} report(s) -> {args.output} "
          f"({len(findings)} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
