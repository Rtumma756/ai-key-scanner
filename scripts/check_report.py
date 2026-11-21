#!/usr/bin/env python3
"""Check a masked-only aiscan JSON report against a severity threshold.

Reads one or more report files produced by
`aiscan scan local <path> --format json --output <report.json>`
and exits non-zero when any finding is at or above `--fail-on`.

The reports this reads are masked-only by construction (aiscan's JSON
reporter serializes prefix4-masked values and SHA-256 fingerprints;
it aborts if a full secret would ever be written). This script prints
counts and file:line/provider/severity lines only — never a key value,
masked or otherwise.

Exit codes:
  0  no finding at or above the threshold (or no findings at all)
  1  at least one finding at or above the threshold
  2  usage error / unreadable or malformed report

When the GITHUB_OUTPUT environment variable is set (GitHub Actions),
also writes `finding-count` and `findings-file` outputs there.

Usage:
  check_report.py [--fail-on {critical,high,medium,low,none}]
                  <report.json> [<report.json> ...]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITIES = tuple(SEVERITY_RANK) + ("none",)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Fail (exit 1) when a masked aiscan JSON report "
                    "contains a finding at or above a severity threshold.")
    p.add_argument("--fail-on", choices=SEVERITIES, default="high",
                   help="Minimum severity that fails the check "
                        "(default: high; 'none' never fails).")
    p.add_argument("reports", nargs="+",
                   help="Masked-only JSON report file(s) from "
                        "`aiscan scan local --format json`.")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    threshold = None if args.fail_on == "none" else SEVERITY_RANK[args.fail_on]

    total = 0
    by_severity: dict[str, int] = {}
    worst_rank = None  # lowest numeric rank = most severe finding seen
    lines: list[str] = []

    for path in args.reports:
        try:
            with open(path, encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, ValueError) as e:
            print(f"error: cannot read report {path}: {e}", file=sys.stderr)
            return 2
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            print(f"error: malformed report {path}: 'findings' is not "
                  f"a list", file=sys.stderr)
            return 2
        for f in findings:
            sev = str(f.get("severity", "low"))
            rank = SEVERITY_RANK.get(sev, 3)
            total += 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
            if worst_rank is None or rank < worst_rank:
                worst_rank = rank
            # Masked output only: file, line, provider, severity.
            lines.append(f"  {f.get('file', '?')}:{f.get('line', 0)} "
                         f"[{f.get('provider', '?')}] {sev}")

    print(f"KeySentry findings: {total} "
          f"({', '.join(f'{s}={by_severity.get(s, 0)}' for s in SEVERITY_RANK)})")
    for line in lines:
        print(line)

    failed = threshold is not None and worst_rank is not None \
        and worst_rank <= threshold
    if failed:
        print(f"FAIL: findings at or above severity '{args.fail_on}' "
              f"— failing the check.", file=sys.stderr)
    else:
        print("PASS: no findings at or above severity "
              f"'{args.fail_on}'." if args.fail_on != "none"
              else "PASS: fail-on is 'none' — check never fails.")

    # GitHub Actions outputs (no-op outside Actions).
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as f:
            f.write(f"finding-count={total}\n")
            f.write(f"findings-file={args.reports[0]}\n")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
