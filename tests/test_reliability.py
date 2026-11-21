#!/usr/bin/env python3
"""Standalone reliability test: python3 tests/test_reliability.py [--live]

Runs the same fixture precision/recall scorecard as `aiscan.py selftest`.
Exits non-zero on any failure. With --live, also runs the live GitHub
smoke test (needs GITHUB_TOKEN; skipped without one).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from selftest import run_selftest  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(run_selftest(live="--live" in sys.argv))
