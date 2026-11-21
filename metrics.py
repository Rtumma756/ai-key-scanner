"""Run metrics for aiscan: per-scan detection counts and scorecards.

Collected for every scan mode (local, git-history, internet, dockerhub,
gists, demo): items scanned, lines/bytes, candidates, findings after
dedup, breakdowns by provider / credential type / severity, verification
outcomes, API requests, and rate-limit events. Nothing here ever holds a
secret value — only counts and masked-safe aggregates.

Also provides the fixture precision/recall scorecard (reuses the expected
counts from selftest.py).
"""
from __future__ import annotations

import json
import time
from collections import Counter

from savings import estimate_savings, render_savings_lines

# Item kinds counted by sources, merged from each source's ``stats`` dict.
ITEM_KIND_KEYS = (
    "files_scanned", "items_seen", "images_scanned", "gists_scanned",
    "commits_scanned", "demo_files", "packages_scanned", "pastes_scanned",
    "questions_scanned", "records_scanned",
)


class RunMetrics:
    """Accumulator for one scan run. The engine and sources feed it."""

    def __init__(self, mode: str):
        self.mode = mode
        self._start = time.monotonic()
        self.duration_s = 0.0
        self.items_scanned = 0
        self.items_by_kind: Counter = Counter()
        self.lines_scanned = 0
        self.bytes_scanned = 0
        self.candidates = 0          # raw matches before dedup
        self.duplicates_removed = 0
        self.api_requests = 0
        self.rate_limit_events = 0
        self.verification: Counter = Counter()
        self.source_stats: dict = {}
        self.errors: list = []
        # Filled by finalize(findings).
        self.findings = 0
        self.by_provider: Counter = Counter()
        self.by_credential_type: Counter = Counter()
        self.by_severity: Counter = Counter()
        self.verified_live = 0
        # Potential-savings estimate for the findings (see savings.py).
        self.savings = None
        self.verified_keys = 0  # owner-verified keys in this run

    def merge_source_stats(self, stats: dict) -> None:
        """Fold a source's ``stats`` dict into this run's counters."""
        if not stats:
            return
        self.source_stats.update(stats)
        for key in ITEM_KIND_KEYS:
            n = stats.get(key, 0)
            if n:
                self.items_scanned += n
                self.items_by_kind[key] += n
        self.api_requests += stats.get("api_requests", 0)
        self.rate_limit_events += stats.get("rate_limit_hits", 0)

    def add_duplicates(self, n: int) -> None:
        self.duplicates_removed += n

    def finalize(self, findings, verified_fingerprints=None) -> "RunMetrics":
        """Compute finding breakdowns and stop the clock.

        ``verified_fingerprints`` is a set of 16-hex-char SHA-256 prefixes
        (see savings.py): findings matching it count as owner-verified in
        the savings split. None/empty means nothing verified.
        """
        self.duration_s = time.monotonic() - self._start
        self.findings = len(findings)
        for f in findings:
            self.by_provider[f.provider] += 1
            self.by_credential_type[f.credential_type] += 1
            self.by_severity[f.severity] += 1
            if f.verification in ("live", "no_quota"):
                self.verified_live += 1
        self.savings = estimate_savings(findings, verified_fingerprints)
        self.verified_keys = self.savings["verified_keys"]
        return self

    def to_dict(self) -> dict:
        return {
            "tool": "aiscan",
            "mode": self.mode,
            "duration_s": round(self.duration_s, 2),
            "items_scanned": self.items_scanned,
            "items_by_kind": dict(self.items_by_kind),
            "lines_scanned": self.lines_scanned,
            "bytes_scanned": self.bytes_scanned,
            "candidates": self.candidates,
            "duplicates_removed": self.duplicates_removed,
            "findings": self.findings,
            "by_provider": dict(self.by_provider),
            "by_credential_type": dict(self.by_credential_type),
            "by_severity": dict(self.by_severity),
            "verification": dict(self.verification),
            "verified_live": self.verified_live,
            "verified_keys": self.verified_keys,
            "api_requests": self.api_requests,
            "rate_limit_events": self.rate_limit_events,
            "source_stats": self.source_stats,
            "errors": self.errors,
            "potential_savings_estimate": self.savings,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def render_scorecard(self) -> str:
        """Human-readable scorecard for terminal / Markdown reports.

        Opens with one plain-language line so a non-technical reader gets
        the result without parsing the counts below.
        """
        lines = []
        lines.append(
            f"Result: {self.findings} possible leaked key(s) found in "
            f"{self.items_scanned} item(s) scanned. "
            f"{self.duplicates_removed} duplicate(s) removed; "
            f"{self.verified_live} confirmed live "
            f"(verification is off unless you explicitly enable it).")
        lines.append(f"Metrics — mode: {self.mode}")
        lines.append(f"  Duration: {self.duration_s:.2f}s")
        kinds = ", ".join(f"{k.replace('_scanned', '')}: {v}"
                          for k, v in sorted(self.items_by_kind.items()))
        lines.append(f"  Items scanned: {self.items_scanned}"
                     + (f" ({kinds})" if kinds else ""))
        lines.append(f"  Lines scanned: {self.lines_scanned}  "
                     f"Bytes scanned: {self.bytes_scanned}")
        lines.append(f"  Candidates: {self.candidates}  "
                     f"Duplicates removed: {self.duplicates_removed}  "
                     f"Findings: {self.findings}")
        if self.by_provider:
            prov = ", ".join(f"{p} {c}"
                             for p, c in self.by_provider.most_common())
            lines.append(f"  By provider: {prov}")
        if self.by_credential_type:
            types = ", ".join(f"{t} {c}" for t, c in
                              self.by_credential_type.most_common())
            lines.append(f"  By credential type: {types}")
        if self.by_severity:
            sev = ", ".join(f"{s} {c}" for s, c in
                            sorted(self.by_severity.items()))
            lines.append(f"  By severity: {sev}")
        if self.verification:
            ver = ", ".join(f"{s} {c}" for s, c in
                            sorted(self.verification.items()))
            lines.append(f"  Verification: {ver}")
        lines.append(f"  Verified live: {self.verified_live}")
        lines.append(f"  API requests: {self.api_requests}  "
                     f"Rate-limit events: {self.rate_limit_events}")
        if self.errors:
            lines.append(f"  Errors/notes: {len(self.errors)}")
            for err in self.errors[:5]:
                lines.append(f"    - {err}")
        if self.savings and self.savings["total_keys"]:
            lines.append("")
            for line in render_savings_lines(self.savings):
                lines.append(line)
        return "\n".join(lines)


def fixture_scorecard(findings):
    """Precision/recall against the planted fixtures.

    Reuses EXPECTED_PROVIDER_COUNTS from selftest.py. Returns a dict with
    recall, precision, expected/got totals and per-provider mismatches.
    ``findings`` must come from scanning tests/fixtures.
    """
    from selftest import EXPECTED_PROVIDER_COUNTS, EXPECTED_TOTAL

    counts = Counter(f.provider for f in findings)
    missing = {p: (EXPECTED_PROVIDER_COUNTS[p], counts.get(p, 0))
               for p in EXPECTED_PROVIDER_COUNTS
               if counts.get(p, 0) != EXPECTED_PROVIDER_COUNTS[p]}
    extra = {p: c for p, c in counts.items()
             if p not in EXPECTED_PROVIDER_COUNTS}
    decoy_hits = [f for f in findings if f.file_path.endswith("decoys.txt")]
    # Recall = expected findings present; precision = findings that are
    # expected (no extras). Both are 1.0 on a clean fixture run.
    recalled = EXPECTED_TOTAL - sum(
        max(0, want - counts.get(p, 0))
        for p, want in EXPECTED_PROVIDER_COUNTS.items())
    recall = recalled / EXPECTED_TOTAL if EXPECTED_TOTAL else 1.0
    correct = sum(min(counts.get(p, 0), want)
                  for p, want in EXPECTED_PROVIDER_COUNTS.items())
    precision = correct / len(findings) if findings else 1.0
    return {
        "expected_total": EXPECTED_TOTAL,
        "got_total": len(findings),
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "missing": missing,
        "extra": extra,
        "decoy_hits": len(decoy_hits),
        "by_provider": dict(counts),
    }


def render_fixture_scorecard(score: dict) -> str:
    lines = []
    lines.append("Fixture precision/recall scorecard")
    lines.append(f"  Expected: {score['expected_total']}  "
                 f"Got: {score['got_total']}")
    lines.append(f"  Recall: {score['recall']:.2%}  "
                 f"Precision: {score['precision']:.2%}")
    if score["missing"]:
        lines.append(f"  Missing: {score['missing']}")
    if score["extra"]:
        lines.append(f"  Unexpected providers: {score['extra']}")
    lines.append(f"  Decoy hits: {score['decoy_hits']}")
    return "\n".join(lines)
