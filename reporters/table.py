"""Terminal table reporter. Only masked values are ever printed."""
from __future__ import annotations

from common import SEVERITY_RANK
from confidence import score_finding
from savings import estimate_savings, render_savings_lines


def confidence_distribution(findings) -> dict:
    """Bucket counts for confidence scores: high >=80, medium 50-79, low <50."""
    buckets = {"high (>=80)": 0, "medium (50-79)": 0, "low (<50)": 0}
    for f in findings:
        score, _ = score_finding(f)
        if score >= 80:
            buckets["high (>=80)"] += 1
        elif score >= 50:
            buckets["medium (50-79)"] += 1
        else:
            buckets["low (<50)"] += 1
    return buckets


def _assert_redacted(text: str, findings) -> None:
    for f in findings:
        if f.value and f.value in text:
            raise RuntimeError(
                "REDACTION FAILURE: a full secret would have been printed. "
                "Aborting output."
            )


def render_table(findings, mode: str, verified: bool, metrics=None,
                 verified_fingerprints=None) -> str:
    lines = []
    lines.append("=" * 100)
    lines.append(f"aiscan — AI API leaked-key scan  |  mode: {mode}")
    if verified:
        lines.append("WARNING: verification was ON. It sends each key to its "
                     "provider (read-only probe). Only verify keys you own "
                     "or are authorized to test.")
    lines.append("=" * 100)
    if not findings:
        lines.append("No findings. (A clean result is not a safety guarantee "
                     "— review high-severity hits and re-scan after changes.)")
        if metrics is not None:
            lines.append("")
            lines.append("--- Metrics ---")
            lines.append(metrics.render_scorecard())
        return "\n".join(lines) + "\n"

    header = (f"{'SEVERITY':<9} {'CONF':>4} {'PROVIDER':<16} {'MASKED KEY':<20} "
              f"{'VERIFICATION':<11} LOCATION")
    lines.append(header)
    lines.append("-" * 100)
    for f in sorted(findings, key=lambda x: SEVERITY_RANK[x.severity]):
        score, evidence = score_finding(f)
        lines.append(
            f"{f.severity:<9} {score:>4} {f.provider:<16} {f.masked:<20} "
            f"{f.verification:<11} {f.location}"
        )
        lines.append(f"{'':<9} {f.credential_type}  |  {f.snippet[:110]}")
        lines.append(f"{'':<9} confidence {score}/100: {'; '.join(evidence)}")
    lines.append("-" * 100)
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    lines.append(f"Total findings: {len(findings)}  ({summary})")
    dist = confidence_distribution(findings)
    lines.append("Confidence: " + ", ".join(f"{k}: {v}" for k, v in dist.items()))
    lines.append("")
    for line in render_savings_lines(
            estimate_savings(findings, verified_fingerprints)):
        lines.append(line)
    live = [f for f in findings if f.verification in ("live", "no_quota")]
    if live:
        lines.append(f"ACTION REQUIRED: {len(live)} verified-live credential(s) "
                     "— revoke them now (see the Markdown report for steps).")
    if metrics is not None:
        lines.append("")
        lines.append("--- Metrics ---")
        lines.append(metrics.render_scorecard())
    out = "\n".join(lines) + "\n"
    _assert_redacted(out, findings)
    return out
