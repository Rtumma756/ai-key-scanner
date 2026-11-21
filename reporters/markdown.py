"""Markdown remediation reporter.

Findings are grouped by severity (verified-live first) and each finding
carries its own remediation steps. A global checklist closes the report.
Only masked values are ever written.
"""
from __future__ import annotations

from datetime import datetime, timezone

from common import SEVERITY_RANK
from confidence import score_finding
from reporters.remediation import GLOBAL_CHECKLIST
from savings import estimate_savings, render_savings_markdown


def _assert_redacted(text: str, findings) -> None:
    for f in findings:
        if f.value and f.value in text:
            raise RuntimeError(
                "REDACTION FAILURE: a full secret would have been written. "
                "Aborting output."
            )


def render_markdown(findings, mode: str, verified: bool, metrics=None,
                    verified_fingerprints=None) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    lines.append("# aiscan — AI API leaked-key remediation report")
    lines.append("")
    lines.append(f"**Mode:** {mode}  |  **Generated:** {ts}  |  "
                 f"**Findings:** {len(findings)}")
    lines.append("")
    if verified:
        lines.append("> **Verification was ON.** Read-only probes only "
                     "(model-list / balance endpoints). Only verify keys you "
                     "own or are authorized to test.")
        lines.append("")
    if not findings:
        lines.append("No findings. Re-scan after any change; a clean result "
                     "is not a safety guarantee.")
        lines.append("")
        if metrics is not None:
            lines.append("## Metrics")
            lines.append("")
            lines.append("```")
            lines.append(metrics.render_scorecard())
            lines.append("```")
            lines.append("")
        out = "\n".join(lines)
        _assert_redacted(out, findings)
        return out + "\n"

    grouped = {}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)
    for severity in sorted(grouped, key=lambda s: SEVERITY_RANK[s]):
        items = grouped[severity]
        lines.append(f"## {severity.capitalize()} ({len(items)})")
        lines.append("")
        for f in items:
            score, evidence = score_finding(f)
            lines.append(f"### {f.provider} — `{f.masked}`")
            lines.append("")
            lines.append(f"- **Type:** {f.credential_type}")
            lines.append(f"- **Confidence:** {score}/100 — {'; '.join(evidence)}")
            lines.append(f"- **Location:** `{f.location}`")
            lines.append(f"- **Source:** {f.source}  |  **Detected via:** {f.detected_via}")
            lines.append(f"- **Verification:** {f.verification}"
                         + (f" — {f.verification_detail}" if f.verification_detail else ""))
            lines.append(f"- **Fingerprint:** `{f.fingerprint}` (SHA-256 prefix)")
            lines.append(f"- **Context:** `{f.snippet[:140]}`")
            lines.append("- **Remediate:**")
            for step in f.remediation():
                lines.append(f"  - {step}")
            lines.append("")

    lines.append("## Confidence distribution")
    lines.append("")
    lines.append("Static 0-100 scores (format, usage context, file type, "
                 "liveness, corroboration; placeholders score ~0). "
                 "Corpus rows carry no snippet, so their scores are a lower "
                 "bound on what a live scan would give.")
    lines.append("")
    dist = {"high (>=80)": 0, "medium (50-79)": 0, "low (<50)": 0}
    for f in findings:
        score, _ = score_finding(f)
        if score >= 80:
            dist["high (>=80)"] += 1
        elif score >= 50:
            dist["medium (50-79)"] += 1
        else:
            dist["low (<50)"] += 1
    for bucket, count in dist.items():
        lines.append(f"- **{bucket}:** {count}")
    lines.append("")

    lines.extend(render_savings_markdown(
        estimate_savings(findings, verified_fingerprints)))
    lines.append("## Remediation checklist")
    lines.append("")
    for step in GLOBAL_CHECKLIST:
        lines.append(f"- [ ] {step}")
    lines.append("")
    if metrics is not None:
        lines.append("## Metrics")
        lines.append("")
        lines.append("```")
        lines.append(metrics.render_scorecard())
        lines.append("```")
        lines.append("")
    out = "\n".join(lines)
    _assert_redacted(out, findings)
    return out
