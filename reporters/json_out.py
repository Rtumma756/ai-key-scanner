"""JSON reporter. Only masked values and fingerprints are serialized."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from confidence import score_finding
from savings import estimate_savings


def _assert_redacted(text: str, findings) -> None:
    for f in findings:
        if f.value and f.value in text:
            raise RuntimeError(
                "REDACTION FAILURE: a full secret would have been written. "
                "Aborting output."
            )


def render_json(findings, mode: str, verified: bool, metrics=None,
                verified_fingerprints=None) -> str:
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    conf_buckets = {"high (>=80)": 0, "medium (50-79)": 0, "low (<50)": 0}
    for f in findings:
        score, _ = score_finding(f)
        if score >= 80:
            conf_buckets["high (>=80)"] += 1
        elif score >= 50:
            conf_buckets["medium (50-79)"] += 1
        else:
            conf_buckets["low (<50)"] += 1
    payload = {
        "tool": "aiscan",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "verification_enabled": verified,
        "verification_note": (
            "Verification is read-only (model-list/balance probes) and "
            "must only run on keys the user owns or is authorized to test."
            if verified else "Verification was off."
        ),
        "summary": {
            "total_findings": len(findings),
            "by_severity": counts,
            "verified_live": sum(
                1 for f in findings if f.verification in ("live", "no_quota")),
            "confidence_distribution": conf_buckets,
        },
        "findings": [f.public_dict() for f in findings],
        "potential_savings_estimate": estimate_savings(
            findings, verified_fingerprints),
    }
    if metrics is not None:
        payload["metrics"] = metrics.to_dict()
    out = json.dumps(payload, indent=2) + "\n"
    _assert_redacted(out, findings)
    return out
