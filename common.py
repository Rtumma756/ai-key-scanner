"""Shared models for aiscan: findings, masking, dedup.

Security rule enforced by design: a Finding keeps the full secret value in
memory ONLY (field ``value``, repr=False) so verification probes can use it.
Nothing that leaves the process — terminal, JSON, Markdown — ever touches
``value``. Reporters serialize ``public_dict()`` only, which exposes the
masked form and a SHA-256 fingerprint prefix.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

# Masking modes for displayed keys. Default: "prefix4" (first 4 chars shown,
# rest hidden). "ends" hides the first 5 and last 3 chars and shows the middle
# — that exposes most of a key, so it must only be used for keys the viewer
# owns (their own assets), never for strangers' keys in shared reports.
MASK_MODES = ("prefix4", "ends")
MASK_MODE = os.environ.get("AISCAN_MASK_MODE", "prefix4")
if MASK_MODE not in MASK_MODES:
    MASK_MODE = "prefix4"


def set_mask_mode(mode: str) -> None:
    """Set the process-wide masking mode ('prefix4' or 'ends')."""
    global MASK_MODE
    if mode not in MASK_MODES:
        raise ValueError(f"unknown mask mode {mode!r} (want one of {MASK_MODES})")
    MASK_MODE = mode


def mask_value(value: str, mode: str | None = None) -> str:
    """Masked form shown everywhere. Default mode 'prefix4': first 4 chars
    + '...', rest hidden. Mode 'ends': first 5 and last 3 chars hidden,
    middle shown — exposes most of the key; own keys only."""
    mode = mode or MASK_MODE
    if mode == "ends":
        if len(value) <= 8:
            return "*" * len(value)
        return "*" * 5 + value[5:-3] + "*" * 3
    return f"{value[:4]}..."

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

REMEDIATION_STEPS = [
    "Revoke / rotate the key at the provider console: {console_url}",
    "Remove the secret from the codebase AND from git history "
    "(git filter-repo --replace-text, or BFG Repo-Cleaner). Deleting the "
    "file is not enough — history keeps the key.",
    "Move the secret to environment variables or a secret manager; "
    "never commit .env files.",
    "Add .env and other secret files to .gitignore.",
    "Enable push protection (GitHub: Settings -> Code security -> "
    "Secret scanning -> Push protection).",
    "Check provider usage and billing for unexpected activity on the key.",
]


def value_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    provider: str
    credential_type: str
    value: str = field(repr=False)  # full secret, in-memory only
    file_path: str = ""
    line_number: int = 0
    snippet: str = ""  # already redacted by the engine
    severity: str = "high"
    source: str = "local"
    console_url: str = ""
    verification: str = "not_checked"  # not_checked|live|no_quota|dead|unknown|unsupported
    verification_detail: str = ""
    detected_via: str = "regex"  # regex | context | entropy

    @property
    def masked(self) -> str:
        return mask_value(self.value)

    @property
    def fingerprint(self) -> str:
        """First 16 hex chars of the SHA-256 of the secret (safe to show)."""
        return value_hash(self.value)[:16]

    @property
    def location(self) -> str:
        if self.line_number > 0:
            return f"{self.file_path}:{self.line_number}"
        return self.file_path

    def remediation(self) -> list:
        steps = []
        for step in REMEDIATION_STEPS:
            steps.append(step.format(console_url=self.console_url or "(provider console)"))
        return steps

    def public_dict(self) -> dict:
        """The ONLY serialization of a finding. Never includes the secret."""
        try:
            from confidence import score_finding

            confidence_score, confidence_evidence = score_finding(self)
        except Exception:
            confidence_score, confidence_evidence = (
                0, ["confidence scoring unavailable"])
        return {
            "provider": self.provider,
            "credential_type": self.credential_type,
            "masked": self.masked,
            "fingerprint_sha256_16": self.fingerprint,
            "file": self.file_path,
            "line": self.line_number,
            "location": self.location,
            "snippet": self.snippet,
            "severity": self.severity,
            "source": self.source,
            "verification": self.verification,
            "verification_detail": self.verification_detail,
            "detected_via": self.detected_via,
            "console_url": self.console_url,
            "confidence": confidence_score,
            "confidence_evidence": confidence_evidence,
            "remediation": self.remediation(),
        }
