"""Remediation content shared by the reporters."""
from __future__ import annotations

GLOBAL_CHECKLIST = [
    "Revoke every verified-live key at its provider console immediately — "
    "a leaked key is typically used within minutes.",
    "Rotate any key that was ever committed, even if verification says "
    "'dead': history may hold a copy that still works.",
    "Purge secrets from git history with git filter-repo --replace-text "
    "or BFG Repo-Cleaner, then force-push; deleting the file is not enough.",
    "Move secrets to environment variables or a secret manager; never "
    "commit .env files.",
    "Add .env, *.pem and other secret files to .gitignore.",
    "Enable push protection (GitHub: Settings -> Code security -> "
    "Secret scanning -> Push protection).",
    "Check provider usage and billing for unexpected activity.",
    "Re-scan after remediation to confirm zero findings.",
]


def finding_remediation(finding) -> list:
    return finding.remediation()
