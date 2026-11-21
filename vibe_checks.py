"""OWASP-style vibe-app checks for KeySentry Pillar 2.

Each check inspects one file's text and returns findings as plain dicts:

    {"id", "title", "severity", "file", "line", "evidence", "fix"}

``evidence`` never contains a raw secret: any detector match in the
evidence line is replaced with its prefix4 mask first. ``fix`` is a
plain-language suggestion written for a non-developer.

Check ids (shared with the TypeScript port in key-sentry/lib/vibe-checks.ts
— keep both in sync so Python and web reports agree):

    vibe-env-committed          committed .env / env file
    vibe-firebase-open-rules    Firebase rules allow read/write if true
    vibe-db-no-auth             DB connection string with no credentials
    vibe-storage-public         publicly readable storage bucket in config
    vibe-api-no-auth            (heuristic) API route with no auth reference
    vibe-cors-wildcard          CORS "*" / overly permissive headers
    vibe-hardcoded-internal-url hardcoded internal URL / private IP

Leaked secrets themselves are NOT checked here — vibe_scan.py runs the
existing engine/detectors (scan_line) for those and reports them with
check id ``vibe-leaked-secret``.
"""
from __future__ import annotations

import os
import re

from common import mask_value
from detectors import scan_line

# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _safe_evidence(line: str) -> str:
    """Evidence text with every detected credential masked (prefix4)."""
    evidence = line.strip()
    for raw in scan_line(line, allow_examples=True):
        evidence = evidence.replace(raw.value, mask_value(raw.value))
    if len(evidence) > 160:
        evidence = evidence[:160] + "…"
    return evidence


def _finding(check_id, title, severity, path, line_no, evidence, fix):
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "file": path,
        "line": line_no,
        "evidence": evidence,
        "fix": fix,
    }


# ---------------------------------------------------------------------------
# Individual checks (each: file path + lines -> findings)
# ---------------------------------------------------------------------------

_ENV_BASENAMES = (".env",)


def _is_env_file(path: str) -> bool:
    base = os.path.basename(path)
    return base == ".env" or base.startswith(".env.")


def check_env_file(path: str, lines: list) -> list:
    """(b) A committed .env file — secrets live in it by design."""
    if not _is_env_file(path):
        return []
    base = os.path.basename(path)
    if base in (".env.example", ".env.sample"):
        return []
    return [_finding(
        "vibe-env-committed",
        "Committed .env file — secrets may be in git history",
        "high", path, 0, base,
        "Your app's secret settings file is saved in the project, so "
        "anyone who can see the code can see the secrets. Move the "
        "secrets into your hosting provider's settings (for example "
        "Vercel → Settings → Environment Variables), delete the file "
        "from the project, and add .env to .gitignore.",
    )]


_FIREBASE_ALLOW_RE = re.compile(
    r"allow\s+(read|write|read\s*,\s*write|write\s*,\s*read)\s*:\s*if\s+true\b",
    re.IGNORECASE)


def check_firebase_rules(path: str, lines: list) -> list:
    """(c) Firebase rules with open read/write."""
    base = os.path.basename(path).lower()
    if base not in ("firestore.rules", "database.rules.json",
                    "storage.rules", "firebase.json"):
        # Also scan any *.rules file.
        if not base.endswith(".rules"):
            return []
    findings = []
    for i, line in enumerate(lines, 1):
        if _FIREBASE_ALLOW_RE.search(line):
            findings.append(_finding(
                "vibe-firebase-open-rules",
                "Firebase rule lets anyone read or write your database",
                "critical", path, i, _safe_evidence(line),
                "Your database is open to anyone on the internet. In the "
                "Firebase console → Rules, change 'allow read: if true' "
                "(and 'allow write: if true') to a rule that only lets "
                "signed-in users in, for example "
                "'allow read, write: if request.auth != null'.",
            ))
    return findings


# mongodb://host/db or postgres://host/db with no user:pass before the host.
_NO_AUTH_URI_RE = re.compile(
    r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb)://"
    r"(?!([^/\s:@]+):([^/\s:@]+)@)[^/\s@]+/",
)


def check_db_no_auth(path: str, lines: list) -> list:
    """(c) DB connection strings without any username/password."""
    findings = []
    for i, line in enumerate(lines, 1):
        if _NO_AUTH_URI_RE.search(line):
            findings.append(_finding(
                "vibe-db-no-auth",
                "Database connection has no username or password",
                "high", path, i, _safe_evidence(line),
                "Your app connects to its database without a username or "
                "password, so anyone who finds the address can open it. "
                "In your database provider's dashboard, create a database "
                "user with a strong password and put the full connection "
                "address (with that username and password) in your "
                "hosting provider's secret settings — never in the code.",
            ))
    return findings


_PUBLIC_STORAGE_RES = [
    re.compile(r"(?i)public[\s_-]?read\b"),
    re.compile(r"(?i)\"?public\"?\s*:\s*true"),
    re.compile(r"(?i)acl\s*[:=]\s*[\"']?public-read[\"']?"),
]


def check_storage_public(path: str, lines: list) -> list:
    """(c) Publicly readable storage bucket declared in config."""
    base = os.path.basename(path).lower()
    if base not in ("firebase.json", "storage.rules", "s3.json",
                    "bucket.json", "terraform.tf", "main.tf"):
        if not (base.endswith(".tf") or "storage" in base
                or "bucket" in base):
            return []
    findings = []
    for i, line in enumerate(lines, 1):
        if any(rx.search(line) for rx in _PUBLIC_STORAGE_RES):
            # Firebase open rules are reported by check_firebase_rules;
            # skip the same "allow read: if true" line here.
            if _FIREBASE_ALLOW_RE.search(line):
                continue
            findings.append(_finding(
                "vibe-storage-public",
                "Storage bucket is set to public read",
                "high", path, i, _safe_evidence(line),
                "Your file storage is set so anyone on the internet can "
                "read the files in it. In your storage provider's "
                "settings, turn off public access and only let signed-in "
                "users (or signed links) open files.",
            ))
    return findings


_AUTH_WORDS = (
    "auth", "verifytoken", "requireauth", "authenticate", "jwt",
    "session", "middleware", "protected", "isauthenticated", "checkauth",
    "authorize", "permission", "apikey", "api-key",
)
_HANDLER_RES = [
    re.compile(r"export\s+(default\s+)?(async\s+)?function\s+\w*"),
    re.compile(r"export\s+default\s+"),
    re.compile(r"\b(app|router)\.(get|post|put|patch|delete|all)\s*\("),
    re.compile(r"export\s+(const|async)\s+\w+\s*=\s*(async\s*)?\("),
]


def check_api_no_auth(path: str, lines: list) -> list:
    """(d) HEURISTIC: API route handler with no auth middleware reference.

    One finding per file, explicitly labelled heuristic — it only means
    "no sign of an auth check in this file", not "this endpoint is open".
    """
    low_path = path.replace("\\", "/").lower()
    if not ("/api/" in low_path or "/routes/" in low_path
            or low_path.startswith("api/") or low_path.startswith("routes/")
            or "route." in os.path.basename(low_path)
            or "handler" in os.path.basename(low_path)):
        return []
    base = os.path.basename(path).lower()
    if not (base.endswith((".js", ".jsx", ".ts", ".tsx", ".py"))):
        return []
    text = "\n".join(lines)
    if not any(rx.search(text) for rx in _HANDLER_RES):
        return []
    lowered = re.sub(r"[^a-z0-9]+", "", text.lower())
    if any(word in lowered for word in _AUTH_WORDS):
        return []
    first_handler = 0
    for i, line in enumerate(lines, 1):
        if any(rx.search(line) for rx in _HANDLER_RES):
            first_handler = i
            break
    return [_finding(
        "vibe-api-no-auth",
        "API route shows no sign-in check (heuristic — please verify)",
        "medium", path, first_handler,
        os.path.basename(path),
        "This check is only a heuristic guess: it could not see any sign-in check "
        "in this API file, so the endpoint may be open to anyone. Ask "
        "your developer (or the AI tool that built the app) to confirm "
        "the endpoint checks that the caller is signed in before it "
        "returns or changes any data.",
    )]


_CORS_RES = [
    re.compile(r"(?i)access-control-allow-origin\s*[:=]\s*[\"']?\*"),
    re.compile(r"(?i)origin\s*:\s*[\"']\*+[\"']"),
    re.compile(r"(?i)allow_origins\s*=\s*\[[\"']\*+[\"']\]"),
    re.compile(r"(?i)allow_all_origins\s*=\s*true"),
]


def check_cors_wildcard(path: str, lines: list) -> list:
    """(e) CORS "*" / overly permissive headers."""
    findings = []
    for i, line in enumerate(lines, 1):
        if any(rx.search(line) for rx in _CORS_RES):
            findings.append(_finding(
                "vibe-cors-wildcard",
                "Any website may call your API (CORS allows *)",
                "medium", path, i, _safe_evidence(line),
                "Your app tells browsers that any website on the internet "
                "may call its API. Change the allowed website list to "
                "just your own site's address (for example "
                "https://your-app.com) instead of '*'.",
            ))
    return findings


_PRIVATE_IP_RE = re.compile(
    r"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
    r"[0-9.]+(?::\d+)?(?:/[^\s\"']*)?")


def check_hardcoded_internal_url(path: str, lines: list) -> list:
    """(f) Hardcoded internal URLs / private IPs."""
    findings = []
    for i, line in enumerate(lines, 1):
        m = _PRIVATE_IP_RE.search(line)
        if m:
            findings.append(_finding(
                "vibe-hardcoded-internal-url",
                "Hardcoded internal address in the code",
                "low", path, i, _safe_evidence(line),
                "The code contains a private network address (something "
                "like 192.168.x.x) that only works inside one office or "
                "home network. Move the address into your hosting "
                "provider's settings so the app works everywhere and the "
                "internal address is not published with the code.",
            ))
    return findings


# ---------------------------------------------------------------------------
# Runner: all checks over one file
# ---------------------------------------------------------------------------

CHECKS = (
    check_env_file,
    check_firebase_rules,
    check_db_no_auth,
    check_storage_public,
    check_api_no_auth,
    check_cors_wildcard,
    check_hardcoded_internal_url,
)


def check_file(path: str, text: str) -> list:
    """Run every vibe config check over one file's text."""
    lines = text.splitlines()
    findings: list = []
    for check in CHECKS:
        findings.extend(check(path, lines))
    return findings


def check_files(files: list) -> list:
    """Run every check over [(path, text), ...]; findings sorted by severity."""
    findings: list = []
    for path, text in files:
        findings.extend(check_file(path, text))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 3),
                                 f["file"], f["line"]))
    return findings


# ---------------------------------------------------------------------------
# Audit events (Pillar 3 schema, per-report chain)
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402
import json  # noqa: E402
import uuid  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

AUDIT_AGENT_ID = "vibe-scanner"
AUDIT_AGENT_VERSION = "0.1.0"
AUDIT_POLICY_ID = "vibe-scan"


def canonical_json(obj: dict) -> str:
    """JSON with sorted keys and no spaces — the hash input format."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def build_audit_events(findings: list, repo_url: str, report_id: str,
                       prev_hash: str | None = None) -> list:
    """One ``vibe.finding`` event per finding, hash-chained.

    ``prev_hash`` is the previous event's hash (genesis: 64 zeros).
    Never includes file contents or secret values — arg_keys and the
    repo URL only, per the schema.
    """
    events = []
    prev = prev_hash or "0" * 64
    for finding in findings:
        event = {
            "event_type": "vibe.finding",
            "timestamp": datetime.now(timezone.utc).isoformat()
                         .replace("+00:00", "Z"),
            "prev_hash": prev,
            "principal_id": "anonymous",
            "parent_agent_id": None,
            "session_id": report_id,
            "policy_id": AUDIT_POLICY_ID,
            "ticket_of_record": None,
            "model_run_id": None,
            "agent_id": AUDIT_AGENT_ID,
            "agent_version": AUDIT_AGENT_VERSION,
            "model": None,
            "tool": "vibe-scan",
            "resource": repo_url,
            "arg_keys": ["repoUrl"],
            "decision": {"allow": True, "policy": AUDIT_POLICY_ID,
                         "reason": "public repo scan"},
            "outcome": "success",
            "correlation_id": report_id,
            "event_id": str(uuid.uuid4()),
        }
        payload = canonical_json(event) + prev
        event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        event["event_hash"] = event_hash
        events.append(event)
        prev = event_hash
    return events


def verify_audit_chain(events: list) -> bool:
    """Recompute the chain; True only when every hash links correctly."""
    prev = "0" * 64
    for event in events:
        if event.get("prev_hash") != prev:
            return False
        event_copy = {k: v for k, v in event.items()
                      if k != "event_hash"}
        expected = hashlib.sha256(
            (canonical_json(event_copy) + prev).encode("utf-8")).hexdigest()
        if expected != event.get("event_hash"):
            return False
        prev = event["event_hash"]
    return True
