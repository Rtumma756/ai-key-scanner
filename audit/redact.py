"""Redaction BEFORE write for audit events (allowlist approach).

Only the fields in :data:`audit.schema.EVENT_FIELDS` may be stored, and
argument VALUES are never stored — only argument KEY NAMES in
``arg_keys``. Free-text fields are scrubbed of any secret-looking
substring (provider detector patterns + a generic high-entropy token
heuristic) before the event reaches the log or the validator.

This is the load-bearing rule of Pillar 3: the audit trail must never
become a second leak. Validation (:func:`audit.schema.validate_event`)
runs after redaction and is the backstop — it rejects anything that
still looks secret.
"""
from __future__ import annotations

import re
import uuid

from detectors.entropy import shannon_entropy
from detectors.registry import scan_line

from .schema import EVENT_FIELDS, utcnow_iso

REDACTED = "[REDACTED]"

# A token is "secret-looking" when it is long enough and random enough.
# Mirrors the scanner's generic fallback (registry.ENTROPY_THRESHOLD /
# MIN_GENERIC_LENGTH).
ENTROPY_THRESHOLD = 4.5
MIN_TOKEN_LENGTH = 16

# Split text into candidate tokens (letters/digits plus the separators
# that appear inside keys/tokens).
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-./+=]{16,}")

# Field names whose VALUE is always a credential, even when the value
# itself does not match a detector pattern. Their values are dropped
# outright (the key name may still appear in arg_keys).
SENSITIVE_KEY_NAMES = (
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "access_token", "auth_token", "token", "private_key", "client_secret",
    "bearer",
)


def find_pattern_hits(text: str) -> list[str]:
    """Secret-looking substrings matching a provider detector pattern
    (regex / context / entropy-fallback), WITHOUT the generic token
    entropy heuristic.

    Used for the cross-field fused check in validation: fusing fields
    without a separator merges neighbouring values into one long token,
    which would trip the entropy heuristic on innocent data. Provider
    patterns (``sk-`` + 48 chars, ``gsk_`` + ..., ...) are the signal
    that survives reassembly, so the fused check uses patterns only.
    """
    if not text:
        return []
    return [match.value for match in scan_line(text, allow_examples=True)]


def find_secret_hits(text: str) -> list[str]:
    """Return the secret-looking substrings found in ``text``.

    Two passes: the provider detector patterns (via ``scan_line`` with
    ``allow_examples=True`` so even marked test keys count — an audit
    log must not carry them either) and the generic high-entropy token
    heuristic. Example/test keys are NOT exempt here on purpose: the
    audit log is not a scan report, and a "test" key in an audit event
    is still a credential-shaped value that does not belong in the log.
    """
    if not text:
        return []
    hits: list[str] = []
    for match in scan_line(text, allow_examples=True):
        hits.append(match.value)
    for token in _TOKEN_RE.findall(text):
        if token in hits:
            continue
        if shannon_entropy(token) >= ENTROPY_THRESHOLD:
            hits.append(token)
    return hits


def contains_secret(text: str) -> bool:
    """True when ``text`` carries any secret-looking substring."""
    return bool(find_secret_hits(text))


def scrub_text(text: str) -> str:
    """Replace every secret-looking substring in ``text`` with
    ``[REDACTED]``. Longest hits first so a nested match does not leave
    a fragment behind."""
    if not text:
        return text
    for hit in sorted(set(find_secret_hits(text)), key=len, reverse=True):
        text = text.replace(hit, REDACTED)
    return text


def _arg_keys_from(raw: dict) -> list[str]:
    """Argument KEY NAMES only, from any argument-carrying field.

    Accepts ``arg_keys`` (already key names), ``args`` / ``arguments``
    (a dict — keys only, values dropped), or a list of key names.
    Values are never read, never stored.
    """
    keys: list[str] = []
    for field in ("arg_keys", "args", "arguments"):
        value = raw.get(field)
        if isinstance(value, dict):
            keys.extend(str(k) for k in value.keys())
        elif isinstance(value, list):
            keys.extend(str(k) for k in value)
    # De-duplicated, order-preserving.
    seen: set[str] = set()
    out: list[str] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def redact_event(raw: dict) -> dict:
    """Build a storable event from untrusted input.

    * Only allowlisted schema fields survive; everything else
      (``args``, ``arguments``, ``error``, nested blobs, unknown keys)
      is dropped.
    * ``arg_keys`` holds argument KEY NAMES only.
    * Free-text string fields are scrubbed of secret-looking substrings.
    * A raw ``error`` / ``error_message`` string is scrubbed and folded
      into ``decision.reason`` when no reason was supplied (error text
      is where leaked tokens usually hide).
    * ``event_hash`` / ``prev_hash`` are never accepted from input —
      the chain sets them at append time.
    * ``event_id`` / ``timestamp`` are server-assigned when absent:
      a uuid4 hex id and the current UTC time. A present-but-malformed
      value is left alone so validation still rejects it.
    """
    if not isinstance(raw, dict):
        raise ValueError("event must be a JSON object")

    event: dict = {}
    for f in EVENT_FIELDS:
        if f in ("event_hash", "prev_hash"):
            continue  # chain-owned, set at append time
        if f == "event_id":
            event["event_id"] = raw.get("event_id") or uuid.uuid4().hex
            continue
        if f == "timestamp":
            event["timestamp"] = raw.get("timestamp") or utcnow_iso()
            continue
        if f == "arg_keys":
            event["arg_keys"] = _arg_keys_from(raw)
            continue
        if f == "decision":
            decision = raw.get("decision")
            if not isinstance(decision, dict):
                decision = {}
            reason = decision.get("reason", "")
            if not reason and isinstance(raw.get("error"), str):
                reason = raw["error"]
            elif not reason and isinstance(raw.get("error_message"), str):
                reason = raw["error_message"]
            event["decision"] = {
                "allow": bool(decision.get("allow", True)),
                "policy": scrub_text(str(decision.get("policy", ""))),
                "reason": scrub_text(str(reason or "")),
            }
            continue
        if f == "confidence":
            confidence = raw.get("confidence")
            event["confidence"] = confidence if isinstance(
                confidence, (int, float)) and not isinstance(
                confidence, bool) else None
            continue
        value = raw.get(f, "")
        event[f] = scrub_text(str(value)) if isinstance(value, str) else value
    return event
