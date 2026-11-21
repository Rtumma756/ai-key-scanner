"""Canonical audit-event schema for KeySentry Pillar 3 (Agent Audit Trail).

One structured JSON event per agent tool call / finding / action. This is
the canonical schema shared by the CLI and the web app (see
``key-sentry/lib/audit-redact.ts`` for the TypeScript mirror) and by the
sibling Pillar 1 / Pillar 2 agents that emit events in the same format —
implement it exactly as specified here.

Hash chain (tamper-evident, not just append-only)
-------------------------------------------------
``event_hash = sha256_hex(canonical_json(event WITHOUT event_hash)
+ prev_hash)``

where ``canonical_json`` is ``json.dumps(sort_keys=True,
separators=(",", ":"))`` and the event WITHOUT ``event_hash`` still
includes ``prev_hash``. The genesis event uses ``prev_hash = "0" * 64``.

Field rules (load-bearing)
--------------------------
* Argument VALUES are never stored — only argument KEY NAMES in
  ``arg_keys``. See :mod:`audit.redact`.
* ``decision.reason`` is free text and is scrubbed of secret-looking
  substrings before write. See :mod:`audit.redact`.
* Validation (:func:`validate_event`) is the backstop: it rejects any
  event carrying a secret-looking value in ANY field, including a secret
  split across fields (checked on the concatenation of the fields).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SCHEMA_VERSION = 1

GENESIS_PREV_HASH = "0" * 64

# The exact field set. ``redact_event`` drops anything not in this list.
EVENT_FIELDS = (
    "event_id",
    "event_type",
    "timestamp",
    "prev_hash",
    "event_hash",
    "principal_id",
    "parent_agent_id",
    "session_id",
    "policy_id",
    "ticket_of_record",
    "model_run_id",
    "agent_id",
    "agent_version",
    "model",
    "tool",
    "resource",
    "arg_keys",
    "decision",
    "outcome",
    "correlation_id",
    "confidence",
)

# Fields whose values are hex digests by construction; they are excluded
# from the cross-field secret scan (a uuid / sha256 hex string is not a
# secret, and including them could only fuse with a neighbour field).
DIGEST_FIELDS = ("event_id", "prev_hash", "event_hash")

REQUIRED_FIELDS = tuple(f for f in EVENT_FIELDS if f != "event_hash")

OUTCOMES = ("success", "denied", "error")

_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(obj: object) -> str:
    """The one canonical serialisation: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_event_hash(event_without_hash: dict, prev_hash: str) -> str:
    """sha256 of canonical_json(event WITHOUT event_hash) + prev_hash.

    ``event_without_hash`` must already include ``prev_hash`` as a field.
    """
    payload = canonical_json(event_without_hash) + prev_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def utcnow_iso() -> str:
    """Current UTC time as ISO-8601 (server time)."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditEvent:
    """A canonical audit event. ``event_hash`` is filled in by the chain
    at append time (:func:`audit.chain.append_event`), not by callers."""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    event_type: str = ""
    timestamp: str = field(default_factory=utcnow_iso)
    prev_hash: str = GENESIS_PREV_HASH
    event_hash: str = ""
    principal_id: str = ""
    parent_agent_id: str = ""
    session_id: str = ""
    policy_id: str = ""
    ticket_of_record: str = ""
    model_run_id: str = ""
    agent_id: str = ""
    agent_version: str = ""
    model: str = ""
    tool: str = ""
    resource: str = ""
    arg_keys: list = field(default_factory=list)
    decision: dict = field(default_factory=lambda: {
        "allow": True, "policy": "", "reason": ""})
    outcome: str = "success"
    correlation_id: str = ""
    # Optional confidence score (0.0-1.0) carried in decision metadata;
    # None means "not scored". Used by the confidence-floor detector.
    confidence: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        known = {f: data[f] for f in EVENT_FIELDS if f in data}
        return cls(**known)


def new_event(**kwargs) -> dict:
    """Build a fresh event dict with generated id + server timestamp.

    Pass any schema field as a keyword; unknown keywords are ignored
    (they must never reach the log — see :func:`audit.redact.redact_event`).
    """
    event = AuditEvent(**{k: v for k, v in kwargs.items()
                          if k in EVENT_FIELDS})
    return event.to_dict()


def validate_event(event: dict, check_secrets: bool = True) -> list[str]:
    """Validate an event dict. Returns a list of error strings (empty =
    valid). This is the backstop after redaction — it must never pass an
    event that still carries a secret-looking value."""
    errors: list[str] = []
    if not isinstance(event, dict):
        return ["event must be a JSON object"]
    for f in REQUIRED_FIELDS:
        if f not in event:
            errors.append(f"missing required field: {f}")
    if errors:
        return errors

    if not isinstance(event["event_id"], str) or not _HEX_32.match(event["event_id"]):
        errors.append("event_id must be a 32-char lowercase hex string (uuid4 hex)")
    if not isinstance(event["event_type"], str) or not event["event_type"]:
        errors.append("event_type must be a non-empty string")
    if not isinstance(event["timestamp"], str):
        errors.append("timestamp must be an ISO-8601 string")
    else:
        try:
            datetime.fromisoformat(event["timestamp"])
        except ValueError:
            errors.append("timestamp is not valid ISO-8601")
    if not isinstance(event["prev_hash"], str) or not _HEX_64.match(event["prev_hash"]):
        errors.append("prev_hash must be a 64-char lowercase hex string")
    if "event_hash" in event and event["event_hash"] not in ("", None):
        if not isinstance(event["event_hash"], str) or not _HEX_64.match(event["event_hash"]):
            errors.append("event_hash must be a 64-char lowercase hex string")
    for f in ("principal_id", "parent_agent_id", "session_id", "policy_id",
              "ticket_of_record", "model_run_id", "agent_id", "agent_version",
              "model", "tool", "resource", "correlation_id"):
        if not isinstance(event.get(f), str):
            errors.append(f"{f} must be a string")
    if not isinstance(event.get("arg_keys"), list) or not all(
            isinstance(k, str) for k in event["arg_keys"]):
        errors.append("arg_keys must be a list of strings")
    decision = event.get("decision")
    if not isinstance(decision, dict):
        errors.append("decision must be an object")
    else:
        if not isinstance(decision.get("allow"), bool):
            errors.append("decision.allow must be a boolean")
        if not isinstance(decision.get("policy"), str):
            errors.append("decision.policy must be a string")
        if not isinstance(decision.get("reason"), str):
            errors.append("decision.reason must be a string")
    if event.get("outcome") not in OUTCOMES:
        errors.append(f"outcome must be one of {OUTCOMES}")
    confidence = event.get("confidence")
    if confidence is not None and (
            not isinstance(confidence, (int, float)) or isinstance(confidence, bool)
            or not 0.0 <= confidence <= 1.0):
        errors.append("confidence must be null or a number between 0.0 and 1.0")

    if check_secrets:
        # Local import: redact.py does not import schema (no cycle).
        from .redact import find_pattern_hits, find_secret_hits
        for f in EVENT_FIELDS:
            if f in DIGEST_FIELDS:
                continue
            value = event.get(f)
            if isinstance(value, str) and find_secret_hits(value):
                errors.append(f"field {f} contains a secret-looking value")
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and find_secret_hits(item):
                        errors.append(f"field {f} contains a secret-looking value")
                        break
            elif isinstance(value, dict):
                for item in value.values():
                    if isinstance(item, str) and find_secret_hits(item):
                        errors.append(f"field {f} contains a secret-looking value")
                        break
        # Backstop for a secret SPLIT across fields: scan the fused
        # string fields (no separator, so a key split in two halves
        # reassembles into a detector match). Digest fields are excluded.
        # Patterns only — the entropy heuristic would trip on tokens
        # artificially merged by the fusion (see find_pattern_hits).
        parts: list[str] = []
        for f in EVENT_FIELDS:
            if f in DIGEST_FIELDS:
                continue
            value = event.get(f)
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                parts.extend(str(x) for x in value)
            elif isinstance(value, dict):
                parts.extend(str(x) for x in value.values())
        if find_pattern_hits("".join(parts)):
            errors.append("event carries a secret-looking value split across fields")
    return errors
