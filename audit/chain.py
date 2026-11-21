"""Hash-chained, append-only JSONL audit log.

Each event's ``event_hash`` covers the previous event's hash (see
:mod:`audit.schema`), so any later edit to any line breaks verification
from that line onward. Log ATTEMPTS, not only successes — a denial is
often the most important record, so ``append_event`` stores whatever
redacted + validated event it is given, whatever its outcome.

Retention (see :mod:`audit.export` / ``audit.py retention``) moves old
events to archive files. A hot log whose first event is NOT genesis
therefore continues a chain that lives in the archive: ``verify_chain``
reports that first event as ``continued`` (not a failure) as long as its
own hash recomputes correctly.
"""
from __future__ import annotations

import json
import os

from .schema import (
    GENESIS_PREV_HASH,
    canonical_json,
    compute_event_hash,
    validate_event,
)

DEFAULT_LOG_PATH = os.path.join("audit", "audit.jsonl")


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)


def read_events(log_path: str) -> list[dict]:
    """Read all events from a JSONL log file (empty list when missing)."""
    if not os.path.exists(log_path):
        return []
    events: list[dict] = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def last_event_hash(log_path: str) -> str:
    """event_hash of the last event in the log, or genesis when empty."""
    events = read_events(log_path)
    if not events:
        return GENESIS_PREV_HASH
    return str(events[-1].get("event_hash", GENESIS_PREV_HASH))


def append_event(log_path: str, event: dict) -> dict:
    """Append one redacted event, chaining it to the previous hash.

    The caller must have run ``redact_event`` first; ``event`` must
    already carry ``event_id`` / ``timestamp`` etc. but must NOT carry
    ``event_hash`` (it is computed here). The stored event is returned.
    Raises ValueError when validation fails — nothing is appended.
    """
    stored = dict(event)
    stored.pop("event_hash", None)
    prev_hash = last_event_hash(log_path)
    stored["prev_hash"] = prev_hash
    stored["event_hash"] = compute_event_hash(stored, prev_hash)
    errors = validate_event(stored)
    if errors:
        raise ValueError("event rejected: " + "; ".join(errors))
    _ensure_parent(log_path)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(canonical_json(stored) + "\n")
    return stored


def verify_events(events: list[dict]) -> dict:
    """Recompute a chain held in memory. Returns per-event results plus
    the first bad index (None when the chain is intact)."""
    results: list[dict] = []
    first_bad: int | None = None
    prev_hash = GENESIS_PREV_HASH
    continued = False
    for index, event in enumerate(events):
        ok = True
        error: str | None = None
        stored_hash = event.get("event_hash")
        event_prev = event.get("prev_hash")
        if index == 0:
            if event_prev == GENESIS_PREV_HASH:
                pass  # genesis
            elif isinstance(event_prev, str) and len(event_prev) == 64:
                # Chain continues from an archived segment (retention).
                continued = True
            else:
                ok = False
                error = "first event prev_hash is neither genesis nor a hash"
        elif event_prev != prev_hash:
            ok = False
            error = (
                f"prev_hash does not match previous event_hash "
                f"(expected {prev_hash[:12]}..., got "
                f"{str(event_prev)[:12]}...)"
            )
        if ok:
            without_hash = {k: v for k, v in event.items()
                            if k != "event_hash"}
            expected = compute_event_hash(without_hash, str(event_prev))
            if expected != stored_hash:
                ok = False
                error = "event_hash does not recompute (event tampered)"
        if not ok and first_bad is None:
            first_bad = index
        results.append({
            "index": index,
            "event_id": event.get("event_id"),
            "ok": ok,
            "error": error,
            "continued": continued and index == 0,
        })
        if isinstance(stored_hash, str):
            prev_hash = stored_hash
    return {
        "ok": first_bad is None,
        "count": len(events),
        "first_bad_index": first_bad,
        "continued_from_archive": continued,
        "events": results,
    }


def verify_chain(log_path: str) -> dict:
    """Verify the whole chain in a log file. Missing file = empty chain,
    which verifies cleanly (0 events)."""
    return verify_events(read_events(log_path))
