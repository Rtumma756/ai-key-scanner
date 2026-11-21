"""KeySentry audit trail — canonical events, redaction, hash chain,
detections, compliance export. See docs/commercial/AUDIT-RETENTION.md
for the retention policy.
"""
from .chain import append_event, read_events, verify_chain, verify_events
from .detections import run_all_detections
from .export import (
    eu_ai_act_report,
    iso27001_report,
    siem_export,
    soc2_report,
)
from .redact import contains_secret, redact_event, scrub_text
from .schema import (
    GENESIS_PREV_HASH,
    AuditEvent,
    canonical_json,
    compute_event_hash,
    new_event,
    validate_event,
)

__all__ = [
    "GENESIS_PREV_HASH",
    "AuditEvent",
    "append_event",
    "canonical_json",
    "compute_event_hash",
    "contains_secret",
    "eu_ai_act_report",
    "iso27001_report",
    "new_event",
    "read_events",
    "redact_event",
    "run_all_detections",
    "scrub_text",
    "siem_export",
    "soc2_report",
    "validate_event",
    "verify_chain",
    "verify_events",
]
