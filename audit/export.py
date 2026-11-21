"""Compliance export for audit events.

Mapping tables are shared with the web mirror
(``key-sentry/lib/audit-export.ts``) — keep the control lists in sync
and note any intentional divergence in the coordinator report, not here.

IMPORTANT — these are MAPPING TEMPLATES, not certification claims.
KeySentry is not SOC 2 certified, not ISO 27001 certified, and this
export does not certify compliance with the EU AI Act. The mappings show
which logged events an auditor would look at for each control; a real
audit still needs the organisation's own policies, access reviews and
auditor judgement. Every report carries this disclaimer in its header.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .schema import utcnow_iso

DISCLAIMER = (
    "Mapping template only — NOT a certification claim. KeySentry is not "
    "SOC 2 or ISO 27001 certified, and this export does not certify "
    "compliance with the EU AI Act. It maps logged audit events to the "
    "controls / articles an auditor would examine; a real audit requires "
    "the organisation's own policies and an auditor's judgement."
)

# SOC 2 Trust Services Criteria mapping: control -> event types that
# evidence it. "any" matches every event type.
SOC2_CONTROLS = [
    {"control": "CC6.1", "name": "Logical access — access restricted to authorised users",
     "event_types": ["mcp.tool_call", "agent.action"]},
    {"control": "CC6.6", "name": "Logical access — encryption / protection of credentials",
     "event_types": ["vibe.finding"]},
    {"control": "CC7.2", "name": "Monitoring — system components monitored for anomalies",
     "event_types": ["any"]},
    {"control": "CC7.3", "name": "Monitoring — anomalies evaluated and acted on",
     "event_types": ["agent.action", "vibe.finding"]},
    {"control": "CC8.1", "name": "Change management — changes authorised and tested",
     "event_types": ["agent.action"]},
]

# ISO/IEC 27001:2022 Annex A mapping.
ISO27001_CONTROLS = [
    {"control": "A.12.4.1", "name": "Event logging",
     "event_types": ["any"]},
    {"control": "A.12.4.2", "name": "Protection of log information",
     "event_types": ["any"]},
    {"control": "A.12.4.3", "name": "Administrator and operator logs",
     "event_types": ["mcp.tool_call", "agent.action"]},
    {"control": "A.9.2.1", "name": "User registration and de-registration",
     "event_types": ["agent.action"]},
    {"control": "A.9.4.2", "name": "Secure log-on procedures",
     "event_types": ["mcp.tool_call"]},
    {"control": "A.8.15", "name": "Logging",
     "event_types": ["any"]},
]

# EU AI Act Article 12 (record-keeping) — the fields Art. 12 requires a
# high-risk AI system to log for traceability.
EU_AI_ACT_ARTICLE = "12"


def _matched_events(events: list[dict], event_types: list[str]) -> list[dict]:
    if "any" in event_types:
        return list(events)
    return [e for e in events if e.get("event_type") in event_types]


def _control_report(events: list[dict], controls: list[dict],
                    framework: str) -> dict:
    covered_types = {e.get("event_type") for e in events}
    control_rows = []
    for control in controls:
        matched = _matched_events(events, control["event_types"])
        control_rows.append({
            "control": control["control"],
            "name": control["name"],
            "events_matched": len(matched),
            "event_ids": [str(e.get("event_id")) for e in matched],
        })
    return {
        "framework": framework,
        "disclaimer": DISCLAIMER,
        "generated_at": utcnow_iso(),
        "event_count": len(events),
        "event_types_seen": sorted(t for t in covered_types if t),
        "controls": control_rows,
    }


def soc2_report(events: list[dict]) -> dict:
    """SOC 2 control mapping report (template, not a certification)."""
    return _control_report(events, SOC2_CONTROLS, "SOC 2")


def iso27001_report(events: list[dict]) -> dict:
    """ISO/IEC 27001 Annex A control mapping report (template)."""
    return _control_report(events, ISO27001_CONTROLS, "ISO 27001")


def eu_ai_act_report(events: list[dict]) -> dict:
    """EU AI Act Article 12 record-keeping report.

    Art. 12 requires logging that lets an operation be traced: what
    happened, when, by whom (actor), and what was decided. Each record
    below carries exactly those fields.
    """
    records = []
    for event in events:
        decision = event.get("decision") or {}
        records.append({
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp"),
            "actor": {
                "principal_id": event.get("principal_id"),
                "agent_id": event.get("agent_id"),
                "agent_version": event.get("agent_version"),
                "model": event.get("model"),
                "model_run_id": event.get("model_run_id"),
            },
            "operation": {
                "event_type": event.get("event_type"),
                "tool": event.get("tool"),
                "resource": event.get("resource"),
                "arg_keys": event.get("arg_keys"),
            },
            "decision": {
                "allow": decision.get("allow"),
                "policy": decision.get("policy"),
                "reason": decision.get("reason"),
            },
            "outcome": event.get("outcome"),
            "correlation_id": event.get("correlation_id"),
            "session_id": event.get("session_id"),
        })
    return {
        "framework": "EU AI Act",
        "article": EU_AI_ACT_ARTICLE,
        "article_title": "Record-keeping",
        "disclaimer": DISCLAIMER,
        "generated_at": utcnow_iso(),
        "event_count": len(events),
        "records": records,
    }


def siem_export(events: list[dict]) -> str:
    """SIEM-friendly export: one JSON object per line, canonical form."""
    from .schema import canonical_json
    return "".join(canonical_json(e) + "\n" for e in events)


def render_markdown(report: dict) -> str:
    """Human-readable Markdown rendering of a SOC 2 / ISO 27001 / EU AI
    Act report dict."""
    framework = report.get("framework", "")
    lines = [f"# {framework} — audit-trail export", ""]
    if report.get("article"):
        lines.append(
            f"Article {report['article']}: "
            f"{report.get('article_title', '')}")
        lines.append("")
    lines.append(f"> {report.get('disclaimer', '')}")
    lines.append("")
    lines.append(f"Generated: {report.get('generated_at', '')}")
    lines.append(f"Events: {report.get('event_count', 0)}")
    lines.append("")
    if "controls" in report:
        lines.append("## Control mapping")
        lines.append("")
        lines.append("| Control | Name | Events matched |")
        lines.append("| --- | --- | ---: |")
        for row in report["controls"]:
            lines.append(
                f"| {row['control']} | {row['name']} | "
                f"{row['events_matched']} |")
        lines.append("")
    if "records" in report:
        lines.append("## Records (Article 12 trace)")
        lines.append("")
        for record in report["records"]:
            actor = record["actor"]
            operation = record["operation"]
            lines.append(
                f"- `{record['timestamp']}` {record['event_id']} — "
                f"{operation.get('event_type')} / "
                f"{operation.get('tool')} on {operation.get('resource')} "
                f"by agent {actor.get('agent_id')} "
                f"(principal {actor.get('principal_id')}), "
                f"decision allow={record['decision'].get('allow')} "
                f"({record['decision'].get('policy')}), "
                f"outcome {record['outcome']}.")
        lines.append("")
    return "\n".join(lines)


def retention_windows() -> dict:
    """Retention policy: hot 30d / warm 90d / cold 7y (pilot: 90 days
    total — see docs/commercial/AUDIT-RETENTION.md)."""
    return {"hot_days": 30, "warm_days": 90, "cold_years": 7,
            "pilot_total_days": 90}


def apply_retention(log_path: str, archive_dir: str, hot_days: int = 30,
                    warm_days: int = 90,
                    now: datetime | None = None) -> dict:
    """Move events older than the hot window out of the hot log.

    * Events older than ``hot_days`` move to ``audit-warm.jsonl``.
    * Events older than ``warm_days`` move to ``audit-cold.jsonl``.
    * The hot log keeps the rest, in original order, lines verbatim
      (hashes untouched — the chain continues from the archive; see
      :func:`audit.chain.verify_chain`).
    Returns counts. Dry-run when ``apply`` is False is done by the CLI
    (it calls :func:`plan_retention` instead).
    """
    from .chain import read_events
    import os
    now = now or datetime.now(timezone.utc)
    events = read_events(log_path)
    plan = plan_retention(events, hot_days, warm_days, now)
    os.makedirs(archive_dir, exist_ok=True)
    warm_path = os.path.join(archive_dir, "audit-warm.jsonl")
    cold_path = os.path.join(archive_dir, "audit-cold.jsonl")
    if plan["warm"]:
        with open(warm_path, "a", encoding="utf-8") as f:
            for line in plan["warm_lines"]:
                f.write(line)
    if plan["cold"]:
        with open(cold_path, "a", encoding="utf-8") as f:
            for line in plan["cold_lines"]:
                f.write(line)
    with open(log_path, "w", encoding="utf-8") as f:
        for line in plan["hot_lines"]:
            f.write(line)
    return {"hot": len(plan["hot"]), "warm": len(plan["warm"]),
            "cold": len(plan["cold"]),
            "warm_path": warm_path, "cold_path": cold_path}


def plan_retention(events: list[dict], hot_days: int = 30,
                   warm_days: int = 90,
                   now: datetime | None = None) -> dict:
    """Partition events into hot / warm / cold without moving anything.
    Returns the event dicts plus their original verbatim JSONL lines."""
    from datetime import timedelta
    from .schema import canonical_json
    now = now or datetime.now(timezone.utc)
    hot_cutoff = now - timedelta(days=hot_days)
    warm_cutoff = now - timedelta(days=warm_days)
    hot, warm, cold = [], [], []
    hot_lines, warm_lines, cold_lines = [], [], []
    for event in events:
        ts = event.get("timestamp", "")
        try:
            when = datetime.fromisoformat(str(ts))
        except ValueError:
            when = now  # unparseable timestamp: keep hot, never lose it
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        line = canonical_json(event) + "\n"
        if when <= warm_cutoff:
            cold.append(event)
            cold_lines.append(line)
        elif when <= hot_cutoff:
            warm.append(event)
            warm_lines.append(line)
        else:
            hot.append(event)
            hot_lines.append(line)
    return {"hot": hot, "warm": warm, "cold": cold,
            "hot_lines": hot_lines, "warm_lines": warm_lines,
            "cold_lines": cold_lines}
