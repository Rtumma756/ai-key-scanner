"""Five first detections over audit events (pure functions, no DB).

Same five detectors, same names and same thresholds as the web mirror
(``key-sentry/lib/audit-detections.ts``). Each detector takes a list of
canonical event dicts and returns a list of alerts::

    {"detector": ..., "severity": "low|medium|high",
     "evidence_event_ids": [...], "summary": ...}

1. tool_set_drift — an agent calls a tool outside its established set.
2. cost_spike — event count per (agent, model) per hour vs the trailing
   baseline, above threshold (event count is the token/cost proxy).
3. confidence_floor_breach — events carrying a confidence score below
   the floor.
4. cross_tenant_access — one agent touching resources of two different
   tenants (resource tenant prefix differs).
5. sub_agent_fanout — a parent agent spawning children above threshold
   in a window.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

# Thresholds — mirrored in lib/audit-detections.ts. Change both together.
TOOL_DRIFT_BASELINE_EVENTS = 5
COST_SPIKE_THRESHOLD = 3.0
COST_SPIKE_MIN_EVENTS = 10
CONFIDENCE_FLOOR = 0.7
FANOUT_MAX_CHILDREN = 5
FANOUT_WINDOW_SECONDS = 3600


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


def _sorted_events(events: list[dict]) -> list[dict]:
    return sorted(events, key=lambda e: str(e.get("timestamp", "")))


def _tenant_of(resource: str) -> str | None:
    """Tenant prefix of a resource.

    ``tenant:acme/db/users`` -> ``acme``; ``acme/db/users`` -> ``acme``;
    anything without a tenant-shaped prefix -> None.
    """
    if not resource:
        return None
    rest = resource
    if rest.startswith("tenant:"):
        rest = rest[len("tenant:"):]
    elif ":" in rest.split("/")[0]:
        rest = rest.split(":", 1)[1]
    else:
        return None
    tenant = rest.split("/")[0].strip()
    return tenant or None


def detect_tool_set_drift(
    events: list[dict],
    baseline_events: int = TOOL_DRIFT_BASELINE_EVENTS,
) -> list[dict]:
    """An agent calls a tool outside the set established by its first
    ``baseline_events`` events. One alert per agent, listing the new
    tools and the evidence events."""
    alerts: list[dict] = []
    by_agent: dict[str, list[dict]] = defaultdict(list)
    for event in _sorted_events(events):
        agent = event.get("agent_id") or ""
        if agent:
            by_agent[agent].append(event)
    for agent, agent_events in by_agent.items():
        if len(agent_events) <= baseline_events:
            continue
        baseline = {e.get("tool", "") for e in agent_events[:baseline_events]}
        new_tools: dict[str, list[str]] = defaultdict(list)
        for event in agent_events[baseline_events:]:
            tool = event.get("tool", "")
            if tool and tool not in baseline:
                new_tools[tool].append(str(event.get("event_id", "")))
        for tool, ids in sorted(new_tools.items()):
            alerts.append({
                "detector": "tool_set_drift",
                "severity": "medium",
                "evidence_event_ids": ids,
                "summary": (
                    f"Agent {agent} called tool '{tool}' outside its "
                    f"established tool set ({sorted(baseline)})."
                ),
            })
    return alerts


def detect_cost_spike(
    events: list[dict],
    threshold: float = COST_SPIKE_THRESHOLD,
    min_events: int = COST_SPIKE_MIN_EVENTS,
) -> list[dict]:
    """Event count per (agent, model) per hour vs the trailing mean of
    prior hours. Alert when an hour's count is >= ``min_events`` and >=
    ``threshold`` x the trailing baseline (baseline must be > 0)."""
    alerts: list[dict] = []
    buckets: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for event in events:
        ts = _parse_ts(event.get("timestamp", ""))
        if ts is None:
            continue
        hour = ts.strftime("%Y-%m-%dT%H:00:00")
        key = (event.get("agent_id") or "", event.get("model") or "", hour)
        buckets[key].append(event)
    hours_by_agent_model: dict[tuple[str, str], dict[str, int]] = defaultdict(dict)
    ids_by_key: dict[tuple[str, str, str], list[str]] = {}
    for (agent, model, hour), hour_events in buckets.items():
        hours_by_agent_model[(agent, model)][hour] = len(hour_events)
        ids_by_key[(agent, model, hour)] = [
            str(e.get("event_id", "")) for e in hour_events]
    for (agent, model), hours in hours_by_agent_model.items():
        ordered = sorted(hours)
        for i, hour in enumerate(ordered):
            if i == 0:
                continue  # no trailing baseline for the first hour
            prior = [hours[h] for h in ordered[:i]]
            baseline = sum(prior) / len(prior)
            count = hours[hour]
            if baseline > 0 and count >= min_events and count >= threshold * baseline:
                alerts.append({
                    "detector": "cost_spike",
                    "severity": "high",
                    "evidence_event_ids": ids_by_key[(agent, model, hour)],
                    "summary": (
                        f"Agent {agent} ({model}) logged {count} events "
                        f"in hour {hour}, {count / baseline:.1f}x its "
                        f"trailing baseline of {baseline:.1f}/hour "
                        f"(threshold {threshold}x, min {min_events})."
                    ),
                })
    return alerts


def detect_confidence_floor(
    events: list[dict],
    floor: float = CONFIDENCE_FLOOR,
) -> list[dict]:
    """Events carrying a confidence score below ``floor``. One alert per
    agent, with the lowest score in the summary."""
    alerts: list[dict] = []
    by_agent: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        confidence = event.get("confidence")
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
            if confidence < floor:
                by_agent[event.get("agent_id") or ""].append(event)
    for agent, agent_events in sorted(by_agent.items()):
        ids = [str(e.get("event_id", "")) for e in agent_events]
        lowest = min(float(e["confidence"]) for e in agent_events)
        alerts.append({
            "detector": "confidence_floor_breach",
            "severity": "high" if lowest < 0.5 else "medium",
            "evidence_event_ids": ids,
            "summary": (
                f"Agent {agent or '(unknown)'} had {len(agent_events)} "
                f"event(s) below the confidence floor {floor} "
                f"(lowest {lowest:.2f})."
            ),
        })
    return alerts


def detect_cross_tenant_access(events: list[dict]) -> list[dict]:
    """One agent touching resources of two different tenants. One alert
    per agent, listing the tenants and the evidence events."""
    alerts: list[dict] = []
    by_agent: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list))
    for event in events:
        tenant = _tenant_of(event.get("resource", "") or "")
        if tenant is None:
            continue
        agent = event.get("agent_id") or ""
        by_agent[agent][tenant].append(str(event.get("event_id", "")))
    for agent, tenants in sorted(by_agent.items()):
        if len(tenants) < 2:
            continue
        ids = [eid for tenant_ids in tenants.values() for eid in tenant_ids]
        alerts.append({
            "detector": "cross_tenant_access",
            "severity": "high",
            "evidence_event_ids": ids,
            "summary": (
                f"Agent {agent or '(unknown)'} touched {len(tenants)} "
                f"tenants in one trail: {sorted(tenants)}."
            ),
        })
    return alerts


def detect_subagent_fanout(
    events: list[dict],
    max_children: int = FANOUT_MAX_CHILDREN,
    window_seconds: int = FANOUT_WINDOW_SECONDS,
) -> list[dict]:
    """A parent agent spawning more than ``max_children`` distinct child
    agents inside any ``window_seconds`` window. One alert per parent,
    at the first window that breaches."""
    alerts: list[dict] = []
    by_parent: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        parent = event.get("parent_agent_id") or ""
        child = event.get("agent_id") or ""
        if parent and child and child != parent:
            by_parent[parent].append(event)
    for parent, parent_events in sorted(by_parent.items()):
        parsed = [(e, _parse_ts(e.get("timestamp", "")))
                  for e in _sorted_events(parent_events)]
        parsed = [(e, ts) for e, ts in parsed if ts is not None]
        for i, (event, ts) in enumerate(parsed):
            window = [(e, t) for e, t in parsed[i:]
                      if (t - ts).total_seconds() <= window_seconds]
            children = {e.get("agent_id") for e, _ in window}
            if len(children) > max_children:
                alerts.append({
                    "detector": "sub_agent_fanout",
                    "severity": "high",
                    "evidence_event_ids": [
                        str(e.get("event_id", "")) for e, _ in window],
                    "summary": (
                        f"Parent agent {parent} spawned "
                        f"{len(children)} distinct child agents within "
                        f"{window_seconds}s (max {max_children}): "
                        f"{sorted(children)}."
                    ),
                })
                break  # one alert per parent, at the first breach
    return alerts


DETECTORS = (
    detect_tool_set_drift,
    detect_cost_spike,
    detect_confidence_floor,
    detect_cross_tenant_access,
    detect_subagent_fanout,
)


def run_all_detections(events: list[dict]) -> list[dict]:
    """Run all five detectors over an event list, in detector order."""
    alerts: list[dict] = []
    for detector in DETECTORS:
        alerts.extend(detector(events))
    return alerts
