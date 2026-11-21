#!/usr/bin/env python3
"""plans.py — KeySentry freemium plan definitions (CLI side).

One source of truth: docs/commercial/plans.json (Free / Maker /
Starter / Team / Business / Enterprise). This module loads it and
answers the three questions every gate needs:

  get_plan(plan)                 -> tier dict (unknown/missing -> Free)
  feature_allowed(plan, feature) -> bool
  check_limit(plan, resource, used) -> (allowed, message)
  upgrade_message(plan, feature) -> str naming the next tier, its
          price, and exactly what it unlocks

Free-never-locked-out rule: when the plan file is missing or a plan id
is unknown, the system defaults to Free and ALL free-layer
capabilities keep working; commercial features return an upgrade
prompt, never a crash or a silent block. The same rule is encoded in
lib/plans.ts on the web side — the wording of the messages comes from
plans.json, so both sides stay identical.

Local plan state (dev/testing only) lives in .key-sentry-plan.json
next to this file. Real plan state comes from billing (Stripe webhook
-> workspace_plans); `set-plan` prints that warning every time.

Importable without side effects: importing this module reads nothing
and never raises — the plan file is loaded lazily, with a built-in
fallback if it is missing.

Standalone:
  python3 plans.py show            print current plan + limits
  python3 plans.py set-plan <tier> set the local dev plan (free,
                                   maker, starter, team, business,
                                   enterprise)
  python3 plans.py counters        print today's daily-cap counters
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

_PLANS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "docs", "commercial", "plans.json")

PLAN_STATE_FILENAME = ".key-sentry-plan.json"

# Built-in fallback used ONLY when plans.json cannot be read. Same
# numbers as the canonical file; free features keep working, paid
# features still name the right next tier. This is what makes the
# free layer survive a missing plan file instead of crashing.
_FALLBACK_PLANS = {
    "version": 2,
    "tier_order": ["free", "maker", "starter", "premium", "team",
                   "premium_plus", "business", "enterprise"],
    "upgrade_template": "Upgrade to {tier} (${price}/mo) to unlock {unlocks}.",
    "upgrade_template_custom": "Upgrade to {tier} (custom pricing) to unlock {unlocks}.",
    "limit_message_template": "{plan} plan allows up to {limit} {label} (you have {used}).",
    "daily_limit_message_template": "{plan} plan allows up to {limit} {label} (you have used {used} today).",
    "daily_cap_suffix": "Come back tomorrow, it works again (free caps reset at midnight UTC).",
    "resources": {
        "fingerprints": {"label": "fingerprints",
                         "upgrade_feature": "fingerprint_monitoring"},
        "repos": {"label": "repos"},
        "scans_per_day": {"label": "vibe-code scans per day",
                          "daily": True, "reset": "midnight UTC",
                          "next_tier": "maker",
                          "upgrade_unlocks": "unlimited vibe-code scans"},
        "audit_timeline_agents": {"label": "agents on the audit timeline",
                                  "upgrade_feature": "full_audit_timeline"},
        "vibe_reports": {"label": "vibe-code reports",
                         "upgrade_feature": "vibe_monitoring"},
        "audits_per_day": {"label": "agent identity audits per day",
                           "daily": True, "reset": "midnight UTC",
                           "next_tier": "starter",
                           "upgrade_unlocks": "unlimited agent identity audits"},
        "mcp_queries_per_day": {"label": "MCP server queries per day",
                                "daily": True, "reset": "midnight UTC",
                                "next_tier": "maker",
                                "upgrade_unlocks": "unlimited MCP server queries"},
        "dashboard_saves_per_day": {"label": "dashboard saves per day",
                                    "daily": True, "reset": "midnight UTC",
                                    "next_tier": "maker",
                                    "upgrade_unlocks": "unlimited dashboard saves"},
        "shareable_reports": {"label": "shareable reports in the free list",
                              "next_tier": "maker",
                              "upgrade_unlocks": "unlimited shareable reports"},
        "audit_timeline_days": {"label": "days of audit history"},
        "seats": {"label": "team seats",
                  "next_tier": "team",
                  "upgrade_unlocks": "5 team seats"},
        "fingerprint_checks_per_day": {
            "label": "fingerprint checks per day",
            "daily": True, "reset": "midnight UTC",
            "next_tier": "starter",
            "upgrade_unlocks": "automatic fingerprint monitoring — re-checks as often as you like"},
    },
    "features": {
        "fingerprint_monitoring": {
            "label": "Fingerprint monitoring",
            "unlocks": "fingerprint monitoring — alerts when a watched key resurfaces in public code",
        },
        "fix_prs": {
            "label": "Fix PRs",
            "unlocks": "fix PRs — one-click pull requests that rotate a leaked key and re-scan to prove the fix",
        },
        "email_alerts": {
            "label": "Email alerts",
            "unlocks": "email alerts when a monitored fingerprint appears in public code",
        },
        "vibe_monitoring": {
            "label": "Vibe-code monitoring",
            "unlocks": "continuous vibe-code monitoring of your repos",
        },
        "slack_alerts": {
            "label": "Slack alerts",
            "unlocks": "Slack alerts when a monitored fingerprint appears in public code",
        },
        "remediation_workflow": {
            "label": "Remediation workflow",
            "unlocks": "the remediation workflow — guided rotation playbooks and re-scan proof a leak is fixed",
        },
        "owner_verification": {
            "label": "Owner verification",
            "unlocks": "owner verification of your own keys",
        },
        "exports": {
            "label": "Exports",
            "unlocks": "exports of findings and posture reports",
        },
        "full_audit_timeline": {
            "label": "Full audit timeline",
            "unlocks": "the full audit timeline for every agent, not just one",
        },
        "audit_logs": {
            "label": "Audit logs",
            "unlocks": "audit logs — the hash-chained, append-only record an auditor will accept",
        },
        "compliance_export": {
            "label": "Compliance export",
            "unlocks": "compliance export — SOC 2 / ISO 27001 control mapping, EU AI Act Article 12 report, SIEM export",
        },
        "detections": {
            "label": "Audit detections",
            "unlocks": "the five audit detections — tool-set drift, cost spike, confidence-floor breach, cross-tenant access, sub-agent fan-out anomaly",
        },
        "policy_controls": {
            "label": "Policy controls",
            "unlocks": "policy controls and team policy gates",
        },
        "api": {"label": "API access", "unlocks": "API access to KeySentry"},
        "sla": {"label": "SLA", "unlocks": "an uptime SLA"},
        "priority_support": {
            "label": "Priority support",
            "unlocks": "priority support — faster help when a scan or an alert needs a human",
        },
        "sso": {"label": "SSO", "unlocks": "SSO (single sign-on)"},
        "private_deployment": {
            "label": "Private deployment",
            "unlocks": "a private deployment of KeySentry",
        },
        "scan_one_repo": {
            "label": "One-repo scan",
            "unlocks": "one-repo scans with shareable reports",
        },
        "mcp_read_only": {
            "label": "MCP server read-only queries",
            "unlocks": "MCP server read-only queries (\"are my keys exposed?\")",
        },
        "audit_timeline_one_agent": {
            "label": "One-agent audit timeline",
            "unlocks": "an audit timeline for one agent",
        },
        "vibe_report_one_repo": {
            "label": "One-repo vibe-code report",
            "unlocks": "a vibe-code security report for one repo, with plain-language fixes",
        },
    },
    "tiers": {
        "free": {
            "id": "free", "name": "Free", "price_monthly_usd": 0,
            "price_label": "$0",
            "limits": {"repos": 1, "fingerprints": 5, "scans_per_day": 2,
                       "audit_timeline_agents": 1, "vibe_reports": 1,
                       "audits_per_day": 2, "mcp_queries_per_day": 100,
                       "dashboard_saves_per_day": 2,
                       "shareable_reports": 2, "audit_timeline_days": 7,
                       "seats": 1, "fingerprint_checks_per_day": 1},
            "features": ["scan_one_repo", "mcp_read_only",
                         "audit_timeline_one_agent", "vibe_report_one_repo"],
        },
        "maker": {
            "id": "maker", "name": "Maker", "price_monthly_usd": 19,
            "price_label": "$19/mo",
            "limits": {"repos": 5, "fingerprints": 5, "scans_per_day": None,
                       "audit_timeline_agents": 1, "vibe_reports": 5,
                       "audits_per_day": 2, "mcp_queries_per_day": None,
                       "dashboard_saves_per_day": None,
                       "shareable_reports": None, "audit_timeline_days": 30,
                       "seats": 1, "fingerprint_checks_per_day": 1},
            "features": ["scan_one_repo", "mcp_read_only",
                         "audit_timeline_one_agent", "vibe_report_one_repo",
                         "vibe_monitoring", "fix_prs"],
        },
        "starter": {
            "id": "starter", "name": "Starter", "price_monthly_usd": 49,
            "price_label": "$49/mo",
            "limits": {"repos": 5, "fingerprints": 25, "scans_per_day": None,
                       "audit_timeline_agents": 1, "vibe_reports": 5,
                       "audits_per_day": None, "mcp_queries_per_day": None,
                       "dashboard_saves_per_day": None,
                       "shareable_reports": None, "audit_timeline_days": 30,
                       "seats": 1, "fingerprint_checks_per_day": None},
            "features": ["scan_one_repo", "mcp_read_only",
                         "audit_timeline_one_agent", "vibe_report_one_repo",
                         "fingerprint_monitoring", "email_alerts",
                         "vibe_monitoring", "fix_prs"],
        },
        "premium": {
            "id": "premium", "name": "Premium", "price_monthly_usd": 99,
            "price_label": "$99/mo",
            "limits": {"repos": 15, "fingerprints": 75,
                       "scans_per_day": None,
                       "audit_timeline_agents": 1, "vibe_reports": None,
                       "audits_per_day": None,
                       "mcp_queries_per_day": 5000,
                       "dashboard_saves_per_day": None,
                       "shareable_reports": None, "audit_timeline_days": 60,
                       "seats": 5, "fingerprint_checks_per_day": None},
            "features": ["scan_one_repo", "mcp_read_only",
                         "audit_timeline_one_agent", "vibe_report_one_repo",
                         "fingerprint_monitoring", "email_alerts",
                         "vibe_monitoring", "slack_alerts",
                         "remediation_workflow", "fix_prs"],
        },
        "team": {
            "id": "team", "name": "Team", "price_monthly_usd": 149,
            "price_label": "$149/mo",
            "limits": {"repos": None, "fingerprints": None,
                       "scans_per_day": None, "audit_timeline_agents": None,
                       "vibe_reports": None,
                       "audits_per_day": None, "mcp_queries_per_day": None,
                       "dashboard_saves_per_day": None,
                       "shareable_reports": None, "audit_timeline_days": 90,
                       "seats": 5, "fingerprint_checks_per_day": None},
            "features": ["scan_one_repo", "mcp_read_only",
                         "audit_timeline_one_agent", "vibe_report_one_repo",
                         "fingerprint_monitoring", "email_alerts",
                         "vibe_monitoring", "slack_alerts",
                         "remediation_workflow", "owner_verification",
                         "exports", "full_audit_timeline", "fix_prs"],
        },
        "premium_plus": {
            "id": "premium_plus", "name": "Premium Plus",
            "price_monthly_usd": 299, "price_label": "$299/mo",
            "limits": {"repos": None, "fingerprints": None,
                       "scans_per_day": None, "audit_timeline_agents": None,
                       "vibe_reports": None,
                       "audits_per_day": None, "mcp_queries_per_day": None,
                       "dashboard_saves_per_day": None,
                       "shareable_reports": None,
                       "audit_timeline_days": 180,
                       "seats": 25, "fingerprint_checks_per_day": None},
            "features": ["scan_one_repo", "mcp_read_only",
                         "audit_timeline_one_agent", "vibe_report_one_repo",
                         "fingerprint_monitoring", "email_alerts",
                         "vibe_monitoring", "slack_alerts",
                         "remediation_workflow", "owner_verification",
                         "exports", "full_audit_timeline", "fix_prs",
                         "api", "priority_support"],
        },
        "business": {
            "id": "business", "name": "Business", "price_monthly_usd": 499,
            "price_label": "$499/mo",
            "limits": {"repos": None, "fingerprints": None,
                       "scans_per_day": None, "audit_timeline_agents": None,
                       "vibe_reports": None,
                       "audits_per_day": None, "mcp_queries_per_day": None,
                       "dashboard_saves_per_day": None,
                       "shareable_reports": None,
                       "audit_timeline_days": 2555,
                       "seats": None, "fingerprint_checks_per_day": None},
            "features": ["scan_one_repo", "mcp_read_only",
                         "audit_timeline_one_agent", "vibe_report_one_repo",
                         "fingerprint_monitoring", "email_alerts",
                         "vibe_monitoring", "slack_alerts",
                         "remediation_workflow", "owner_verification",
                         "exports", "full_audit_timeline", "audit_logs",
                         "compliance_export", "detections",
                         "policy_controls", "api", "sla", "fix_prs"],
        },
        "enterprise": {
            "id": "enterprise", "name": "Enterprise",
            "price_monthly_usd": None, "price_label": "Custom",
            "limits": {"repos": None, "fingerprints": None,
                       "scans_per_day": None, "audit_timeline_agents": None,
                       "vibe_reports": None,
                       "audits_per_day": None, "mcp_queries_per_day": None,
                       "dashboard_saves_per_day": None,
                       "shareable_reports": None, "audit_timeline_days": None,
                       "seats": None, "fingerprint_checks_per_day": None},
            "features": ["scan_one_repo", "mcp_read_only",
                         "audit_timeline_one_agent", "vibe_report_one_repo",
                         "fingerprint_monitoring", "email_alerts",
                         "vibe_monitoring", "slack_alerts",
                         "remediation_workflow", "owner_verification",
                         "exports", "full_audit_timeline", "audit_logs",
                         "compliance_export", "detections",
                         "policy_controls", "api", "sla", "sso",
                         "private_deployment", "fix_prs"],
        },
    },
}

DEFAULT_PLAN_ID = "free"


def load_plans(path: str | None = None) -> dict:
    """Load the canonical plan definitions. Missing/unreadable file ->
    the built-in fallback (Free keeps working; never raises)."""
    target = path or _PLANS_PATH
    try:
        with open(target, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "tiers" not in data:
            raise ValueError("plans file has no 'tiers'")
        return data
    except (OSError, ValueError, json.JSONDecodeError):
        return json.loads(json.dumps(_FALLBACK_PLANS))


def _tier_order(plans: dict) -> list[str]:
    order = plans.get("tier_order") or list(plans.get("tiers", {}).keys())
    return [t for t in order if t in plans.get("tiers", {})]


def get_plan(plan, plans: dict | None = None) -> dict:
    """Tier dict for a plan id (or a tier dict passed through).

    Unknown ids, None, and anything unparseable all resolve to Free —
    the free layer never breaks on unknown plan state.
    """
    data = plans if plans is not None else load_plans()
    tiers = data.get("tiers", {})
    if isinstance(plan, dict) and plan.get("id") in tiers:
        return tiers[plan["id"]]
    if isinstance(plan, str) and plan in tiers:
        return tiers[plan]
    return tiers.get(DEFAULT_PLAN_ID, _FALLBACK_PLANS["tiers"]["free"])


def get_plan_id(plan, plans: dict | None = None) -> str:
    """Normalized plan id; unknown -> 'free'."""
    return get_plan(plan, plans).get("id", DEFAULT_PLAN_ID)


def feature_allowed(plan, feature: str, plans: dict | None = None) -> bool:
    """True when `feature` is included in `plan`."""
    data = plans if plans is not None else load_plans()
    tier = get_plan(plan, data)
    return feature in (tier.get("features") or [])


def next_tier_for_feature(plan, feature: str,
                          plans: dict | None = None) -> dict | None:
    """First tier above `plan` (in tier order) that allows `feature`.

    None when no higher tier allows it (already included everywhere
    above, or the feature exists nowhere).
    """
    data = plans if plans is not None else load_plans()
    order = _tier_order(data)
    current = get_plan_id(plan, data)
    try:
        start = order.index(current) + 1
    except ValueError:
        start = 0
    for tier_id in order[start:]:
        tier = data["tiers"][tier_id]
        if feature in (tier.get("features") or []):
            return tier
    return None


def _format_upgrade(plans: dict, tier: dict, unlocks: str) -> str:
    price = tier.get("price_monthly_usd")
    if price is None:
        template = plans.get(
            "upgrade_template_custom",
            "Upgrade to {tier} (custom pricing) to unlock {unlocks}.")
        return template.format(tier=tier.get("name", tier.get("id", "")),
                               unlocks=unlocks)
    template = plans.get(
        "upgrade_template",
        "Upgrade to {tier} (${price}/mo) to unlock {unlocks}.")
    return template.format(tier=tier.get("name", tier.get("id", "")),
                           price=price, unlocks=unlocks)


def upgrade_message(plan, feature: str, plans: dict | None = None) -> str:
    """Upgrade prompt for a feature `plan` does not include.

    Names the next tier, its price, and exactly what it unlocks. When
    the feature is already included, says so instead of upselling.
    """
    data = plans if plans is not None else load_plans()
    tier = get_plan(plan, data)
    feature_def = (data.get("features") or {}).get(feature, {})
    label = feature_def.get("label", feature)
    if feature_allowed(plan, feature, data):
        return (f"{label} is included in your {tier.get('name', tier.get('id', ''))} "
                "plan.")
    nxt = next_tier_for_feature(plan, feature, data)
    if nxt is None:
        return f"{label} is not available on any paid plan yet."
    return _format_upgrade(data, nxt, feature_def.get("unlocks", label))


def next_tier_for_limit(plan, resource: str,
                        plans: dict | None = None) -> dict | None:
    """First tier above `plan` with a higher (or unlimited) limit for
    `resource`. None when no higher tier raises it."""
    data = plans if plans is not None else load_plans()
    order = _tier_order(data)
    current = get_plan(plan, data)
    current_limit = (current.get("limits") or {}).get(resource)
    try:
        start = order.index(current.get("id", DEFAULT_PLAN_ID)) + 1
    except ValueError:
        start = 0
    for tier_id in order[start:]:
        tier = data["tiers"][tier_id]
        limit = (tier.get("limits") or {}).get(resource)
        if limit is None or (
                current_limit is not None and limit > current_limit):
            return tier
    return None


def _format_limit(limit) -> str:
    return "unlimited" if limit is None else f"up to {limit}"


def _limit_upgrade_details(plan, resource: str,
                           plans: dict) -> dict | None:
    """Structured upgrade for a denied limit check, or None.

    Returned dict: {"tier": tier dict, "unlocks": str, "message": str}.
    Preference order (the caps build, FREE-TIER-CAPS.md):
      1. The resource's explicit `next_tier` (plans.json) when it sits
         above the current plan and raises the limit — this is what
         makes scans/MCP/saves name Maker while audits/fingerprints
         name Starter, instead of the layer model's "Starter for
         everything". The copy comes from the resource's
         `upgrade_unlocks` ("unlimited vibe-code scans").
      2. The resource's `upgrade_feature` route (existing behavior):
         the feature's upgrade message, only when the current plan does
         NOT already include that feature (Free + fingerprints ->
         Starter + fingerprint monitoring). When it is already included
         (Starter + 26 fingerprints), the fix is a higher limit, so
         step 3 names the tier that raises it (Team, unlimited).
      3. The next tier that raises the limit.
    None when no higher tier raises the limit.
    """
    label = ((plans.get("resources") or {}).get(resource) or {}).get(
        "label", resource)
    res_def = (plans.get("resources") or {}).get(resource) or {}
    tier = get_plan(plan, plans)
    current_id = tier.get("id", DEFAULT_PLAN_ID)
    current_limit = (tier.get("limits") or {}).get(resource)
    order = _tier_order(plans)

    def _raises(nxt_tier: dict) -> bool:
        nxt_limit = (nxt_tier.get("limits") or {}).get(resource)
        return nxt_limit is None or (
            current_limit is not None and nxt_limit > current_limit)

    # 1. Explicit per-resource next tier (caps build).
    nxt_id = res_def.get("next_tier")
    tiers = plans.get("tiers") or {}
    if (isinstance(nxt_id, str) and nxt_id in tiers
            and current_id in order and nxt_id in order
            and order.index(nxt_id) > order.index(current_id)):
        nxt = tiers[nxt_id]
        if _raises(nxt):
            unlocks = res_def.get("upgrade_unlocks") or (
                f"{_format_limit((nxt.get('limits') or {}).get(resource))} "
                f"{label}")
            return {"tier": nxt, "unlocks": unlocks,
                    "message": _format_upgrade(plans, nxt, unlocks)}
    # 2. Feature route (layer-model behavior, unchanged).
    feature = res_def.get("upgrade_feature")
    if feature and not feature_allowed(plan, feature, plans):
        nxt = next_tier_for_feature(plan, feature, plans)
        if nxt is not None and _raises(nxt):
            feature_def = (plans.get("features") or {}).get(feature, {})
            return {"tier": nxt,
                    "unlocks": feature_def.get("unlocks", feature),
                    "message": upgrade_message(plan, feature, plans)}
    # 3. Next tier that raises the limit.
    nxt = next_tier_for_limit(plan, resource, plans)
    if nxt is None:
        return None
    unlocks = (f"{_format_limit((nxt.get('limits') or {}).get(resource))} "
               f"{label}")
    return {"tier": nxt, "unlocks": unlocks,
            "message": _format_upgrade(plans, nxt, unlocks)}


def _limit_upgrade_message(plan, resource: str, plans: dict) -> str:
    """Upgrade sentence for a denied limit check.

    Empty string when no higher tier raises the limit.
    """
    details = _limit_upgrade_details(plan, resource, plans)
    return details["message"] if details else ""


def daily_cap_upgrade(plan, resource: str,
                      plans: dict | None = None) -> dict | None:
    """Structured upgrade prompt for a daily-cap hit, or None.

    {"message": str, "tier": name, "price": price_label,
     "unlocks": str} — the same dict the web cap-hit responses carry.
    None when the plan's limit for the resource is already unlimited
    (no cap to hit) or no higher tier lifts it.
    """
    data = plans if plans is not None else load_plans()
    tier = get_plan(plan, data)
    if (tier.get("limits") or {}).get(resource) is None:
        return None
    details = _limit_upgrade_details(plan, resource, data)
    if details is None:
        return None
    tier = details["tier"]
    return {"message": details["message"],
            "tier": tier.get("name", tier.get("id", "")),
            "price": tier.get("price_label", ""),
            "unlocks": details["unlocks"]}


def daily_cap_message(plan, resource: str, used: int,
                      plans: dict | None = None) -> str:
    """Full denial message for a daily-cap hit.

    Limit sentence + upgrade (next tier, price, unlocks) + the
    come-back-tomorrow suffix. Never a bare error, never a dead end.
    """
    data = plans if plans is not None else load_plans()
    tier = get_plan(plan, data)
    limit = (tier.get("limits") or {}).get(resource)
    label = ((data.get("resources") or {}).get(resource) or {}).get(
        "label", resource)
    if limit is None:
        return ""
    template = data.get(
        "daily_limit_message_template",
        "{plan} plan allows up to {limit} {label} "
        "(you have used {used} today).")
    message = template.format(plan=tier.get("name", tier.get("id", "")),
                              limit=limit, label=label, used=used)
    upgrade = _limit_upgrade_message(plan, resource, data)
    if upgrade:
        message += " " + upgrade
    suffix = data.get(
        "daily_cap_suffix",
        "Come back tomorrow, it works again "
        "(free caps reset at midnight UTC).")
    return message + " " + suffix


def check_daily_cap(plan, resource: str, used_today: int,
                    plans: dict | None = None) -> tuple[bool, str, int,
                                                        int | None]:
    """Is one more use of daily-capped `resource` allowed?

    Returns (allowed, message, used_today, limit). Allowed when
    used_today < limit; a null limit is unlimited. Unlike check_limit
    (persistent counts, used <= limit), a daily cap bites when the
    day's count has REACHED the limit — the 3rd scan of a 2/day cap is
    denied. The denial message is the full daily-cap message.
    """
    data = plans if plans is not None else load_plans()
    tier = get_plan(plan, data)
    limit = (tier.get("limits") or {}).get(resource)
    if limit is None:
        return True, "", used_today, None
    if used_today < limit:
        return True, "", used_today, limit
    return False, daily_cap_message(plan, resource, used_today, data), \
        used_today, limit


def format_counter(used: int, limit: int | None, label: str,
                   plan_name: str = "Free") -> str:
    """Counter display: "1 of 2 free scans used today".

    `label` is the short resource name ("scans", "audits",
    "dashboard saves", "MCP queries"). Unlimited plans print the count
    with the plan name instead of a fraction.
    """
    if limit is None:
        return (f"{used} {label} used today "
                f"(unlimited on the {plan_name} plan)")
    if plan_name == "Free":
        return f"{used} of {limit} free {label} used today"
    return f"{used} of {limit} {label} used today ({plan_name} plan)"


def format_allowance(used: int, limit: int | None, label: str) -> str:
    """Non-daily allowance display: "1 of 1 agents on the timeline".

    Used by the audit timeline (1 agent, last 7 days) — not a daily
    counter, so no "used today" phrasing.
    """
    if limit is None:
        return f"{used} {label} (unlimited)"
    return f"{used} of {limit} {label}"


def check_limit(plan, resource: str, used: int,
                plans: dict | None = None) -> tuple[bool, str]:
    """Is `used` of `resource` within `plan`'s limit?

    `used` is the total count held (e.g. fingerprints watched). Allowed
    when used <= limit; a null limit is unlimited (within abuse caps).
    The denial message states the limit and the upgrade that raises it.
    """
    data = plans if plans is not None else load_plans()
    tier = get_plan(plan, data)
    limit = (tier.get("limits") or {}).get(resource)
    if limit is None:
        return True, ""
    label = ((data.get("resources") or {}).get(resource) or {}).get(
        "label", resource)
    if used <= limit:
        return True, ""
    template = data.get(
        "limit_message_template",
        "{plan} plan allows up to {limit} {label} (you have {used}).")
    message = template.format(plan=tier.get("name", tier.get("id", "")),
                              limit=limit, label=label, used=used)
    upgrade = _limit_upgrade_message(plan, resource, data)
    if upgrade:
        message += " " + upgrade
    return False, message


# --- Local plan state (dev/testing only) -------------------------------

def _state_path(path: str | None = None) -> str:
    if path:
        return path
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        PLAN_STATE_FILENAME)


def load_local_plan(path: str | None = None,
                    plans: dict | None = None) -> str:
    """Plan id from the local state file; 'free' when absent/unreadable
    or when it names an unknown tier. Never raises."""
    data = plans if plans is not None else load_plans()
    try:
        with open(_state_path(path), encoding="utf-8") as fh:
            state = json.load(fh)
        plan_id = state.get("plan") if isinstance(state, dict) else None
    except (OSError, ValueError, json.JSONDecodeError):
        return DEFAULT_PLAN_ID
    if isinstance(plan_id, str) and plan_id in (data.get("tiers") or {}):
        return plan_id
    return DEFAULT_PLAN_ID


def save_local_plan(plan_id: str, path: str | None = None) -> str:
    """Persist the local dev plan. Raises ValueError on unknown tiers."""
    data = load_plans()
    if plan_id not in (data.get("tiers") or {}):
        raise ValueError(
            f"unknown plan: {plan_id!r} (want one of "
            f"{', '.join(_tier_order(data))})")
    target = _state_path(path)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump({"plan": plan_id}, fh, indent=2)
        fh.write("\n")
    return plan_id


# --- Daily usage counters (free-tier caps) -----------------------------

USAGE_STATE_FILENAME = ".key-sentry-usage.json"

# Resources with a daily cap (plans.json: daily:true). The per-resource
# counter key is the resource id, except per-fingerprint checks, which
# use "fingerprint_check:<16-hex>" — one counter per fingerprint, so
# each fingerprint gets its own 1x/day.
DAILY_COUNTER_RESOURCES = (
    "scans_per_day",
    "audits_per_day",
    "mcp_queries_per_day",
    "dashboard_saves_per_day",
    "fingerprint_checks_per_day",
)


def utc_today(now: datetime | str | None = None) -> str:
    """Current UTC date as YYYY-MM-DD (the counter bucket).

    `now` is injectable (a datetime, or a YYYY-MM-DD string) so tests
    can fake the date and prove the midnight-UTC rollover.
    """
    if isinstance(now, str):
        return now
    moment = now or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).date().isoformat()


def _usage_state_path(path: str | None = None) -> str:
    if path:
        return path
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        USAGE_STATE_FILENAME)


def load_daily_usage(path: str | None = None,
                     now: datetime | str | None = None) -> dict:
    """Today's daily counters, {"date": ..., "counters": {...}}.

    A state file from another UTC date rolls over to empty counters —
    the midnight-UTC reset. Missing/corrupt files read as empty.
    Never raises.
    """
    today = utc_today(now)
    try:
        with open(_usage_state_path(path), encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError, json.JSONDecodeError):
        return {"date": today, "counters": {}}
    if not isinstance(state, dict) or state.get("date") != today:
        return {"date": today, "counters": {}}
    counters = state.get("counters")
    return {"date": today,
            "counters": counters if isinstance(counters, dict) else {}}


def _save_daily_usage(state: dict, path: str | None = None) -> None:
    target = _usage_state_path(path)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
        fh.write("\n")


def daily_used(resource: str, path: str | None = None,
               now: datetime | str | None = None) -> int:
    """Uses of `resource` so far today (0 when none / rolled over)."""
    counters = load_daily_usage(path, now).get("counters") or {}
    value = counters.get(resource, 0)
    return value if isinstance(value, int) and value >= 0 else 0


def record_daily_use(resource: str, path: str | None = None,
                     now: datetime | str | None = None) -> int:
    """Record one use of `resource` today; returns the new count."""
    state = load_daily_usage(path, now)
    counters = state["counters"]
    counters[resource] = daily_used(resource, path, now) + 1
    _save_daily_usage(state, path)
    return counters[resource]


def check_daily_cap_today(plan, resource: str, path: str | None = None,
                          now: datetime | str | None = None,
                          plans: dict | None = None) -> tuple[bool, str, int,
                                                              int | None]:
    """Daily-cap check against today's counter for `resource`.

    Reads today's count from the local state file, then answers
    (allowed, message, used_today, limit) via check_daily_cap.
    Allowed when used < limit.
    """
    return check_daily_cap(plan, resource, daily_used(resource, path, now),
                           plans)


def _describe_plan(plan_id: str, plans: dict) -> str:
    tier = get_plan(plan_id, plans)
    lines = [f"plan: {tier.get('name', plan_id)} "
             f"({tier.get('price_label', '')})"]
    limits = tier.get("limits") or {}
    labels = plans.get("resources") or {}
    for resource, limit in limits.items():
        label = labels.get(resource, {}).get("label", resource)
        lines.append(f"  {label}: "
                     f"{'unlimited' if limit is None else limit}")
    features = tier.get("features") or []
    feature_defs = plans.get("features") or {}
    lines.append("  features: " + ", ".join(
        feature_defs.get(f, {}).get("label", f) for f in features))
    return "\n".join(lines)


def _cmd_counters() -> int:
    """Print today's daily-cap counters for the local plan."""
    plans = load_plans()
    plan_id = load_local_plan(plans=plans)
    tier = get_plan(plan_id, plans)
    plan_name = tier.get("name", plan_id)
    print(f"daily counters ({utc_today()}, {plan_name} plan — "
          "reset at midnight UTC):")
    labels = {
        "scans_per_day": "scans",
        "audits_per_day": "audits",
        "mcp_queries_per_day": "MCP queries",
        "dashboard_saves_per_day": "dashboard saves",
    }
    for resource in DAILY_COUNTER_RESOURCES:
        limit = (tier.get("limits") or {}).get(resource)
        label = labels.get(
            resource,
            ((plans.get("resources") or {}).get(resource) or {}).get(
                "label", resource))
        if resource == "fingerprint_checks_per_day":
            # Per-fingerprint counters live under
            # fingerprint_check:<fp>; report how many fingerprints were
            # checked today instead of a single number.
            state = load_daily_usage()
            checked = sum(
                1 for key in (state.get("counters") or {})
                if key.startswith("fingerprint_check:"))
            print(f"  {format_counter(checked, limit, 'fingerprint checks', plan_name)}"
                  f" (1x/day each)")
            continue
        print(f"  {format_counter(daily_used(resource), limit, label, plan_name)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="plans.py",
        description="KeySentry plan definitions: show the local plan, "
                    "set it (dev/testing only), or show today's daily "
                    "free-tier counters.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_show = sub.add_parser("show", help="print the current plan + limits")
    p_show.set_defaults(func=lambda args: _cmd_show())

    p_set = sub.add_parser("set-plan", help="set the local dev plan")
    p_set.add_argument("tier", help="free, maker, starter, team, "
                       "business, or enterprise")
    p_set.set_defaults(func=lambda args: _cmd_set_plan(args.tier))

    p_counters = sub.add_parser(
        "counters", help="print today's daily-cap counters "
                         "(\"N of M free scans used today\")")
    p_counters.set_defaults(func=lambda args: _cmd_counters())

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_show() -> int:
    plans = load_plans()
    print(_describe_plan(load_local_plan(plans=plans), plans))
    return 0


def _cmd_set_plan(tier: str) -> int:
    try:
        plan_id = save_local_plan(tier)
    except ValueError as exc:
        print(f"set-plan: {exc}", file=sys.stderr)
        return 2
    print(f"local plan set to {plan_id} "
          f"({get_plan(plan_id).get('price_label', '')}).")
    print("WARNING: this sets the LOCAL dev plan only. Real plan state "
          "comes from billing — the Stripe webhook writes workspace_plans "
          "in the web app. Do not rely on this file for enforcement in "
          "production.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
