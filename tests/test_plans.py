#!/usr/bin/env python3
"""Tests for the KeySentry freemium Layer Model (plans.py + sync).

Covers the canonical plans.json, the sync to key-sentry/lib/plans.json,
feature gates and limit boundaries per tier, upgrade copy, the
free-never-locked-out default (missing plan file / unknown plan id),
and the fingerprint_watch.py `check` plan gate — all without network,
database, or Stripe. Run with:
  python3 -m pytest tests/test_plans.py
(or: python3 -m pytest tests/ from the repo root).
"""
import argparse
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import fingerprint_watch as fw  # noqa: E402
import plans  # noqa: E402
from scripts.sync_plans import sync_plans  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANONICAL = os.path.join(REPO_ROOT, "docs", "commercial", "plans.json")
WEB_COPY = os.path.join(REPO_ROOT, "..", "key-sentry", "lib", "plans.json")


def _load_canonical():
    with open(CANONICAL, encoding="utf-8") as fh:
        return json.load(fh)


def _fps(n):
    return [f"{i:016x}" for i in range(1, n + 1)]


def _write_fp_file(path, fps):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"fingerprints": [
            {"fingerprint": fp, "provider": "Groq", "label": ""}
            for fp in fps]}, fh)


def _write_results_file(path, fps):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"rows": [
            {"fingerprint": fp, "provider": "Groq",
             "file": "github:acme/app/.env", "line": 1}
            for fp in fps]}, fh)


def _check_ns(results, fingerprints, plan):
    return argparse.Namespace(results=str(results),
                              fingerprints=str(fingerprints),
                              dry_run=True, plan=plan)


# --- plans.json + sync -------------------------------------------------

def test_plans_json_loads_and_matches_synced_copy(tmp_path):
    data = _load_canonical()
    assert set(data["tiers"]) == {
        "free", "maker", "starter", "premium", "team", "premium_plus",
        "business", "enterprise"}
    # Regenerate into a temp dir and compare with the canonical file.
    out = tmp_path / "plans.json"
    synced = sync_plans(CANONICAL, str(out))
    assert synced == data
    with open(out, encoding="utf-8") as fh:
        assert json.load(fh) == data
    # The live web copy must be identical too (drift fails the build).
    with open(WEB_COPY, encoding="utf-8") as fh:
        assert json.load(fh) == data


def test_tier_prices():
    data = _load_canonical()
    assert data["tiers"]["free"]["price_monthly_usd"] == 0
    assert data["tiers"]["maker"]["price_monthly_usd"] == 19
    assert data["tiers"]["starter"]["price_monthly_usd"] == 49
    assert data["tiers"]["team"]["price_monthly_usd"] == 149
    assert data["tiers"]["business"]["price_monthly_usd"] == 499
    assert data["tiers"]["enterprise"]["price_monthly_usd"] is None


# --- feature gates -----------------------------------------------------

def test_free_allowed_features():
    for feature in ("scan_one_repo", "mcp_read_only",
                    "audit_timeline_one_agent", "vibe_report_one_repo"):
        assert plans.feature_allowed("free", feature), feature


def test_free_denied_commercial_features():
    for feature in ("fingerprint_monitoring", "email_alerts",
                    "vibe_monitoring", "slack_alerts",
                    "remediation_workflow", "owner_verification", "exports",
                    "full_audit_timeline", "audit_logs",
                    "compliance_export", "detections", "policy_controls",
                    "api", "sla", "sso", "private_deployment"):
        assert not plans.feature_allowed("free", feature), feature


def test_starter_gates():
    for feature in ("fingerprint_monitoring", "email_alerts",
                    "vibe_monitoring"):
        assert plans.feature_allowed("starter", feature), feature
    for feature in ("slack_alerts", "remediation_workflow", "detections",
                    "compliance_export", "api"):
        assert not plans.feature_allowed("starter", feature), feature


def test_team_gates():
    for feature in ("slack_alerts", "remediation_workflow",
                    "owner_verification", "exports", "full_audit_timeline"):
        assert plans.feature_allowed("team", feature), feature
    for feature in ("audit_logs", "compliance_export", "detections",
                    "policy_controls", "api", "sla"):
        assert not plans.feature_allowed("team", feature), feature


def test_business_and_enterprise_gates():
    for feature in ("audit_logs", "compliance_export", "detections",
                    "policy_controls", "api", "sla"):
        assert plans.feature_allowed("business", feature), feature
    assert not plans.feature_allowed("business", "sso")
    assert not plans.feature_allowed("business", "private_deployment")
    assert plans.feature_allowed("enterprise", "sso")
    assert plans.feature_allowed("enterprise", "private_deployment")


# --- limit boundaries --------------------------------------------------

def test_limit_boundaries_fingerprints():
    assert plans.check_limit("free", "fingerprints", 5)[0] is True
    allowed, msg = plans.check_limit("free", "fingerprints", 6)
    assert allowed is False
    assert "up to 5 fingerprints" in msg and "you have 6" in msg
    assert plans.check_limit("starter", "fingerprints", 25)[0] is True
    assert plans.check_limit("starter", "fingerprints", 26)[0] is False
    # Team/Business/Enterprise: unlimited (within the abuse caps).
    for tier in ("team", "business", "enterprise"):
        assert plans.check_limit(tier, "fingerprints", 999)[0] is True


def test_limit_boundaries_other_resources():
    assert plans.check_limit("free", "repos", 1)[0] is True
    assert plans.check_limit("free", "repos", 2)[0] is False
    # Caps build (FREE-TIER-CAPS.md): the web vibe-scan cap is 2/day
    # on Free (was 10/day in the layer model).
    assert plans.check_limit("free", "scans_per_day", 2)[0] is True
    assert plans.check_limit("free", "scans_per_day", 3)[0] is False
    assert plans.check_limit("starter", "repos", 5)[0] is True
    assert plans.check_limit("starter", "repos", 6)[0] is False


# --- upgrade messages --------------------------------------------------

def test_upgrade_message_names_next_tier_price_and_unlock():
    msg = plans.upgrade_message("free", "fingerprint_monitoring")
    assert "Starter" in msg and "$49" in msg
    assert "fingerprint monitoring" in msg
    msg = plans.upgrade_message("free", "detections")
    assert "Business" in msg and "$499" in msg
    assert "detections" in msg
    msg = plans.upgrade_message("free", "compliance_export")
    assert "Business" in msg and "$499" in msg
    assert "compliance export" in msg
    msg = plans.upgrade_message("team", "api")
    assert "Premium Plus" in msg and "$299" in msg
    msg = plans.upgrade_message("free", "remediation_workflow")
    assert "Premium" in msg and "$99" in msg


def test_upgrade_message_for_included_feature_says_so():
    msg = plans.upgrade_message("free", "scan_one_repo")
    assert "included in your Free plan" in msg


def test_limit_denial_message_names_upgrade():
    _, msg = plans.check_limit("free", "fingerprints", 6)
    assert "Starter" in msg and "$49" in msg
    assert "fingerprint monitoring" in msg
    _, msg = plans.check_limit("starter", "fingerprints", 26)
    assert "Premium" in msg and "$99" in msg
    assert "up to 75 fingerprints" in msg


# --- free-never-locked-out ---------------------------------------------

def test_missing_plan_file_defaults_to_free():
    data = plans.load_plans("/nonexistent/no-such-plans.json")
    assert plans.get_plan_id("free", data) == "free"
    assert plans.feature_allowed("free", "scan_one_repo", data) is True
    assert plans.feature_allowed("free", "fingerprint_monitoring",
                                 data) is False
    assert plans.check_limit("free", "fingerprints", 5, data)[0] is True
    assert plans.check_limit("free", "fingerprints", 6, data)[0] is False
    msg = plans.upgrade_message("free", "fingerprint_monitoring", data)
    assert "Starter" in msg and "$49" in msg


def test_unknown_plan_id_defaults_to_free():
    assert plans.get_plan_id("bogus") == "free"
    assert plans.get_plan_id(None) == "free"
    assert plans.feature_allowed("bogus", "scan_one_repo") is True
    assert plans.feature_allowed("bogus", "api") is False


def test_local_plan_state_roundtrip(tmp_path, monkeypatch):
    state = tmp_path / ".key-sentry-plan.json"
    monkeypatch.setattr(plans, "_state_path",
                        lambda path=None: str(state))
    assert plans.load_local_plan() == "free"  # absent -> Free
    plans.save_local_plan("team")
    assert plans.load_local_plan() == "team"
    with pytest.raises(ValueError):
        plans.save_local_plan("bogus")
    state.write_text('{"plan": "bogus"}', encoding="utf-8")
    assert plans.load_local_plan() == "free"  # unknown stored -> Free


# --- fingerprint_watch.py plan gate ------------------------------------

def test_watch_free_plan_six_fingerprints_prompts_and_checks_five(
        tmp_path, capsys):
    fp_file = tmp_path / "fp6.json"
    res_file = tmp_path / "res6.json"
    _write_fp_file(fp_file, _fps(6))
    _write_results_file(res_file, _fps(6))
    rc = fw.cmd_check(_check_ns(res_file, fp_file, "free"))
    out = capsys.readouterr().out
    assert rc == 0
    # Upgrade prompt: names Starter, $49/mo, fingerprint monitoring.
    assert "Starter" in out and "$49" in out
    assert "fingerprint monitoring" in out
    # Free capability keeps working: first 5 checked, not a dead end.
    assert "continuing with the first 5 fingerprint(s)" in out
    assert "5 watched fingerprint(s)" in out
    assert "5 match(es)" in out


def test_watch_starter_plan_twenty_five_allowed(tmp_path, capsys):
    fp_file = tmp_path / "fp25.json"
    res_file = tmp_path / "res25.json"
    _write_fp_file(fp_file, _fps(25))
    _write_results_file(res_file, _fps(25))
    rc = fw.cmd_check(_check_ns(res_file, fp_file, "starter"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Starter" not in out  # no upgrade prompt
    assert "25 watched fingerprint(s)" in out
    assert "25 match(es)" in out


# --- Maker tier + daily caps (caps build) --------------------------------

def test_maker_tier_present_with_doc_fields():
    data = _load_canonical()
    maker = data["tiers"]["maker"]
    assert maker["name"] == "Maker"
    assert maker["price_monthly_usd"] == 19
    assert maker["price_label"] == "$19/mo"
    # FREE-TIER-CAPS.md: 5 apps, unlimited scans, monitoring, fix PRs,
    # 30-day history.
    assert maker["limits"]["repos"] == 5
    assert maker["limits"]["scans_per_day"] is None
    assert maker["limits"]["audit_timeline_days"] == 30
    for feature in ("scan_one_repo", "mcp_read_only",
                    "audit_timeline_one_agent", "vibe_report_one_repo",
                    "vibe_monitoring", "fix_prs"):
        assert feature in maker["features"], feature
    # Maker is the vibe-coder tier, not the dev-team tier: no
    # fingerprint monitoring, no email alerts, no unlimited audits.
    for feature in ("fingerprint_monitoring", "email_alerts"):
        assert feature not in maker["features"], feature
    assert maker["limits"]["fingerprints"] == 5
    assert maker["limits"]["audits_per_day"] == 2
    assert data["tier_order"] == ["free", "maker", "starter", "premium",
                                  "team", "premium_plus", "business",
                                  "enterprise"]


def test_premium_and_premium_plus_tiers():
    """Premium ($99) and Premium Plus ($299) bridge tiers (FREE-TIER-CAPS.md)."""
    data = _load_canonical()
    premium = data["tiers"]["premium"]
    assert premium["price_monthly_usd"] == 99
    assert premium["limits"]["repos"] == 15
    assert premium["limits"]["fingerprints"] == 75
    assert premium["limits"]["mcp_queries_per_day"] == 5000
    assert premium["limits"]["audit_timeline_days"] == 60
    assert premium["limits"]["seats"] == 5
    assert premium["limits"]["scans_per_day"] is None
    assert premium["limits"]["audits_per_day"] is None
    assert premium["limits"]["fingerprint_checks_per_day"] is None
    # Premium: Slack alerts + remediation, no owner verification, no API.
    for feature in ("slack_alerts", "remediation_workflow"):
        assert feature in premium["features"], feature
    for feature in ("owner_verification", "api", "full_audit_timeline"):
        assert feature not in premium["features"], feature
    premium_plus = data["tiers"]["premium_plus"]
    assert premium_plus["price_monthly_usd"] == 299
    assert premium_plus["limits"]["repos"] is None
    assert premium_plus["limits"]["fingerprints"] is None
    assert premium_plus["limits"]["mcp_queries_per_day"] is None
    assert premium_plus["limits"]["audit_timeline_days"] == 180
    assert premium_plus["limits"]["seats"] == 25
    # Premium Plus: everything in Team plus API and priority support;
    # compliance (audit logs) stays Business.
    assert "api" in premium_plus["features"]
    assert "priority_support" in premium_plus["features"]
    assert "audit_logs" not in premium_plus["features"]


def test_premium_upgrade_paths():
    """Upgrade prompts name the next rung on the price-ordered ladder:
    a Premium cap hit names Team, a Premium Plus cap hit names Business."""
    # Premium's only finite daily cap is MCP queries (5,000/day) -> Team.
    assert plans.next_tier_for_limit(
        "premium", "mcp_queries_per_day")["id"] == "team"
    assert plans.next_tier_for_limit(
        "premium", "audit_timeline_days")["id"] == "team"
    # Premium seats (5) cannot lift at Team (also 5) -> Premium Plus.
    assert plans.next_tier_for_limit("premium", "seats")["id"] == "premium_plus"
    # Premium Plus's finite caps lift at Business (7y history, unlimited seats).
    assert plans.next_tier_for_limit(
        "premium_plus", "audit_timeline_days")["id"] == "business"
    assert plans.next_tier_for_limit(
        "premium_plus", "seats")["id"] == "business"
    up = plans.daily_cap_upgrade("premium", "mcp_queries_per_day")
    assert up is not None and up["tier"] == "Team" and up["price"] == "$149/mo"
    msg = plans.daily_cap_message("premium", "mcp_queries_per_day", 5000)
    assert "Team" in msg and "$149" in msg
    assert "Come back tomorrow" in msg
    up = plans.daily_cap_upgrade("premium_plus", "audit_timeline_days")
    assert up is not None and up["tier"] == "Business"
    assert up["price"] == "$499/mo"


def test_daily_cap_limits_per_tier():
    data = _load_canonical()
    free = data["tiers"]["free"]["limits"]
    assert free["scans_per_day"] == 2
    assert free["audits_per_day"] == 2
    assert free["mcp_queries_per_day"] == 100
    assert free["dashboard_saves_per_day"] == 2
    assert free["shareable_reports"] == 2
    assert free["audit_timeline_days"] == 7
    assert free["seats"] == 1
    assert free["fingerprint_checks_per_day"] == 1
    maker = data["tiers"]["maker"]["limits"]
    assert maker["scans_per_day"] is None
    assert maker["mcp_queries_per_day"] is None
    assert maker["dashboard_saves_per_day"] is None
    assert maker["shareable_reports"] is None
    assert maker["audits_per_day"] == 2  # audits lift at Starter
    assert maker["audit_timeline_days"] == 30
    starter = data["tiers"]["starter"]["limits"]
    assert starter["audits_per_day"] is None
    assert starter["fingerprints"] == 25
    assert starter["audit_timeline_days"] == 30
    assert data["tiers"]["team"]["limits"]["audit_timeline_days"] == 90
    assert data["tiers"]["team"]["limits"]["seats"] == 5
    assert data["tiers"]["business"]["limits"]["audit_timeline_days"] == 2555
    # Every daily resource is flagged daily with a midnight-UTC reset.
    for resource in ("scans_per_day", "audits_per_day",
                     "mcp_queries_per_day", "dashboard_saves_per_day",
                     "fingerprint_checks_per_day"):
        res = data["resources"][resource]
        assert res["daily"] is True, resource
        assert res["reset"] == "midnight UTC", resource


def test_daily_cap_next_tier_per_resource():
    # Vibe scans / MCP queries / dashboard saves / shareable reports
    # -> Maker; audits / fingerprints / alerts -> Starter; seats ->
    # Team. The layer model named Starter for everything — fixed here.
    _, msg, _, _ = plans.check_daily_cap("free", "scans_per_day", 2)
    assert "Maker" in msg and "$19" in msg
    assert "unlimited vibe-code scans" in msg
    _, msg, _, _ = plans.check_daily_cap("free", "mcp_queries_per_day", 100)
    assert "Maker" in msg and "$19" in msg
    assert "unlimited MCP server queries" in msg
    _, msg, _, _ = plans.check_daily_cap(
        "free", "dashboard_saves_per_day", 2)
    assert "Maker" in msg and "$19" in msg
    assert "unlimited dashboard saves" in msg
    _, msg = plans.check_limit("free", "shareable_reports", 3)
    assert "Maker" in msg and "$19" in msg
    assert "unlimited shareable reports" in msg
    _, msg, _, _ = plans.check_daily_cap("free", "audits_per_day", 2)
    assert "Starter" in msg and "$49" in msg
    assert "unlimited agent identity audits" in msg
    _, msg, _, _ = plans.check_daily_cap(
        "free", "fingerprint_checks_per_day", 1)
    assert "Starter" in msg and "$49" in msg
    _, msg = plans.check_limit("free", "seats", 2)
    assert "Team" in msg and "$149" in msg
    assert "5 team seats" in msg
    # Audit history: Free -> Maker (30 days), Maker -> Premium (60 days).
    _, msg = plans.check_limit("free", "audit_timeline_days", 8)
    assert "Maker" in msg and "$19" in msg
    assert "30 days of audit history" in msg
    _, msg = plans.check_limit("maker", "audit_timeline_days", 31)
    assert "Premium" in msg and "$99" in msg
    assert "60 days of audit history" in msg


def test_daily_cap_message_always_names_tier_and_tomorrow():
    for resource, used in (("scans_per_day", 2), ("audits_per_day", 2),
                           ("mcp_queries_per_day", 100),
                           ("dashboard_saves_per_day", 2),
                           ("fingerprint_checks_per_day", 1)):
        allowed, msg, _, limit = plans.check_daily_cap("free", resource,
                                                       used)
        assert allowed is False, resource
        assert limit is not None
        assert "come back tomorrow" in msg.lower(), resource
        assert "midnight UTC" in msg, resource
    # Under the cap: allowed, no message.
    assert plans.check_daily_cap("free", "scans_per_day", 1)[0] is True
    assert plans.check_daily_cap("free", "scans_per_day", 1)[1] == ""
    # Unlimited tiers never hit the cap.
    assert plans.check_daily_cap("maker", "scans_per_day", 999)[0] is True
    assert plans.check_daily_cap("starter", "audits_per_day", 999)[0] is True


def test_daily_cap_upgrade_structured():
    prompt = plans.daily_cap_upgrade("free", "scans_per_day")
    assert prompt == {
        "message": "Upgrade to Maker ($19/mo) to unlock "
                   "unlimited vibe-code scans.",
        "tier": "Maker", "price": "$19/mo",
        "unlocks": "unlimited vibe-code scans"}
    prompt = plans.daily_cap_upgrade("free", "audits_per_day")
    assert prompt["tier"] == "Starter" and prompt["price"] == "$49/mo"
    assert prompt["unlocks"] == "unlimited agent identity audits"
    assert plans.daily_cap_upgrade("maker", "scans_per_day") is None


def test_counter_display_text():
    assert plans.format_counter(1, 2, "scans") == \
        "1 of 2 free scans used today"
    assert plans.format_counter(2, 2, "audits") == \
        "2 of 2 free audits used today"
    assert plans.format_counter(3, None, "scans", "Maker") == \
        "3 scans used today (unlimited on the Maker plan)"
    assert plans.format_counter(1, 2, "audits", "Maker") == \
        "1 of 2 audits used today (Maker plan)"
    assert plans.format_allowance(1, 1, "agents on the timeline") == \
        "1 of 1 agents on the timeline"
    assert plans.format_allowance(3, None, "agents on the timeline") == \
        "3 agents on the timeline (unlimited)"
