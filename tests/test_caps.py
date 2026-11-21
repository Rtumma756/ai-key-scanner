#!/usr/bin/env python3
"""Tests for the KeySentry free-tier caps (FREE-TIER-CAPS.md).

Covers the CLI side: daily counters (increments + midnight-UTC
rollover with a faked date), the per-fingerprint 1x/day check gate in
fingerprint_watch.py, the MCP server 100/day query counter, the Maker
tier in plans.json, the plans.json -> lib/plans.json sync, and the
per-resource upgrade copy. No network, database, or Stripe.

Run with:
  python3 -m pytest tests/test_caps.py
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import fingerprint_watch as fw  # noqa: E402
import mcp_server as mcp  # noqa: E402
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


def _check_ns(results, fingerprints, plan, dry_run=True):
    return argparse.Namespace(results=str(results),
                              fingerprints=str(fingerprints),
                              dry_run=dry_run, plan=plan)


def _dt(year, month, day, hour=0, minute=0):
    return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)


# --- daily counters: increments + midnight-UTC rollover ----------------

def test_daily_counter_increments_and_reads_back(tmp_path):
    usage = str(tmp_path / "usage.json")
    assert plans.daily_used("scans_per_day", usage) == 0
    assert plans.record_daily_use("scans_per_day", usage) == 1
    assert plans.record_daily_use("scans_per_day", usage) == 2
    assert plans.daily_used("scans_per_day", usage) == 2
    # Other resources are independent counters.
    assert plans.daily_used("audits_per_day", usage) == 0
    assert plans.record_daily_use("audits_per_day", usage) == 1


def test_daily_counter_rolls_over_at_midnight_utc(tmp_path):
    usage = str(tmp_path / "usage.json")
    day1 = _dt(2026, 11, 21, 23, 30)  # 23:30 UTC, Nov 21
    day2 = _dt(2026, 11, 22, 0, 30)  # 00:30 UTC, Nov 22
    assert plans.record_daily_use("scans_per_day", usage, now=day1) == 1
    assert plans.record_daily_use("scans_per_day", usage, now=day1) == 2
    assert plans.daily_used("scans_per_day", usage, now=day1) == 2
    # Same counter, next UTC day: rolled over to zero.
    assert plans.daily_used("scans_per_day", usage, now=day2) == 0
    # And the cap check allows again.
    allowed, _, used, limit = plans.check_daily_cap_today(
        "free", "scans_per_day", usage, now=day2)
    assert allowed is True and used == 0 and limit == 2
    # A stale state file (yesterday's date) loads as empty.
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps(
        {"date": "2026-11-21",
         "counters": {"scans_per_day": 2}}), encoding="utf-8")
    assert plans.load_daily_usage(str(stale), now=day2) == {
        "date": "2026-11-22", "counters": {}}
    # A UTC-evening time in a US timezone is still the same UTC day.
    assert plans.utc_today(_dt(2026, 11, 21, 19, 0)) == "2026-11-21"


def test_daily_cap_check_boundaries():
    # 2/day: the 1st and 2nd uses are allowed, the 3rd is denied.
    assert plans.check_daily_cap("free", "scans_per_day", 0)[0] is True
    assert plans.check_daily_cap("free", "scans_per_day", 1)[0] is True
    allowed, msg, used, limit = plans.check_daily_cap(
        "free", "scans_per_day", 2)
    assert allowed is False and used == 2 and limit == 2
    assert "Maker" in msg and "$19" in msg
    assert "come back tomorrow" in msg.lower()
    # 100/day MCP: 100 allowed, 101 denied.
    assert plans.check_daily_cap("free", "mcp_queries_per_day", 99)[0] is True
    assert plans.check_daily_cap("free", "mcp_queries_per_day", 100)[0] is False


# --- per-fingerprint 1x/day (fingerprint_watch.py check) --------------

def test_watch_second_check_same_day_prompts_but_still_shows_result(
        tmp_path, monkeypatch, capsys):
    usage = tmp_path / "usage.json"
    monkeypatch.setattr(plans, "_usage_state_path",
                        lambda path=None: str(usage))
    fps = _fps(2)
    # Seed: the first fingerprint was already checked today.
    usage.write_text(json.dumps({
        "date": plans.utc_today(),
        "counters": {f"fingerprint_check:{fps[0]}": 1}}),
        encoding="utf-8")
    fp_file = tmp_path / "fp.json"
    res_file = tmp_path / "res.json"
    _write_fp_file(fp_file, fps)
    _write_results_file(res_file, fps)
    rc = fw.cmd_check(_check_ns(res_file, fp_file, "free", dry_run=True))
    out = capsys.readouterr().out
    assert rc == 0
    # Upgrade prompt: Starter, $49/mo, fingerprint monitoring, and the
    # come-back-tomorrow line.
    assert "Starter" in out and "$49" in out
    assert "come back tomorrow" in out.lower()
    assert "1 fingerprint(s) already checked today" in out
    # Never a dead end: both fingerprints' matches still display.
    assert "2 match(es)" in out
    assert "fingerprint checks today: 1 of 2 fingerprint(s) checked" in out
    # Dry run consumed nothing: the fresh fingerprint is still fresh.
    assert plans.daily_used(f"fingerprint_check:{fps[1]}",
                            str(usage)) == 0


def test_watch_check_records_fresh_fingerprints(tmp_path, monkeypatch,
                                                capsys):
    usage = tmp_path / "usage.json"
    monkeypatch.setattr(plans, "_usage_state_path",
                        lambda path=None: str(usage))
    fps = _fps(2)
    fp_file = tmp_path / "fp.json"
    res_file = tmp_path / "res.json"
    _write_fp_file(fp_file, fps)
    _write_results_file(res_file, fps)
    # Non-dry-run with no admin pass: nothing is POSTed (rc 1), but
    # the checks themselves are recorded.
    rc = fw.cmd_check(_check_ns(res_file, fp_file, "free", dry_run=False))
    out = capsys.readouterr().out
    assert rc == 1
    assert "fingerprint checks today: 2 of 2 fingerprint(s) checked" in out
    assert plans.daily_used(f"fingerprint_check:{fps[0]}",
                            str(usage)) == 1
    assert plans.daily_used(f"fingerprint_check:{fps[1]}",
                            str(usage)) == 1
    # A second run the same day sees both as already checked.
    rc = fw.cmd_check(_check_ns(res_file, fp_file, "free", dry_run=True))
    out = capsys.readouterr().out
    assert "2 fingerprint(s) already checked today" in out
    assert "2 match(es)" in out  # results still display


def test_watch_starter_rechecks_are_unlimited(tmp_path, monkeypatch,
                                              capsys):
    usage = tmp_path / "usage.json"
    monkeypatch.setattr(plans, "_usage_state_path",
                        lambda path=None: str(usage))
    fps = _fps(2)
    usage.write_text(json.dumps({
        "date": plans.utc_today(),
        "counters": {f"fingerprint_check:{fps[0]}": 1,
                     f"fingerprint_check:{fps[1]}": 1}}),
        encoding="utf-8")
    fp_file = tmp_path / "fp.json"
    res_file = tmp_path / "res.json"
    _write_fp_file(fp_file, fps)
    _write_results_file(res_file, fps)
    rc = fw.cmd_check(_check_ns(res_file, fp_file, "starter", dry_run=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "already checked today" not in out
    assert "come back tomorrow" not in out


# --- MCP server 100/day counter ----------------------------------------

def _quota_server(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    fp_file = tmp_path / "fingerprints.json"
    fp_file.write_text(json.dumps({"fingerprints": []}), encoding="utf-8")
    return mcp.KeySentryMCP(results_dir, fp_file, tmp_path / "audit",
                            usage_file=tmp_path / "mcp-usage.json")


def test_mcp_100_queries_then_101st_prompts(tmp_path):
    server = _quota_server(tmp_path)
    for i in range(100):
        res = server.call_tool("fingerprint_check",
                               {"fingerprint": "0" * 16})
        assert "error" not in res, f"query {i + 1} should be allowed"
        assert res["usage"]["queries_used_today"] == i + 1
        assert res["usage"]["queries_limit_per_day"] == 100
    res = server.call_tool("fingerprint_check", {"fingerprint": "0" * 16})
    assert "error" in res
    assert "Maker" in res["error"] and "$19" in res["error"]
    assert "unlimited MCP server queries" in res["error"]
    assert "come back tomorrow" in res["error"].lower()
    assert res["usage"]["queries_used_today"] == 100
    # The denial is an error result, not a crash, and the JSON-RPC
    # wrapper keeps the usage metadata in the text.
    rpc = mcp.handle_request(
        server,
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": "fingerprint_check",
                    "arguments": {"fingerprint": "0" * 16}}})
    # Tool errors are result responses with isError (MCP convention),
    # not top-level JSON-RPC errors.
    assert rpc["result"]["isError"] is True
    text = rpc["result"]["content"][0]["text"]
    assert "Maker" in text and "queries_used_today" in text


def test_mcp_quota_rolls_over_next_utc_day(tmp_path):
    server = _quota_server(tmp_path)
    usage_file = tmp_path / "mcp-usage.json"
    usage_file.write_text(json.dumps(
        {"date": "2026-01-01", "queries": 100}), encoding="utf-8")
    res = server.call_tool("fingerprint_check", {"fingerprint": "0" * 16})
    assert "error" not in res
    assert res["usage"]["queries_used_today"] == 1
    assert res["usage"]["queries_limit_per_day"] == 100


def test_mcp_usage_metadata_on_success_and_refusal(tmp_path):
    server = _quota_server(tmp_path)
    res = server.call_tool("posture_summary", {})
    assert "error" not in res
    assert res["usage"] == {"queries_used_today": 1,
                            "queries_limit_per_day": 100}
    # A raw-key refusal still carries the usage metadata.
    res = server.call_tool("exposure_check",
                           {"fingerprint": "sk-proj-" + "Qw7x9Z2m" * 6})
    assert "error" in res and "Refused" in res["error"]
    assert res["usage"]["queries_used_today"] == 2


# --- Maker tier + sync + upgrade copy ----------------------------------

def test_maker_tier_matches_free_tier_caps_doc():
    data = _load_canonical()
    maker = data["tiers"]["maker"]
    assert maker["name"] == "Maker"
    assert maker["price_monthly_usd"] == 19
    assert maker["price_label"] == "$19/mo"
    limits = maker["limits"]
    assert limits["repos"] == 5
    assert limits["scans_per_day"] is None
    assert limits["mcp_queries_per_day"] is None
    assert limits["dashboard_saves_per_day"] is None
    assert limits["shareable_reports"] is None
    assert limits["audit_timeline_days"] == 30
    assert limits["audits_per_day"] == 2
    assert limits["fingerprints"] == 5
    assert "vibe_monitoring" in maker["features"]
    assert "fix_prs" in maker["features"]
    assert "fingerprint_monitoring" not in maker["features"]
    assert "email_alerts" not in maker["features"]


def test_plans_json_matches_synced_web_copy(tmp_path):
    data = _load_canonical()
    out = tmp_path / "plans.json"
    synced = sync_plans(CANONICAL, str(out))
    assert synced == data
    with open(out, encoding="utf-8") as fh:
        assert json.load(fh) == data
    with open(WEB_COPY, encoding="utf-8") as fh:
        assert json.load(fh) == data


def test_upgrade_copy_names_right_tier_per_resource():
    cases = [
        ("scans_per_day", 2, "Maker", "$19", "unlimited vibe-code scans"),
        ("mcp_queries_per_day", 100, "Maker", "$19",
         "unlimited MCP server queries"),
        ("dashboard_saves_per_day", 2, "Maker", "$19",
         "unlimited dashboard saves"),
        ("audits_per_day", 2, "Starter", "$49",
         "unlimited agent identity audits"),
        ("fingerprint_checks_per_day", 1, "Starter", "$49",
         "automatic fingerprint monitoring"),
    ]
    for resource, used, tier, price, unlocks in cases:
        _, msg, _, _ = plans.check_daily_cap("free", resource, used)
        assert tier in msg, resource
        assert price in msg, resource
        assert unlocks in msg, resource
        assert "come back tomorrow" in msg.lower(), resource
    _, msg = plans.check_limit("free", "shareable_reports", 3)
    assert "Maker" in msg and "unlimited shareable reports" in msg
    _, msg = plans.check_limit("free", "seats", 2)
    assert "Team" in msg and "5 team seats" in msg


def test_plans_counters_subcommand(tmp_path, monkeypatch, capsys):
    usage = tmp_path / "usage.json"
    state = tmp_path / "plan.json"
    monkeypatch.setattr(plans, "_usage_state_path",
                        lambda path=None: str(usage))
    monkeypatch.setattr(plans, "_state_path",
                        lambda path=None: str(state))
    plans.record_daily_use("scans_per_day", str(usage))
    rc = plans.main(["counters"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 of 2 free scans used today" in out
    assert "0 of 2 free audits used today" in out
    assert "0 of 100 free MCP queries used today" in out
    assert "reset at midnight UTC" in out
