#!/usr/bin/env python3
"""Tests for Team basics (fingerprint_watch.py: assign + posture).

Covers the CLI-side helpers and the two new subcommands with the HTTP
layer monkeypatched — no network, no database, no admin passphrase is
ever sent anywhere real. Run with:
  python3 -m pytest tests/test_team.py
(or: python3 -m pytest tests/ from the repo root).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import fingerprint_watch as fw  # noqa: E402

SAMPLE_POSTURE = {
    "repos": [
        {
            "repo": "acme/app",
            "total": 5,
            "open": 3,
            "resolved": 2,
            "byProvider": {"Groq": 3, "Gemini": 2},
            "openByAge": {"lt7d": 1, "d7to30": 1, "gt30d": 1},
            "oldestOpen": "2026-11-10T08:00:00.000Z",
        },
        {
            "repo": "acme/empty",
            "total": 0,
            "open": 0,
            "resolved": 0,
            "byProvider": {},
            "openByAge": {"lt7d": 0, "d7to30": 0, "gt30d": 0},
            "oldestOpen": None,
        },
    ],
    "summary": {
        "totalMatches": 5,
        "openMatches": 3,
        "resolvedMatches": 2,
        "repoCount": 2,
        "openRate": 0.6,
    },
}


def _ns(**kwargs):
    return argparse.Namespace(**kwargs)


# --- assignee normalization -------------------------------------------------

def test_normalize_assignee_trims():
    assert fw.normalize_assignee("  Priya  ") == "Priya"


def test_normalize_assignee_empty_stays_empty():
    assert fw.normalize_assignee("   ") == ""


def test_normalize_assignee_max_100_ok():
    assert fw.normalize_assignee("a" * 100) == "a" * 100


def test_normalize_assignee_over_100_rejected():
    try:
        fw.normalize_assignee("a" * 101)
    except ValueError as exc:
        assert "100" in str(exc)
    else:
        raise AssertionError("expected ValueError for 101 chars")


# --- base URL / admin pass resolution --------------------------------------

def test_base_url_prefers_keysentry_base_url(monkeypatch):
    monkeypatch.setenv("KEYSENTRY_BASE_URL", "https://example.test")
    monkeypatch.setenv("KEYSENTRY_URL", "https://legacy.test")
    assert fw.base_url() == "https://example.test"


def test_base_url_falls_back_to_keysentry_url(monkeypatch):
    monkeypatch.delenv("KEYSENTRY_BASE_URL", raising=False)
    monkeypatch.setenv("KEYSENTRY_URL", "https://legacy.test")
    assert fw.base_url() == "https://legacy.test"


def test_base_url_default(monkeypatch):
    monkeypatch.delenv("KEYSENTRY_BASE_URL", raising=False)
    monkeypatch.delenv("KEYSENTRY_URL", raising=False)
    assert fw.base_url() == fw.DEFAULT_BASE_URL


def test_admin_pass_flag_wins_over_env(monkeypatch):
    monkeypatch.setenv("KEYSENTRY_ADMIN_PASS", "env-pass")
    assert fw.admin_pass_from(_ns(admin_pass="flag-pass")) == "flag-pass"
    assert fw.admin_pass_from(_ns(admin_pass="")) == "env-pass"


# --- posture formatting -----------------------------------------------------

def test_format_posture_table_has_repos_and_summary():
    text = fw.format_posture_table(SAMPLE_POSTURE)
    assert "acme/app" in text
    assert "3" in text  # open count for acme/app
    assert "Gemini: 2, Groq: 3" in text  # providers sorted by name
    assert "2026-11-10" in text  # oldest open, date only
    assert "5 matches across 2 repo(s)" in text
    assert "60% open rate" in text


def test_format_posture_table_empty():
    text = fw.format_posture_table({"repos": [], "summary": {}})
    assert "0 matches across 0 repo(s)" in text


def test_csv_cell_quoting():
    assert fw._csv_cell("plain") == "plain"
    assert fw._csv_cell("has, comma") == '"has, comma"'
    assert fw._csv_cell('has "quote"') == '"has ""quote"""'


def test_posture_to_csv_columns_and_quoting():
    csv_text = fw.posture_to_csv(SAMPLE_POSTURE)
    lines = csv_text.strip().split("\n")
    assert lines[0] == ("repo,total,open,resolved,open_lt7d,open_7to30d,"
                        "open_gt30d,oldest_open,by_provider")
    assert lines[1].startswith("acme/app,5,3,2,1,1,1,2026-11-10")
    assert "Gemini: 2; Groq: 3" in lines[1]  # providers sorted by name
    # JSON round-trip of the same payload stays intact.
    assert json.loads(json.dumps(SAMPLE_POSTURE))["summary"]["openRate"] == 0.6


# --- assign subcommand (HTTP mocked) ---------------------------------------

def test_cmd_assign_posts_id_assignee_and_pass(monkeypatch, capsys):
    seen = {}

    def fake_http(url, payload=None, timeout=15):
        seen["url"] = url
        seen["payload"] = payload
        return {"match": {"id": 7, "repo": "acme/app", "status": "new",
                          "assignee": "Priya"},
                "history": [{"oldStatus": "new", "newStatus": "new",
                             "changedBy": "admin",
                             "note": "assigned to Priya"}]}

    monkeypatch.setattr(fw, "_http_json", fake_http)
    rc = fw.cmd_assign(_ns(id=7, assignee="  Priya ", clear=False,
                           admin_pass="secret"))
    assert rc == 0
    assert seen["url"].endswith("/api/matches/assign")
    assert seen["payload"] == {"id": 7, "assignee": "Priya",
                               "adminPass": "secret"}
    out = capsys.readouterr().out
    assert "match 7" in out and "Priya" in out
    assert "assigned to Priya" in out


def test_cmd_assign_clear_sends_empty_assignee(monkeypatch):
    seen = {}

    def fake_http(url, payload=None, timeout=15):
        seen["payload"] = payload
        return {"match": {"id": 7, "repo": "acme/app", "status": "new",
                          "assignee": ""}, "history": []}

    monkeypatch.setattr(fw, "_http_json", fake_http)
    rc = fw.cmd_assign(_ns(id=7, assignee=None, clear=True,
                           admin_pass="secret"))
    assert rc == 0
    assert seen["payload"]["assignee"] == ""


def test_cmd_assign_needs_admin_pass(monkeypatch, capsys):
    monkeypatch.delenv("KEYSENTRY_ADMIN_PASS", raising=False)
    rc = fw.cmd_assign(_ns(id=7, assignee="Priya", clear=False,
                           admin_pass=""))
    assert rc == 2
    assert "KEYSENTRY_ADMIN_PASS" in capsys.readouterr().err


def test_cmd_assign_rejects_long_assignee(monkeypatch):
    rc = fw.cmd_assign(_ns(id=7, assignee="a" * 101, clear=False,
                           admin_pass="secret"))
    assert rc == 2


def test_cmd_assign_needs_name_or_clear(monkeypatch):
    rc = fw.cmd_assign(_ns(id=7, assignee=None, clear=False,
                           admin_pass="secret"))
    assert rc == 2


# --- posture subcommand (HTTP mocked) --------------------------------------

def test_cmd_posture_prints_table(monkeypatch, capsys):
    monkeypatch.setattr(fw, "_http_json",
                        lambda url, payload=None, timeout=15: SAMPLE_POSTURE)
    rc = fw.cmd_posture(_ns(export=None, out=""))
    assert rc == 0
    assert "acme/app" in capsys.readouterr().out


def test_cmd_posture_export_csv(monkeypatch, tmp_path):
    monkeypatch.setattr(fw, "_http_json",
                        lambda url, payload=None, timeout=15: SAMPLE_POSTURE)
    out = str(tmp_path / "posture.csv")
    rc = fw.cmd_posture(_ns(export="csv", out=out))
    assert rc == 0
    text = open(out, encoding="utf-8").read()
    assert text.startswith("repo,total,open,resolved")
    assert "acme/app,5,3,2" in text


def test_cmd_posture_export_json(monkeypatch, tmp_path):
    monkeypatch.setattr(fw, "_http_json",
                        lambda url, payload=None, timeout=15: SAMPLE_POSTURE)
    out = str(tmp_path / "posture.json")
    rc = fw.cmd_posture(_ns(export="json", out=out))
    assert rc == 0
    data = json.load(open(out, encoding="utf-8"))
    assert data["summary"]["totalMatches"] == 5


def test_cmd_posture_http_error(monkeypatch, capsys):
    import urllib.error

    def fake_http(url, payload=None, timeout=15):
        raise urllib.error.HTTPError(url, 503, "unavailable", {}, None)

    monkeypatch.setattr(fw, "_http_json", fake_http)
    rc = fw.cmd_posture(_ns(export=None, out=""))
    assert rc == 1
    assert "503" in capsys.readouterr().err
