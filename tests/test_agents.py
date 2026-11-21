#!/usr/bin/env python3
"""Tests for Pillar 1 — Agent Identity (agents/ + mcp_server.py).

Covers the MCP config scanner, the agent -> credential -> repo ->
owner mapping, fingerprint-only output, the example-key filter, and
the read-only MCP server (JSON-RPC over stdio + hash-chained audit).

All key material below is synthetic test data, built at runtime from
hashes so no real-looking literal sits in the repo. The one literal
key-shaped value used is TESTFAKE-marked (an example key by design).
Run with:  python3 -m pytest tests/test_agents.py
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from agents import build_inventory, build_mapping, scan_config_file  # noqa: E402
from agents.scanner import load_result_fingerprints  # noqa: E402
from common import value_hash  # noqa: E402
from mcp_server import (  # noqa: E402
    compute_event_hash,
    run_selftest,
    verify_audit_chain,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agents"


def _runtime_groq_key() -> str:
    """A detector-shaped Groq key built at runtime (never a literal)."""
    return "gsk_" + hashlib.sha256(b"test-agents-groq-key").hexdigest()[:40]


def _runtime_openai_key() -> str:
    return "sk-proj-" + hashlib.sha256(b"test-agents-openai-key").hexdigest()[:40]


# --- parser: fixture configs ---------------------------------------------

def test_mcp_json_fixture_parses_servers_and_env_refs():
    agents = scan_config_file(FIXTURES / ".mcp.json")
    names = {a["name"] for a in agents}
    assert names == {"github", "groq-helper"}
    assert all(a["type"] == "mcp-server" for a in agents)
    github = next(a for a in agents if a["name"] == "github")
    # Env-var reference, provider unknown (github token), no fingerprint.
    assert any(c["env_var"] == "GITHUB_TOKEN" and c["fingerprint"] == ""
               for c in github["credentials"])


def test_testfake_value_in_config_is_not_a_credential():
    agents = scan_config_file(FIXTURES / ".mcp.json")
    groq = next(a for a in agents if a["name"] == "groq-helper")
    # The TESTFAKE-marked Groq value must not be reported at all.
    assert groq["credentials"] == []
    assert "TESTFAKE" not in json.dumps(agents)


def test_claude_settings_fixture_reports_env_refs(tmp_path):
    settings_dir = tmp_path / ".claude"
    settings_dir.mkdir()
    target = settings_dir / "settings.json"
    target.write_text((FIXTURES / "claude-settings.json").read_text(),
                      encoding="utf-8")
    agents = scan_config_file(target)
    assert len(agents) == 1
    assert agents[0]["type"] == "claude-code"
    env_vars = {c["env_var"] for c in agents[0]["credentials"]}
    assert env_vars == {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}
    providers = {c["provider"] for c in agents[0]["credentials"]}
    assert providers == {"Anthropic", "OpenAI"}


def test_cursor_rules_dir_reports_env_ref_and_skips_testfake(tmp_path):
    rules_dir = tmp_path / ".cursor" / "rules"
    rules_dir.mkdir(parents=True)
    target = rules_dir / "project.mdc"
    target.write_text((FIXTURES / "cursor-rules.md").read_text(),
                      encoding="utf-8")
    agents = scan_config_file(target)
    assert len(agents) == 1 and agents[0]["type"] == "cursor"
    env_vars = {c["env_var"] for c in agents[0]["credentials"]}
    assert env_vars == {"GROQ_API_KEY"}
    assert "TESTFAKE" not in json.dumps(agents)


def test_real_key_in_config_is_fingerprinted_not_exposed(tmp_path):
    key = _runtime_groq_key()
    mcp = tmp_path / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {
        "helper": {"command": "node", "args": ["s.js"],
                   "env": {"GROQ_API_KEY": key}}}}), encoding="utf-8")
    agents = scan_config_file(mcp)
    assert len(agents) == 1
    creds = agents[0]["credentials"]
    assert len(creds) == 1
    cred = creds[0]
    assert cred["provider"] == "Groq"
    assert cred["fingerprint"] == value_hash(key)[:16]
    assert cred["masked"] == "gsk_..."
    # No raw value anywhere in the public output.
    assert key not in json.dumps(agents)


# --- inventory / mapping ---------------------------------------------------

def test_inventory_on_fixture_dir(tmp_path):
    root = tmp_path / "repo"
    (root / ".cursor" / "rules").mkdir(parents=True)
    (root / ".claude").mkdir(parents=True)
    (root / ".mcp.json").write_text(
        (FIXTURES / ".mcp.json").read_text(), encoding="utf-8")
    (root / ".claude" / "settings.json").write_text(
        (FIXTURES / "claude-settings.json").read_text(), encoding="utf-8")
    (root / ".cursor" / "rules" / "project.mdc").write_text(
        (FIXTURES / "cursor-rules.md").read_text(), encoding="utf-8")
    inv = build_inventory(root)
    assert inv["summary"]["agent_count"] == 4  # 2 mcp servers + claude + cursor
    assert inv["summary"]["credential_count"] >= 4
    assert "TESTFAKE" not in json.dumps(inv)


def test_mapping_owner_unknown_without_git(tmp_path):
    root = tmp_path / "nogit"
    root.mkdir()
    (root / ".mcp.json").write_text(
        (FIXTURES / ".mcp.json").read_text(), encoding="utf-8")
    mapping = build_mapping(root)
    assert mapping["owner"] == "unknown"
    assert all(a["owner"] == "unknown" for a in mapping["agents"])
    assert all(a["exposed_count"] == 0 for a in mapping["agents"])


def test_mapping_exposed_count_matches_local_results(tmp_path):
    key = _runtime_openai_key()
    fp = value_hash(key)[:16]
    root = tmp_path / "repo"
    (root / "results").mkdir(parents=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "helper": {"command": "node", "args": ["s.js"],
                   "env": {"OPENAI_API_KEY": key}}}}), encoding="utf-8")
    (root / "results" / "SCAN.json").write_text(json.dumps({
        "rows": [{"fingerprint": fp, "provider": "OpenAI",
                  "file": ".mcp.json", "line": 1, "masked": "sk-p..."}]}),
        encoding="utf-8")
    mapping = build_mapping(root)
    agent = mapping["agents"][0]
    assert agent["exposed_count"] == 1
    assert agent["exposed"] == [{"fingerprint": fp, "provider": "OpenAI"}]
    assert key not in json.dumps(mapping)


def test_load_result_fingerprints_reads_both_shapes(tmp_path):
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / "a.json").write_text(json.dumps([
        {"fingerprint_sha256_16": "a" * 16, "provider": "Groq"}]),
        encoding="utf-8")
    (tmp_path / "results" / "b.json").write_text(json.dumps({
        "rows": [{"fingerprint": "b" * 16, "provider": "OpenAI"}]}),
        encoding="utf-8")
    found = load_result_fingerprints([tmp_path])
    assert set(found) == {"a" * 16, "b" * 16}


# --- MCP server: JSON-RPC over stdio ---------------------------------------

def _spawn_server(tmp_path, fingerprints, rows):
    (tmp_path / "fingerprints.json").write_text(
        json.dumps({"fingerprints": fingerprints}), encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir(exist_ok=True)
    (results_dir / "SELFTEST.json").write_text(
        json.dumps({"rows": rows}), encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "mcp_server.py"),
         "--results-dir", str(results_dir),
         "--fingerprints", str(tmp_path / "fingerprints.json"),
         "--audit-dir", str(tmp_path / "audit")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, cwd=str(tmp_path))
    return proc


def _rpc(proc, method, params=None, req_id=1):
    proc.stdin.write(json.dumps(
        {"jsonrpc": "2.0", "id": req_id, "method": method,
         "params": params or {}}) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def _tool_result(resp):
    assert "result" in resp, resp
    content = resp["result"]["content"][0]["text"]
    return json.loads(content)


def test_mcp_server_all_three_tools_via_json_rpc(tmp_path):
    fake_key = "TESTFAKE-gsk_" + "a1b2c3d4" * 5
    fp = hashlib.sha256(fake_key.encode()).hexdigest()[:16]
    proc = _spawn_server(
        tmp_path,
        [{"fingerprint": fp, "provider": "Groq", "label": "t",
          "agent": "claude-code"}],
        [{"fingerprint": fp, "provider": "Groq",
          "file": ".mcp.json", "line": 3, "masked": "TEST..."}])
    try:
        init = _rpc(proc, "initialize",
                    {"clientInfo": {"name": "test-agent", "version": "1"}},
                    req_id=1)
        assert init["result"]["serverInfo"]["name"] == "keysentry"
        tools = _rpc(proc, "tools/list", req_id=2)
        names = {t["name"] for t in tools["result"]["tools"]}
        assert names == {"exposure_check", "fingerprint_check",
                         "posture_summary"}

        res = _tool_result(_rpc(proc, "tools/call",
                                {"name": "exposure_check",
                                 "arguments": {"fingerprint": fp}}, req_id=3))
        assert res["matched"] is True
        assert res["sightings"][0]["masked"] == "TEST..."
        assert fake_key not in json.dumps(res)

        res = _tool_result(_rpc(proc, "tools/call",
                                {"name": "fingerprint_check",
                                 "arguments": {"fingerprint": fp}}, req_id=4))
        assert res["monitored"] is True and res["agent"] == "claude-code"

        res = _tool_result(_rpc(proc, "tools/call",
                                {"name": "posture_summary",
                                 "arguments": {}}, req_id=5))
        assert res["monitored_fingerprints"] == 1
        assert res["open_matches"] == 1
        assert res["by_provider"] == {"Groq": 1}
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)

    # Audit JSONL written, hash chain recomputes, arg keys only.
    audit_file = tmp_path / "audit" / "audit.jsonl"
    assert audit_file.exists()
    events = [json.loads(line) for line in
              audit_file.read_text(encoding="utf-8").splitlines()]
    assert len(events) >= 3
    assert all(e["event_type"] == "mcp.tool_call" for e in events)
    assert all(set(e["arg_keys"]) <= {"fingerprint"} for e in events)
    assert fake_key not in audit_file.read_text(encoding="utf-8")
    chain = verify_audit_chain(audit_file)
    assert len(chain) == len(events) and all(chain)
    # Spot-check the hash formula on the first event.
    first = dict(events[0])
    stored = first.pop("event_hash")
    assert stored == compute_event_hash(first)
    assert first["prev_hash"] == "0" * 64


def test_mcp_server_refuses_raw_key(tmp_path):
    proc = _spawn_server(tmp_path, [], [])
    try:
        _rpc(proc, "initialize", req_id=1)
        raw = "sk-proj-" + "Qw7x9Z2m" * 6
        resp = _rpc(proc, "tools/call",
                    {"name": "exposure_check",
                     "arguments": {"fingerprint": raw}}, req_id=2)
        assert resp["result"].get("isError") is True
        body = _tool_result(resp)
        assert "Refused" in body["error"]
        assert raw not in json.dumps(resp)
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    audit_text = (tmp_path / "audit" / "audit.jsonl").read_text(encoding="utf-8")
    assert raw not in audit_text and "sk-proj" not in audit_text


def test_mcp_server_selftest_passes():
    assert run_selftest() == 0


def test_mcp_server_selftest_cli():
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "mcp_server.py"), "--selftest"],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "all checks passed" in proc.stdout


# --- CLI wiring --------------------------------------------------------------

def test_cli_agents_inventory_json(tmp_path):
    key = _runtime_groq_key()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "helper": {"command": "node", "args": ["s.js"],
                   "env": {"GROQ_API_KEY": key}}}}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "aiscan.py"), "agents", "inventory",
         str(root), "--json"],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["summary"]["agent_count"] == 1
    assert key not in proc.stdout
    assert data["agents"][0]["credentials"][0]["fingerprint"] == \
        value_hash(key)[:16]


def test_cli_agents_map_json(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(
        (FIXTURES / ".mcp.json").read_text(), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "aiscan.py"), "agents", "map",
         str(root), "--json"],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["owner"] == "unknown"
    assert "TESTFAKE" not in proc.stdout
