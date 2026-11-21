#!/usr/bin/env python3
"""Tests for Pillar 2 — vibe-code security scanner.

Fixtures in tests/fixtures/vibe/ are synthetic test data only. The
.env fixture carries a TESTFAKE key (an example key by construction);
the realistic-looking leaked key used in the masked-only test is built
at runtime from a hash, never written as a literal — no real-looking
credential literal sits in this repo.
"""
import hashlib
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from detectors.registry import DETECTORS  # noqa: E402
from scripts.export_detector_patterns import export_patterns  # noqa: E402
from vibe_checks import (  # noqa: E402
    build_audit_events, check_file, verify_audit_chain,
)
from vibe_scan import scan_repo  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "fixtures", "vibe")


def _read(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def _ids(findings):
    return {f["id"] for f in findings}


# --- vibe_checks on fixture files -----------------------------------------

def test_firebase_open_read_flagged():
    findings = check_file("firestore.rules", _read("firestore.rules"))
    assert "vibe-firebase-open-rules" in _ids(findings)
    f = next(x for x in findings if x["id"] == "vibe-firebase-open-rules")
    assert f["severity"] == "critical"
    assert f["fix"]  # plain-language fix present


def test_cors_wildcard_flagged():
    findings = check_file("server.js", _read("server.js"))
    assert "vibe-cors-wildcard" in _ids(findings)


def test_mongo_uri_without_auth_flagged():
    findings = check_file("config.js", _read("config.js"))
    assert "vibe-db-no-auth" in _ids(findings)


def test_hardcoded_internal_ip_flagged():
    findings = check_file("config.js", _read("config.js"))
    assert "vibe-hardcoded-internal-url" in _ids(findings)


def test_api_route_without_auth_is_heuristic():
    findings = check_file("api/hello.js", _read("api/hello.js"))
    assert "vibe-api-no-auth" in _ids(findings)
    f = next(x for x in findings if x["id"] == "vibe-api-no-auth")
    assert "heuristic" in f["title"].lower()
    assert "heuristic" in f["fix"].lower()


def test_api_route_with_auth_passes():
    text = ("import { verifyToken } from './auth';\n"
            "export default async function handler(req, res) {\n"
            "  const user = verifyToken(req);\n"
            "  res.status(200).json({ ok: true });\n}\n")
    assert "vibe-api-no-auth" not in _ids(check_file("api/me.js", text))


def test_env_file_flagged_but_testfake_key_not_a_leak(tmp_path):
    # The .env fixture itself is a committed-env finding; its TESTFAKE
    # key must NOT become a leaked-secret finding.
    env_text = _read(".env")
    assert "vibe-env-committed" in _ids(check_file(".env", env_text))
    # Scan a clean copy (no .gitignore) so the .env is actually read.
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES, repo)
    report = scan_repo(str(repo), "fixture-repo")
    secret = [f for f in report["findings"]
              if f["id"] == "vibe-leaked-secret"]
    assert secret == []
    assert "vibe-env-committed" in _ids(report["findings"])
    assert "vibe-firebase-open-rules" in _ids(report["findings"])
    assert "vibe-cors-wildcard" in _ids(report["findings"])
    assert "vibe-db-no-auth" in _ids(report["findings"])
    assert "vibe-api-no-auth" in _ids(report["findings"])


def test_every_finding_has_plain_language_fix(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES, repo)
    report = scan_repo(str(repo), "fixture-repo")
    assert report["findings"], "fixture repo should produce findings"
    for f in report["findings"]:
        assert f["fix"] and len(f["fix"]) > 20, f["id"]
        assert f["title"] and f["severity"] in (
            "critical", "high", "medium", "low")


# --- masked-only report ----------------------------------------------------

def test_report_json_is_masked_only(tmp_path):
    # Synthetic realistic-looking key, built at runtime from a hash.
    synthetic = "gsk_" + hashlib.sha256(b"vibe-test-key").hexdigest()[:32]
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        f'GROQ_API_KEY = "{synthetic}"\n', encoding="utf-8")
    report = scan_repo(str(repo), "tmp-repo")
    leaked = [f for f in report["findings"]
              if f["id"] == "vibe-leaked-secret"]
    assert len(leaked) == 1
    assert leaked[0]["masked"].startswith("gsk_")
    assert leaked[0]["fingerprint"] == hashlib.sha256(
        synthetic.encode()).hexdigest()[:16]
    dumped = json.dumps(report)
    assert synthetic not in dumped, "raw secret leaked into report JSON"
    assert synthetic not in json.dumps(report["findings"])


# --- pattern export: single source of truth --------------------------------

def test_exported_patterns_match_live_registry(tmp_path):
    from scripts.export_detector_patterns import main as export_main
    out = tmp_path / "detector-patterns.json"
    assert export_main(["--output", str(out)]) == 0
    exported = json.loads(out.read_text(encoding="utf-8"))
    live = export_patterns()
    assert exported == live
    assert len(exported["detectors"]) == len(DETECTORS)
    for exported_det, live_det in zip(exported["detectors"], DETECTORS):
        assert exported_det["provider"] == live_det.provider
        assert exported_det["pattern"] == live_det.pattern
        assert exported_det["cred_type"] == live_det.cred_type
    # Every regex in the export must compile.
    import re
    for det in exported["detectors"]:
        if det["pattern"] is not None:
            re.compile(det["pattern"])


def test_exported_json_file_matches_registry():
    generated = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "..", "key-sentry", "lib", "detector-patterns.json")
    generated = os.path.normpath(generated)
    assert os.path.exists(generated), (
        "run scripts/export_detector_patterns.py to generate "
        "key-sentry/lib/detector-patterns.json")
    on_disk = json.load(open(generated, encoding="utf-8"))
    assert on_disk == export_patterns()


# --- audit events ------------------------------------------------------------

def test_audit_events_chain_and_schema():
    findings = [
        {"id": "vibe-firebase-open-rules", "fingerprint": None},
        {"id": "vibe-cors-wildcard", "fingerprint": None},
    ]
    events = build_audit_events(findings, "https://github.com/o/r",
                                "report123")
    assert len(events) == 2
    assert events[0]["prev_hash"] == "0" * 64
    assert events[1]["prev_hash"] == events[0]["event_hash"]
    assert verify_audit_chain(events)
    required = {"event_id", "event_type", "timestamp", "prev_hash",
                "event_hash", "principal_id", "parent_agent_id",
                "session_id", "policy_id", "ticket_of_record",
                "model_run_id", "agent_id", "agent_version", "model",
                "tool", "resource", "arg_keys", "decision", "outcome",
                "correlation_id"}
    for event in events:
        assert set(event.keys()) == required, set(event.keys()) ^ required
        assert event["event_type"] == "vibe.finding"
        assert event["principal_id"] == "anonymous"
        assert event["agent_id"] == "vibe-scanner"
        assert event["agent_version"] == "0.1.0"
        assert event["policy_id"] == "vibe-scan"
        assert event["arg_keys"] == ["repoUrl"]
        assert event["session_id"] == "report123"
        assert event["correlation_id"] == "report123"
        assert event["decision"] == {"allow": True, "policy": "vibe-scan",
                                     "reason": "public repo scan"}
        assert event["outcome"] == "success"
        assert event["resource"] == "https://github.com/o/r"
