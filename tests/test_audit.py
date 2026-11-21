#!/usr/bin/env python3
"""Tests for the Pillar 3 audit trail (audit/ package + audit.py CLI).

Secret values below are SYNTHETIC test data, built at runtime from
repetition — never real credentials (same convention as
tests/test_example_filter.py). The smuggle tests assert the stored log
file contains NONE of the secret substrings.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from audit import (  # noqa: E402
    append_event,
    canonical_json,
    compute_event_hash,
    new_event,
    read_events,
    redact_event,
    run_all_detections,
    validate_event,
    verify_chain,
)
from audit.detections import (  # noqa: E402
    detect_confidence_floor,
    detect_cost_spike,
    detect_cross_tenant_access,
    detect_subagent_fanout,
    detect_tool_set_drift,
)
from audit.export import (  # noqa: E402
    apply_retention,
    eu_ai_act_report,
    iso27001_report,
    render_markdown,
    siem_export,
    soc2_report,
)
from audit.redact import find_secret_hits, scrub_text  # noqa: E402

AUDIT_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "audit.py")

# --- Synthetic secrets (built at runtime, never real credentials) -------
OPENAI_KEY = "sk-" + "Ab3dEf7h" * 6          # sk- + 48 alphanumerics
GROQ_KEY = "gsk_" + "Qw7xZr2pLm9vBn4" * 2    # gsk_ + 30 alphanumerics
HF_TOKEN = "hf_" + "Kp3mN8wQ2xZ6vR4tY7u" * 2
PASSWORD = "Sup3rSecretPassw0rd!"
# A key split across two fields: neither half matches a detector or the
# entropy heuristic on its own (low-entropy runs), the fused whole does.
SPLIT_FIRST = "sk-" + "A" * 24
SPLIT_SECOND = "B" * 24
SPLIT_WHOLE = SPLIT_FIRST + SPLIT_SECOND


def base_event(**overrides):
    event = new_event(
        event_type="mcp.tool_call",
        principal_id="human-1",
        parent_agent_id="",
        session_id="sess-001",
        policy_id="pol-default",
        ticket_of_record="TKT-1",
        model_run_id="run-001",
        agent_id="agent-1",
        agent_version="1.0.0",
        model="gpt-4o-mini",
        tool="read_file",
        resource="repo/src/app.py",
        arg_keys=["path"],
        decision={"allow": True, "policy": "pol-default", "reason": "ok"},
        outcome="success",
        correlation_id="task-001",
    )
    event.update(overrides)
    return event


def run_cli(*argv, stdin_text=None, cwd=None):
    return subprocess.run(
        [sys.executable, AUDIT_PY, *argv],
        input=stdin_text, capture_output=True, text=True, cwd=cwd)


# --- Schema validation ----------------------------------------------------
def test_valid_event_passes():
    assert validate_event(base_event()) == []


def test_missing_field_rejected():
    event = base_event()
    del event["tool"]
    errors = validate_event(event)
    assert any("tool" in e for e in errors)


def test_bad_outcome_rejected():
    assert validate_event(base_event(outcome="maybe"))


def test_confidence_out_of_range_rejected():
    assert validate_event(base_event(confidence=1.5))
    assert validate_event(base_event(confidence=-0.1))
    assert validate_event(base_event(confidence=0.5)) == []


def test_secret_in_plain_field_rejected():
    assert validate_event(base_event(tool=OPENAI_KEY))


def test_split_secret_rejected():
    # First half in `tool`, second half in `resource`: EVENT_FIELDS order
    # (tool before resource) reassembles the halves in the fused check.
    event = base_event(tool=SPLIT_FIRST, resource=SPLIT_SECOND)
    # Validation runs after the chain sets prev_hash (append_event);
    # supply the genesis hash here so the secret checks are reached.
    event["prev_hash"] = "0" * 64
    errors = validate_event(event)
    assert any("split" in e for e in errors)


# --- Redaction: smuggle attempts -------------------------------------------
def test_smuggle_openai_key_in_arg_value(tmp_path):
    """(a) realistic-looking OpenAI key as an argument VALUE."""
    raw = base_event()
    raw["args"] = {"api_key": OPENAI_KEY, "model": "gpt-4o-mini"}
    redacted = redact_event(raw)
    # base_event() already carries arg_keys=["path"]; redact merges the
    # args keys in (key names only — the values never survive).
    assert redacted["arg_keys"] == ["path", "api_key", "model"]
    assert OPENAI_KEY not in canonical_json(redacted)
    log = tmp_path / "audit.jsonl"
    append_event(str(log), redacted)
    assert OPENAI_KEY not in log.read_text()


def test_smuggle_token_in_error_message(tmp_path):
    """(b) a token hiding in an error message / decision reason."""
    raw = base_event()
    raw["decision"] = {"allow": False, "policy": "pol-default",
                       "reason": f"upstream 401: token {GROQ_KEY} rejected"}
    redacted = redact_event(raw)
    assert GROQ_KEY not in redacted["decision"]["reason"]
    assert "[REDACTED]" in redacted["decision"]["reason"]
    log = tmp_path / "audit.jsonl"
    append_event(str(log), redacted)
    assert GROQ_KEY not in log.read_text()


def test_smuggle_password_field(tmp_path):
    """(c) a password field: key NAME may stay, value must never."""
    raw = base_event()
    raw["args"] = {"username": "alice", "password": PASSWORD}
    redacted = redact_event(raw)
    assert redacted["arg_keys"] == ["path", "username", "password"]
    assert PASSWORD not in canonical_json(redacted)
    log = tmp_path / "audit.jsonl"
    append_event(str(log), redacted)
    assert PASSWORD not in log.read_text()


def test_smuggle_json_blob_with_secret(tmp_path):
    """(d) a raw JSON blob with a secret nested inside arg values."""
    raw = base_event()
    raw["args"] = {"config": json.dumps({"api_key": OPENAI_KEY,
                                         "timeout": 30})}
    redacted = redact_event(raw)
    assert redacted["arg_keys"] == ["path", "config"]
    assert OPENAI_KEY not in canonical_json(redacted)
    log = tmp_path / "audit.jsonl"
    append_event(str(log), redacted)
    assert OPENAI_KEY not in log.read_text()


def test_smuggle_secret_split_across_fields(tmp_path):
    """(e) a secret split across two fields: validation must reject it,
    so nothing is ever written."""
    raw = base_event(tool=SPLIT_FIRST, resource=SPLIT_SECOND)
    redacted = redact_event(raw)
    redacted["prev_hash"] = "0" * 64  # chain sets this at append time
    errors = validate_event(redacted)
    assert any("split" in e for e in errors)
    log = tmp_path / "audit.jsonl"
    result = run_cli("log", "--log", str(log),
                     stdin_text=json.dumps(raw), cwd=str(tmp_path))
    assert result.returncode != 0
    assert not log.exists() or SPLIT_WHOLE not in log.read_text()


def test_scrub_text_replaces_hits():
    scrubbed = scrub_text(f"leaked {HF_TOKEN} here")
    assert HF_TOKEN not in scrubbed
    assert "[REDACTED]" in scrubbed
    assert find_secret_hits("plain english words only") == []


def test_redact_assigns_id_and_timestamp():
    raw = base_event()
    del raw["event_id"]
    del raw["timestamp"]
    redacted = redact_event(raw)
    assert len(redacted["event_id"]) == 32
    assert redacted["timestamp"]
    redacted["prev_hash"] = "0" * 64
    assert validate_event(redacted) == []


def test_redact_drops_unknown_fields():
    raw = base_event()
    raw["api_key"] = OPENAI_KEY
    raw["nested"] = {"token": GROQ_KEY}
    redacted = redact_event(raw)
    assert "api_key" not in redacted
    assert "nested" not in redacted
    assert OPENAI_KEY not in canonical_json(redacted)
    assert GROQ_KEY not in canonical_json(redacted)


# --- Hash chain ---------------------------------------------------------------
def test_append_and_verify_passes(tmp_path):
    log = tmp_path / "audit.jsonl"
    for _ in range(5):
        append_event(str(log), base_event())
    result = verify_chain(str(log))
    assert result["ok"] is True
    assert result["count"] == 5
    assert result["first_bad_index"] is None


def test_genesis_hash_correct(tmp_path):
    log = tmp_path / "audit.jsonl"
    stored = append_event(str(log), base_event())
    assert stored["prev_hash"] == "0" * 64
    without_hash = {k: v for k, v in stored.items() if k != "event_hash"}
    assert stored["event_hash"] == compute_event_hash(
        without_hash, stored["prev_hash"])


def test_tamper_one_byte_fails_at_exact_index(tmp_path):
    log = tmp_path / "audit.jsonl"
    for i in range(5):
        append_event(str(log), base_event(tool=f"tool_{i}"))
    lines = log.read_text().splitlines()
    tampered = lines[2].replace("tool_2", "tool_X", 1)
    assert tampered != lines[2]
    lines[2] = tampered
    log.write_text("\n".join(lines) + "\n")
    result = verify_chain(str(log))
    assert result["ok"] is False
    assert result["first_bad_index"] == 2
    assert result["events"][0]["ok"] is True
    assert result["events"][1]["ok"] is True
    assert result["events"][2]["ok"] is False


def test_cli_log_and_verify(tmp_path):
    log = tmp_path / "audit.jsonl"
    result = run_cli("log", "--log", str(log),
                     stdin_text=json.dumps(base_event()), cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    stored = json.loads(result.stdout)
    assert stored["stored"] is True
    result = run_cli("verify", "--log", str(log), cwd=str(tmp_path))
    assert result.returncode == 0, result.stdout
    assert "chain intact" in result.stdout


def test_cli_log_scrubs_secret_in_reason(tmp_path):
    log = tmp_path / "audit.jsonl"
    raw = base_event()
    raw["decision"] = {"allow": True, "policy": "p",
                       "reason": f"key was {OPENAI_KEY}"}
    # Redaction scrubs the reason, so this one is stored CLEAN...
    result = run_cli("log", "--log", str(log),
                     stdin_text=json.dumps(raw), cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    assert OPENAI_KEY not in log.read_text()
    assert "[REDACTED]" in log.read_text()


# --- Timeline filters ---------------------------------------------------------
def test_cli_timeline_filters(tmp_path):
    log = tmp_path / "audit.jsonl"
    for agent, session, run in [("agent-1", "sess-1", "run-1"),
                                ("agent-2", "sess-1", "run-1"),
                                ("agent-1", "sess-2", "run-2")]:
        append_event(str(log), base_event(
            agent_id=agent, session_id=session, correlation_id=run))
    out = run_cli("timeline", "--log", str(log), "--agent", "agent-2",
                  cwd=str(tmp_path)).stdout
    assert "agent=agent-2" in out
    assert "agent=agent-1" not in out
    out = run_cli("timeline", "--log", str(log), "--run", "run-2",
                  cwd=str(tmp_path)).stdout
    assert "run=run-2" in out
    assert "run=run-1" not in out


# --- Detections -----------------------------------------------------------------
def _timed_event(ts, **overrides):
    return base_event(timestamp=ts, **overrides)


def test_detector_tool_set_drift_positive():
    events = [_timed_event(f"2026-11-21T10:0{i}:00+00:00", tool="read_file")
              for i in range(5)]
    events.append(_timed_event("2026-11-21T10:05:00+00:00", tool="exec_shell"))
    alerts = detect_tool_set_drift(events)
    assert len(alerts) == 1
    assert alerts[0]["detector"] == "tool_set_drift"
    assert "exec_shell" in alerts[0]["summary"]


def test_detector_tool_set_drift_negative():
    events = [_timed_event(f"2026-11-21T10:0{i}:00+00:00", tool="read_file")
              for i in range(8)]
    assert detect_tool_set_drift(events) == []


def test_detector_cost_spike_positive():
    events = []
    for hour, count in [(10, 5), (11, 5), (12, 30)]:
        for i in range(count):
            events.append(_timed_event(
                f"2026-11-21T{hour:02d}:{i % 60:02d}:00+00:00"))
    alerts = detect_cost_spike(events)
    assert len(alerts) == 1
    assert alerts[0]["detector"] == "cost_spike"
    assert alerts[0]["severity"] == "high"


def test_detector_cost_spike_negative():
    events = []
    for hour, count in [(10, 5), (11, 5), (12, 12)]:
        for i in range(count):
            events.append(_timed_event(
                f"2026-11-21T{hour:02d}:{i % 60:02d}:00+00:00"))
    assert detect_cost_spike(events) == []


def test_detector_confidence_floor_positive():
    events = [base_event(confidence=0.9),
              base_event(confidence=0.65),
              base_event(confidence=0.4)]
    alerts = detect_confidence_floor(events)
    assert len(alerts) == 1
    assert alerts[0]["detector"] == "confidence_floor_breach"
    assert len(alerts[0]["evidence_event_ids"]) == 2


def test_detector_confidence_floor_negative():
    events = [base_event(confidence=0.9), base_event(confidence=0.7),
              base_event(confidence=None)]
    assert detect_confidence_floor(events) == []


def test_detector_cross_tenant_positive():
    events = [base_event(resource="tenant:acme/db/users"),
              base_event(resource="tenant:globex/db/users")]
    alerts = detect_cross_tenant_access(events)
    assert len(alerts) == 1
    assert alerts[0]["detector"] == "cross_tenant_access"


def test_detector_cross_tenant_negative():
    events = [base_event(resource="tenant:acme/db/users"),
              base_event(resource="tenant:acme/db/orders")]
    assert detect_cross_tenant_access(events) == []


def test_detector_subagent_fanout_positive():
    events = []
    for i in range(6):
        events.append(_timed_event(
            f"2026-11-21T10:0{i}:00+00:00",
            parent_agent_id="parent-1", agent_id=f"child-{i}"))
    alerts = detect_subagent_fanout(events)
    assert len(alerts) == 1
    assert alerts[0]["detector"] == "sub_agent_fanout"


def test_detector_subagent_fanout_negative():
    events = []
    for i in range(5):
        events.append(_timed_event(
            f"2026-11-21T10:0{i}:00+00:00",
            parent_agent_id="parent-1", agent_id=f"child-{i}"))
    assert detect_subagent_fanout(events) == []


def test_cli_detect(tmp_path):
    log = tmp_path / "audit.jsonl"
    for i in range(5):
        append_event(str(log), base_event(tool="read_file"))
    append_event(str(log), base_event(tool="exec_shell"))
    result = run_cli("detect", "--log", str(log), cwd=str(tmp_path))
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert any(a["detector"] == "tool_set_drift" for a in data["alerts"])
    assert run_all_detections(read_events(str(log)))


# --- Retention ------------------------------------------------------------------
def _old_event(days_ago, **overrides):
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    return base_event(timestamp=ts, **overrides)


def test_retention_moves_old_events(tmp_path):
    log = tmp_path / "audit.jsonl"
    archive = tmp_path / "archive"
    # Oldest first, so the surviving hot event chains to the archive.
    append_event(str(log), _old_event(100))  # cold (>90d)
    append_event(str(log), _old_event(40))   # warm (>30d, <90d)
    append_event(str(log), _old_event(1))    # hot
    result = apply_retention(str(log), str(archive))
    assert result == {"hot": 1, "warm": 1, "cold": 1,
                      "warm_path": str(archive / "audit-warm.jsonl"),
                      "cold_path": str(archive / "audit-cold.jsonl")}
    assert len(read_events(str(log))) == 1
    assert len(read_events(str(archive / "audit-warm.jsonl"))) == 1
    assert len(read_events(str(archive / "audit-cold.jsonl"))) == 1
    # The hot log still verifies: its first event continues the chain
    # from the archived segment instead of failing.
    verified = verify_chain(str(log))
    assert verified["ok"] is True
    assert verified["continued_from_archive"] is True


def test_cli_retention_dry_run(tmp_path):
    log = tmp_path / "audit.jsonl"
    append_event(str(log), _old_event(40))
    result = run_cli("retention", "--log", str(log),
                     "--archive-dir", str(tmp_path / "archive"),
                     cwd=str(tmp_path))
    assert result.returncode == 0
    assert "dry run" in result.stdout
    assert len(read_events(str(log))) == 1  # nothing moved


# --- Export -----------------------------------------------------------------------
def test_export_soc2_sections():
    events = [base_event(event_type="mcp.tool_call"),
              base_event(event_type="agent.action",
                         decision={"allow": False, "policy": "p",
                                   "reason": "denied"}, outcome="denied")]
    report = soc2_report(events)
    assert "Mapping template only" in report["disclaimer"]
    controls = {c["control"]: c for c in report["controls"]}
    assert controls["CC7.2"]["events_matched"] == 2
    assert controls["CC6.1"]["events_matched"] == 2
    assert report["event_count"] == 2


def test_export_iso27001_sections():
    report = iso27001_report([base_event()])
    controls = {c["control"] for c in report["controls"]}
    assert {"A.12.4.1", "A.12.4.2", "A.9.2.1"} <= controls
    assert "Mapping template only" in report["disclaimer"]


def test_export_eu_ai_act_fields():
    report = eu_ai_act_report([base_event()])
    assert report["article"] == "12"
    record = report["records"][0]
    assert record["actor"]["agent_id"] == "agent-1"
    assert record["operation"]["tool"] == "read_file"
    assert record["decision"]["allow"] is True
    assert record["outcome"] == "success"
    assert "timestamp" in record
    md = render_markdown(report)
    assert "EU AI Act" in md and "Article 12" in md


def test_export_siem_jsonl_no_secrets(tmp_path):
    raw = base_event()
    raw["decision"] = {"allow": True, "policy": "p",
                       "reason": f"saw {OPENAI_KEY} in output"}
    stored = append_event(str(tmp_path / "audit.jsonl"), redact_event(raw))
    text = siem_export([stored])
    assert OPENAI_KEY not in text
    assert json.loads(text.strip())["event_id"] == stored["event_id"]


def test_cli_export_formats(tmp_path):
    log = tmp_path / "audit.jsonl"
    append_event(str(log), base_event())
    for fmt in ("soc2", "iso27001", "eu-ai-act", "siem"):
        result = run_cli("export", "--log", str(log), "--format", fmt,
                         cwd=str(tmp_path))
        assert result.returncode == 0, (fmt, result.stderr)
        assert result.stdout.strip()
    result = run_cli("export", "--log", str(log), "--format", "soc2",
                     "--md", cwd=str(tmp_path))
    assert result.returncode == 0
    assert "| CC7.2 |" in result.stdout
