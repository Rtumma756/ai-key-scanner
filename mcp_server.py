#!/usr/bin/env python3
"""mcp_server.py — KeySentry MCP server (read-only, stdlib only).

Speaks MCP over stdio JSON-RPC (initialize, tools/list, tools/call,
ping). Tools accept FINGERPRINTS ONLY (16 lowercase hex chars) — never
raw key values. If an argument looks like a raw key (matches any
detector pattern, or is longer than 64 chars), the call is refused
with an error and nothing of the value is logged.

Tools:
  exposure_check     {fingerprint} — matched in local scan results?
  fingerprint_check  {fingerprint} — format valid? monitored locally?
  posture_summary    {}            — counts from fingerprints.json +
                                     latest local scan results.

The server NEVER returns raw keys — only fingerprints and masked
(prefix4) forms already present in the local results files.

Audit (Pillar 3 canonical schema): one JSONL event per tool call is
appended to ./audit/audit.jsonl (or --audit-dir / KEYSENTRY_AUDIT_DIR).
Each event is hash-chained: event_hash =
sha256(canonical_json(event without event_hash) + prev_hash), where
canonical_json = json.dumps(sort_keys=True, separators=(",", ":")).
Only argument KEY NAMES are recorded — never values.

Usage:
  python3 mcp_server.py [--results-dir DIR] [--fingerprints FILE]
                        [--audit-dir DIR] [--selftest]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import mask_value  # noqa: E402
from detectors import scan_line  # noqa: E402

# Plan gating (freemium layer): plans.py is the CLI-side source of
# truth for the MCP daily cap (100 queries/day on Free, Maker:
# unlimited) and its upgrade copy. Best-effort import so this file
# still works as a standalone copy; the fallback below enforces the
# Free cap (100/day) with the same upgrade wording.
try:
    import plans as _plans
except ImportError:  # plans.py not on the path
    _plans = None

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_FINGERPRINTS_FILE = BASE_DIR / "fingerprints.json"
DEFAULT_RESULTS_DIR = BASE_DIR / "results"
MCP_USAGE_FILENAME = ".key-sentry-mcp-usage.json"
FREE_MCP_QUERIES_PER_DAY = 100  # fallback when plans.py is unavailable
POLICY_ID = "default-allow-readonly"
PROTOCOL_VERSION = "2025-03-26"

_FP_RE = re.compile(r"^[0-9a-f]{16}$")
_AUDIT_GENESIS_PREV = "0" * 64


def is_valid_fingerprint(value) -> bool:
    return isinstance(value, str) and bool(_FP_RE.match(value))


def looks_like_raw_key(value) -> bool:
    """True when an argument value looks like a raw key, not a
    fingerprint. Refuse it — and log nothing of it."""
    if not isinstance(value, str):
        return False
    if len(value) > 64:
        return True
    if is_valid_fingerprint(value):
        return False
    return bool(scan_line(value))


# ---------------------------------------------------------------------------
# Local data (fingerprints + scan results; read-only)
# ---------------------------------------------------------------------------

def load_watched_fingerprints(path: Path) -> dict[str, dict]:
    """fingerprint -> {provider, label, agent} from fingerprints.json.
    The file may be {"fingerprints": [...]} or a bare list."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    entries = data.get("fingerprints") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        return {}
    out = {}
    for entry in entries:
        if isinstance(entry, dict):
            fp = str(entry.get("fingerprint", "") or "").strip().lower()
            if is_valid_fingerprint(fp):
                out[fp] = {
                    "provider": str(entry.get("provider", "") or ""),
                    "label": str(entry.get("label", "") or ""),
                    "agent": str(entry.get("agent", "") or ""),
                }
        elif isinstance(entry, str) and is_valid_fingerprint(entry.strip().lower()):
            out[entry.strip().lower()] = {"provider": "", "label": "", "agent": ""}
    return out


def load_result_rows(results_dir: Path) -> list[dict]:
    """All finding rows from results/*.json (fingerprint/provider/file/
    line/masked only — never key material)."""
    rows: list[dict] = []
    if not Path(results_dir).is_dir():
        return rows
    for json_file in sorted(Path(results_dir).glob("*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        candidates = data if isinstance(data, list) else (
            data.get("rows") if isinstance(data, dict) else None)
        if not isinstance(candidates, list):
            continue
        for row in candidates:
            if not isinstance(row, dict):
                continue
            fp = row.get("fingerprint_sha256_16") or row.get("fingerprint")
            if isinstance(fp, str) and len(fp) == 16:
                rows.append({
                    "fingerprint": fp.lower(),
                    "provider": str(row.get("provider", "") or ""),
                    "file": str(row.get("file", "") or ""),
                    "line": row.get("line", 0),
                    "masked": str(row.get("masked", "") or ""),
                })
    return rows


# ---------------------------------------------------------------------------
# Audit (canonical hash-chained JSONL, Pillar 3 schema)
# ---------------------------------------------------------------------------

def canonical_json(event: dict) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def compute_event_hash(event_without_hash: dict) -> str:
    prev = event_without_hash["prev_hash"]
    return hashlib.sha256((canonical_json(event_without_hash) + prev).encode("utf-8")).hexdigest()


def verify_audit_chain(audit_file: Path) -> list[bool]:
    """Recompute the hash chain for every event in the file.
    Returns one bool per event (True = hash + linkage check out)."""
    results: list[bool] = []
    prev = _AUDIT_GENESIS_PREV
    try:
        lines = Path(audit_file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return results
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            results.append(False)
            continue
        stored = event.pop("event_hash", None)
        ok = event.get("prev_hash") == prev and stored == compute_event_hash(event)
        results.append(bool(ok))
        prev = stored if isinstance(stored, str) else prev
    return results


class AuditLog:
    """Append-only hash-chained audit log. Writes arg KEY NAMES only."""

    def __init__(self, audit_dir: Path):
        self.dir = Path(audit_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.file = self.dir / "audit.jsonl"

    def _last_hash(self) -> str:
        prev = _AUDIT_GENESIS_PREV
        try:
            for line in self.file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    prev = json.loads(line).get("event_hash", prev)
                except ValueError:
                    continue
        except OSError:
            pass
        return prev

    def emit(self, *, tool: str, arg_keys: list[str], outcome: str,
             session_id: str, agent_id: str = "unknown",
             principal_id: str = "unknown",
             parent_agent_id=None) -> dict:
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": "mcp.tool_call",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "prev_hash": self._last_hash(),
            "principal_id": principal_id,
            "parent_agent_id": parent_agent_id,
            "session_id": session_id,
            "policy_id": POLICY_ID,
            "ticket_of_record": None,
            "model_run_id": None,
            "agent_id": agent_id,
            "agent_version": None,
            "model": None,
            "tool": tool,
            "resource": tool,
            "arg_keys": sorted(arg_keys),
            "decision": {"allow": True, "policy": POLICY_ID,
                         "reason": "read-only tool"},
            "outcome": outcome,
            "correlation_id": session_id,
        }
        event["event_hash"] = compute_event_hash(event)
        with open(self.file, "a", encoding="utf-8") as fh:
            fh.write(canonical_json(event) + "\n")
        return event


# ---------------------------------------------------------------------------
# Tools (fingerprint-only)
# ---------------------------------------------------------------------------

class KeySentryMCP:
    def __init__(self, results_dir: Path, fingerprints_file: Path,
                 audit_dir: Path, session_id: str | None = None,
                 usage_file: Path | None = None):
        self.results_dir = Path(results_dir)
        self.fingerprints_file = Path(fingerprints_file)
        self.audit = AuditLog(audit_dir)
        self.session_id = session_id or str(uuid.uuid4())
        self.agent_id = "unknown"
        # Local daily state file for the MCP query counter (100/day on
        # Free). Same shape as plans.py's usage state: {"date": ...,
        # "queries": N}; a new UTC date resets the count.
        self.usage_file = (Path(usage_file) if usage_file is not None
                           else BASE_DIR / MCP_USAGE_FILENAME)

    # -- daily query quota (FREE-TIER-CAPS.md) --------------------------
    def _query_limit(self) -> int | None:
        """MCP queries/day for the local plan (None = unlimited).

        Plans.py when importable (Maker and up: unlimited), else the
        Free fallback of 100/day.
        """
        if _plans is not None:
            try:
                plan_id = _plans.load_local_plan()
                return _plans.get_plan(plan_id).get("limits", {}).get(
                    "mcp_queries_per_day")
            except Exception:
                pass
        return FREE_MCP_QUERIES_PER_DAY

    def _load_quota_state(self, today: str) -> dict:
        try:
            state = json.loads(self.usage_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"date": today, "queries": 0}
        if not isinstance(state, dict) or state.get("date") != today:
            return {"date": today, "queries": 0}
        queries = state.get("queries", 0)
        return {"date": today,
                "queries": queries if isinstance(queries, int)
                and queries >= 0 else 0}

    def _save_quota_state(self, state: dict) -> None:
        try:
            self.usage_file.write_text(json.dumps(state, indent=2) + "\n",
                                       encoding="utf-8")
        except OSError:
            # Quota state is best-effort: a failed write degrades to
            # unenforced rather than crashing the server.
            pass

    def _quota_message(self, used: int) -> str:
        """Upgrade prompt for a quota hit (names Maker, $19/mo)."""
        if _plans is not None:
            try:
                plan_id = _plans.load_local_plan()
                return _plans.daily_cap_message(
                    plan_id, "mcp_queries_per_day", used)
            except Exception:
                pass
        return (
            "Free plan allows up to 100 MCP server queries per day "
            f"(you have used {used} today). Upgrade to Maker ($19/mo) to "
            "unlock unlimited MCP server queries. Come back tomorrow, it "
            "works again (free caps reset at midnight UTC).")

    def _quota_check(self) -> tuple[bool, dict]:
        """Check-and-record one MCP query.

        Returns (allowed, usage) where usage is
        {"queries_used_today": N, "queries_limit_per_day": M} — the
        metadata every tool result carries ("queries used today:
        N of 100"). The 101st query of the day is denied; the count
        resets on a new UTC date.
        """
        limit = self._query_limit()
        if limit is None:
            return True, {"queries_used_today": 0,
                          "queries_limit_per_day": None}
        today = datetime.now(timezone.utc).date().isoformat()
        state = self._load_quota_state(today)
        used = state.get("queries", 0)
        if used >= limit:
            return False, {"queries_used_today": used,
                           "queries_limit_per_day": limit}
        used += 1
        self._save_quota_state({"date": today, "queries": used})
        return True, {"queries_used_today": used,
                      "queries_limit_per_day": limit}

    # -- data helpers ------------------------------------------------------
    def _watched(self) -> dict[str, dict]:
        return load_watched_fingerprints(self.fingerprints_file)

    def _rows(self) -> list[dict]:
        return load_result_rows(self.results_dir)

    def _refusal(self, tool: str, args: dict) -> dict:
        self.audit.emit(tool=tool, arg_keys=list(args.keys()),
                        outcome="error", session_id=self.session_id,
                        agent_id=self.agent_id)
        return {"error": "Refused: tools accept fingerprints only "
                         "(16 hex chars). Raw key values are never "
                         "accepted, stored, or logged."}

    def _check_args(self, tool: str, args: dict):
        """Return an error dict when any argument value looks like a raw
        key; otherwise None. Fingerprint-shaped values pass."""
        for value in args.values():
            if isinstance(value, str) and looks_like_raw_key(value):
                return self._refusal(tool, args)
        return None

    # -- tools -------------------------------------------------------------
    def tool_exposure_check(self, args: dict) -> dict:
        refusal = self._check_args("exposure_check", args)
        if refusal is not None:
            return refusal
        fp = args.get("fingerprint", "")
        if not is_valid_fingerprint(fp):
            self.audit.emit(tool="exposure_check", arg_keys=list(args.keys()),
                            outcome="error", session_id=self.session_id,
                            agent_id=self.agent_id)
            return {"error": "fingerprint must be 16 lowercase hex chars "
                             "(SHA-256 of the key, first 16)."}
        rows = [r for r in self._rows() if r["fingerprint"] == fp]
        self.audit.emit(tool="exposure_check", arg_keys=list(args.keys()),
                        outcome="success", session_id=self.session_id,
                        agent_id=self.agent_id)
        return {
            "fingerprint": fp,
            "matched": bool(rows),
            "live": bool(rows),  # present in the latest local scan results
            "sightings": [
                {"provider": r["provider"], "file": r["file"],
                 "line": r["line"],
                 **({"masked": r["masked"]} if r["masked"] else {})}
                for r in rows
            ],
        }

    def tool_fingerprint_check(self, args: dict) -> dict:
        refusal = self._check_args("fingerprint_check", args)
        if refusal is not None:
            return refusal
        fp = args.get("fingerprint", "")
        if not is_valid_fingerprint(fp):
            self.audit.emit(tool="fingerprint_check", arg_keys=list(args.keys()),
                            outcome="error", session_id=self.session_id,
                            agent_id=self.agent_id)
            return {"error": "fingerprint must be 16 lowercase hex chars "
                             "(SHA-256 of the key, first 16)."}
        watched = self._watched()
        entry = watched.get(fp)
        self.audit.emit(tool="fingerprint_check", arg_keys=list(args.keys()),
                        outcome="success", session_id=self.session_id,
                        agent_id=self.agent_id)
        return {
            "fingerprint": fp,
            "valid_format": True,
            "monitored": entry is not None,
            "provider": entry["provider"] if entry else "",
            "agent": entry["agent"] if entry else "",
        }

    def tool_posture_summary(self, args: dict) -> dict:
        refusal = self._check_args("posture_summary", args)
        if refusal is not None:
            return refusal
        watched = self._watched()
        rows = self._rows()
        by_provider: dict[str, int] = {}
        for r in rows:
            by_provider[r["provider"] or "(unknown)"] = \
                by_provider.get(r["provider"] or "(unknown)", 0) + 1
        open_matches = [r for r in rows if r["fingerprint"] in watched]
        self.audit.emit(tool="posture_summary", arg_keys=list(args.keys()),
                        outcome="success", session_id=self.session_id,
                        agent_id=self.agent_id)
        return {
            "monitored_fingerprints": len(watched),
            "total_findings_in_results": len(rows),
            "open_matches": len(open_matches),
            "by_provider": by_provider,
            "open_by_provider": {
                p: sum(1 for r in open_matches if (r["provider"] or "(unknown)") == p)
                for p in sorted({r["provider"] or "(unknown)" for r in open_matches})
            },
        }

    def call_tool(self, name: str, args: dict) -> dict:
        handlers = {
            "exposure_check": self.tool_exposure_check,
            "fingerprint_check": self.tool_fingerprint_check,
            "posture_summary": self.tool_posture_summary,
        }
        handler = handlers.get(name)
        if handler is None:
            self.audit.emit(tool=name, arg_keys=list(args.keys()),
                            outcome="error", session_id=self.session_id,
                            agent_id=self.agent_id)
            return {"error": f"unknown tool: {name}"}
        if not isinstance(args, dict):
            args = {}
        # Daily query quota (FREE-TIER-CAPS.md): 100/day on Free, the
        # 101st errors naming Maker. Every tool result carries the
        # usage metadata ("queries used today: N of 100").
        allowed, usage = self._quota_check()
        if not allowed:
            self.audit.emit(tool=name, arg_keys=list(args.keys()),
                            outcome="error", session_id=self.session_id,
                            agent_id=self.agent_id)
            return {"error": self._quota_message(
                        usage["queries_used_today"]),
                    "usage": usage}
        result = handler(args)
        if isinstance(result, dict):
            result["usage"] = usage
        return result


TOOLS = [
    {"name": "exposure_check",
     "description": "Check whether a fingerprint (16 hex chars, SHA-256 "
                    "first 16 of a key) appears in local KeySentry scan "
                    "results. Fingerprints only — raw keys are refused.",
     "inputSchema": {"type": "object",
                     "properties": {"fingerprint": {"type": "string"}},
                     "required": ["fingerprint"]}},
    {"name": "fingerprint_check",
     "description": "Validate a fingerprint's format and report whether "
                    "it is monitored locally (fingerprints.json). "
                    "Fingerprints only — raw keys are refused.",
     "inputSchema": {"type": "object",
                     "properties": {"fingerprint": {"type": "string"}},
                     "required": ["fingerprint"]}},
    {"name": "posture_summary",
     "description": "Counts from local fingerprints.json and the latest "
                    "scan results: totals, by provider, open matches.",
     "inputSchema": {"type": "object", "properties": {}}},
]


# ---------------------------------------------------------------------------
# JSON-RPC over stdio
# ---------------------------------------------------------------------------

def _result_response(req_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error_response(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def handle_request(server: KeySentryMCP, req: dict) -> dict | None:
    method = req.get("method", "")
    req_id = req.get("id")
    params = req.get("params") or {}
    if method == "initialize":
        client = params.get("clientInfo", {}) if isinstance(params, dict) else {}
        if isinstance(client, dict) and client.get("name"):
            server.agent_id = str(client["name"])
        return _result_response(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "keysentry", "version": "0.1.0"},
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return _result_response(req_id, {})
    if method == "tools/list":
        return _result_response(req_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name", "") if isinstance(params, dict) else ""
        args = params.get("arguments", {}) if isinstance(params, dict) else {}
        if not isinstance(args, dict):
            args = {}
        result = server.call_tool(name, args)
        if isinstance(result, dict) and "error" in result:
            # The whole result dict (error + usage metadata), not just
            # the error string — a quota denial's "queries used today:
            # N of 100" must survive into the response.
            return _result_response(req_id, {
                "content": [{"type": "text",
                             "text": json.dumps(result)}],
                "isError": True,
            })
        return _result_response(req_id, {
            "content": [{"type": "text", "text": json.dumps(result)}],
        })
    return _error_response(req_id, -32601, f"method not found: {method}")


def serve(server: KeySentryMCP) -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except ValueError:
            sys.stdout.write(json.dumps(
                _error_response(None, -32700, "parse error")) + "\n")
            sys.stdout.flush()
            continue
        if not isinstance(req, dict):
            continue
        try:
            resp = handle_request(server, req)
        except Exception as exc:  # never crash the stdio loop
            resp = _error_response(req.get("id"), -32603, f"internal error: {exc}")
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


# ---------------------------------------------------------------------------
# --selftest
# ---------------------------------------------------------------------------

def run_selftest() -> int:
    """Exercise all three tools against temp fixtures; print PASS/FAIL.
    Uses a TESTFAKE key only (never a real credential)."""
    import tempfile

    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              f"{' — ' + detail if detail and not ok else ''}")
        if not ok:
            failures.append(name)

    print("selftest: mcp_server (fingerprint-only, audit-chained)")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # Fixture key: TESTFAKE-marked, so it is never a real credential.
        fake_key = "TESTFAKE-gsk_" + "a1b2c3d4" * 5
        fp = hashlib.sha256(fake_key.encode()).hexdigest()[:16]
        masked = mask_value(fake_key)
        (tmp_path / "fingerprints.json").write_text(json.dumps({
            "fingerprints": [{"fingerprint": fp, "provider": "Groq",
                              "label": "selftest", "agent": "claude-code"}],
        }), encoding="utf-8")
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        (results_dir / "SELFTEST.json").write_text(json.dumps({
            "rows": [{"fingerprint": fp, "provider": "Groq",
                      "file": "github:acme/app/.mcp.json", "line": 3,
                      "masked": masked}],
        }), encoding="utf-8")
        server = KeySentryMCP(results_dir, tmp_path / "fingerprints.json",
                              tmp_path / "audit",
                              usage_file=tmp_path / "mcp-usage-main.json")

        # 1. exposure_check finds the fixture fingerprint, masked only.
        res = server.tool_exposure_check({"fingerprint": fp})
        check("exposure_check finds fixture fingerprint",
              res.get("matched") is True and res.get("live") is True)
        check("exposure_check returns masked form only",
              res.get("sightings", [{}])[0].get("masked") == masked
              and fake_key not in json.dumps(res))
        # 2. fingerprint_check reports monitored + agent tag.
        res = server.tool_fingerprint_check({"fingerprint": fp})
        check("fingerprint_check reports monitored",
              res.get("monitored") is True and res.get("agent") == "claude-code")
        res = server.tool_fingerprint_check({"fingerprint": "0" * 16})
        check("fingerprint_check reports unmonitored fingerprint",
              res.get("monitored") is False and res.get("valid_format") is True)
        # 3. posture_summary counts.
        res = server.tool_posture_summary({})
        check("posture_summary counts",
              res.get("monitored_fingerprints") == 1
              and res.get("total_findings_in_results") == 1
              and res.get("open_matches") == 1)
        # 4. Raw-key refusal: nothing of the value is returned or logged.
        raw = "sk-proj-" + "Qw7x9Z2m" * 6
        res = server.tool_exposure_check({"fingerprint": raw})
        check("raw key value is refused",
              "error" in res and "Refused" in res["error"])
        audit_text = (tmp_path / "audit" / "audit.jsonl").read_text(encoding="utf-8")
        check("refused value appears nowhere in the audit log",
              raw not in audit_text and "sk-proj" not in audit_text)
        check("audit log records arg keys only, never values",
              "fingerprint" in audit_text and fp not in audit_text)
        # 5. Hash chain recomputes for every written event.
        chain = verify_audit_chain(tmp_path / "audit" / "audit.jsonl")
        check("audit hash chain recomputes for all events",
              len(chain) >= 5 and all(chain), f"chain={chain}")
        # 6. Malformed fingerprint is an error, not a crash.
        res = server.tool_fingerprint_check({"fingerprint": "xyz"})
        check("malformed fingerprint is an error",
              "error" in res)
        # 7. Daily query quota (FREE-TIER-CAPS.md): 100/day on Free,
        # the 101st errors naming Maker; usage metadata counts 1..100.
        quota_server = KeySentryMCP(
            results_dir, tmp_path / "fingerprints.json",
            tmp_path / "audit", usage_file=tmp_path / "mcp-usage.json")
        quota_ok = True
        for i in range(100):
            r = quota_server.call_tool(
                "fingerprint_check", {"fingerprint": "0" * 16})
            if ("error" in r
                    or r.get("usage", {}).get("queries_used_today") != i + 1
                    or r.get("usage", {}).get("queries_limit_per_day") != 100):
                quota_ok = False
                break
        check("100 MCP queries allowed, usage metadata counts 1..100",
              quota_ok)
        r = quota_server.call_tool(
            "fingerprint_check", {"fingerprint": "0" * 16})
        check("101st MCP query errors naming Maker",
              "error" in r and "Maker" in r["error"]
              and "$19" in r["error"])
        check("101st MCP query says come back tomorrow",
              "error" in r and "come back tomorrow" in r["error"].lower())
        check("101st MCP query still carries usage metadata",
              r.get("usage", {}).get("queries_used_today") == 100
              and r.get("usage", {}).get("queries_limit_per_day") == 100)
        # Rollover: a state file dated yesterday resets the count.
        (tmp_path / "mcp-usage.json").write_text(json.dumps(
            {"date": "2026-01-01", "queries": 100}), encoding="utf-8")
        r = quota_server.call_tool(
            "fingerprint_check", {"fingerprint": "0" * 16})
        check("quota resets on a new UTC day",
              "error" not in r
              and r.get("usage", {}).get("queries_used_today") == 1)

    if failures:
        print(f"selftest: {len(failures)} failure(s).")
        return 1
    print("selftest: all checks passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp_server.py",
        description="KeySentry MCP server (read-only, fingerprint-only). "
                    "Speaks MCP over stdio JSON-RPC.")
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR),
                        help="scan-results dir (default ./results)")
    parser.add_argument("--fingerprints", default=str(DEFAULT_FINGERPRINTS_FILE),
                        help="fingerprints.json (default ./fingerprints.json)")
    parser.add_argument("--audit-dir",
                        default=os.environ.get("KEYSENTRY_AUDIT_DIR", "./audit"),
                        help="audit JSONL dir (default ./audit)")
    parser.add_argument("--usage-file",
                        default=os.environ.get(
                            "KEYSENTRY_MCP_USAGE_FILE", ""),
                        help="daily query-counter state file (default "
                             "./.key-sentry-mcp-usage.json); tests should "
                             "point it at a temp file so the repo-root "
                             "counter is not touched")
    parser.add_argument("--selftest", action="store_true",
                        help="exercise all three tools against fixtures "
                             "and verify the audit chain; then exit")
    args = parser.parse_args(argv)
    if args.selftest:
        return run_selftest()
    server = KeySentryMCP(Path(args.results_dir), Path(args.fingerprints),
                          Path(args.audit_dir),
                          usage_file=Path(args.usage_file)
                          if args.usage_file else None)
    return serve(server)


if __name__ == "__main__":
    raise SystemExit(main())
