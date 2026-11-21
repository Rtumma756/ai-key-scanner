#!/usr/bin/env python3
"""KeySentry audit-trail CLI (Pillar 3) — local use only.

    python3 audit.py log       < event.json   # append one redacted event
    python3 audit.py verify    [--log PATH]   # recompute the hash chain
    python3 audit.py timeline  [--agent ID] [--session ID] [--run ID]
    python3 audit.py detect    [--log PATH]   # run the five detectors
    python3 audit.py export --format soc2|iso27001|eu-ai-act|siem [--md]
    python3 audit.py retention [--apply] [--hot-days 30] [--warm-days 90]

Default log: ./audit/audit.jsonl (created on first append). Events are
redacted BEFORE write (argument values never stored, only key names)
and validated as a backstop; a rejected event is never appended and the
command exits non-zero. Denials are first-class events — log attempts,
not only successes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit import (  # noqa: E402
    append_event,
    read_events,
    redact_event,
    run_all_detections,
    verify_chain,
)
from audit.chain import DEFAULT_LOG_PATH  # noqa: E402
from audit.export import (  # noqa: E402
    apply_retention,
    eu_ai_act_report,
    iso27001_report,
    plan_retention,
    render_markdown,
    retention_windows,
    siem_export,
    soc2_report,
)


def _fail(message: str, code: int = 2) -> int:
    print(f"audit: error: {message}", file=sys.stderr)
    return code


def cmd_log(args: argparse.Namespace) -> int:
    try:
        raw = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        return _fail(f"stdin is not valid JSON: {e}")
    if not isinstance(raw, dict):
        return _fail("event must be a JSON object")
    try:
        redacted = redact_event(raw)
    except ValueError as e:
        return _fail(str(e))
    # append_event chains the event (sets prev_hash / event_hash) and
    # validates it as the backstop; a rejection appends nothing.
    try:
        stored = append_event(args.log, redacted)
    except ValueError as e:
        return _fail(str(e))
    print(json.dumps({
        "stored": True,
        "event_id": stored["event_id"],
        "event_hash": stored["event_hash"],
        "log": args.log,
    }))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    result = verify_chain(args.log)
    for item in result["events"]:
        status = "PASS" if item["ok"] else "FAIL"
        note = ""
        if item.get("continued"):
            note = " (continues from archive)"
        if item["error"]:
            note = f" — {item['error']}"
        print(f"[{item['index']:>4}] {status} {item['event_id']}{note}")
    if result["continued_from_archive"]:
        print("note: chain continues from an archived segment "
              "(first event is not genesis).")
    print(f"{result['count']} events, "
          f"{'chain intact' if result['ok'] else 'CHAIN BROKEN'}"
          + ("" if result["ok"] else
             f" — first bad index {result['first_bad_index']}"))
    return 0 if result["ok"] else 1


def cmd_timeline(args: argparse.Namespace) -> int:
    events = read_events(args.log)
    shown = 0
    for event in events:
        if args.agent and event.get("agent_id") != args.agent:
            continue
        if args.session and event.get("session_id") != args.session:
            continue
        if args.run and event.get("correlation_id") != args.run:
            continue
        decision = event.get("decision") or {}
        allow = "ALLOW" if decision.get("allow") else "DENY"
        print(
            f"{event.get('timestamp', '')} "
            f"agent={event.get('agent_id', '')} "
            f"{event.get('event_type', '')} "
            f"tool={event.get('tool', '')} "
            f"resource={event.get('resource', '')} "
            f"[{allow} {decision.get('policy', '')}] "
            f"outcome={event.get('outcome', '')} "
            f"run={event.get('correlation_id', '')}")
        shown += 1
    print(f"{shown} event(s) shown of {len(events)} in {args.log}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    events = read_events(args.log)
    alerts = run_all_detections(events)
    print(json.dumps({"event_count": len(events), "alerts": alerts},
                       indent=2))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    events = read_events(args.log)
    if args.format == "siem":
        text = siem_export(events)
    elif args.format == "soc2":
        report = soc2_report(events)
        text = render_markdown(report) if args.md else json.dumps(report, indent=2)
    elif args.format == "iso27001":
        report = iso27001_report(events)
        text = render_markdown(report) if args.md else json.dumps(report, indent=2)
    elif args.format == "eu-ai-act":
        report = eu_ai_act_report(events)
        text = render_markdown(report) if args.md else json.dumps(report, indent=2)
    else:
        return _fail(f"unknown format: {args.format}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {args.format} export ({len(events)} events) to {args.out}")
    else:
        print(text, end="" if text.endswith("\n") else "\n")
    return 0


def cmd_retention(args: argparse.Namespace) -> int:
    windows = retention_windows()
    hot_days = args.hot_days if args.hot_days is not None else windows["hot_days"]
    warm_days = args.warm_days if args.warm_days is not None else windows["warm_days"]
    if args.pilot:
        warm_days = windows["pilot_total_days"]
    events = read_events(args.log)
    plan = plan_retention(events, hot_days, warm_days)
    print(f"retention policy: hot {hot_days}d / warm {warm_days}d / "
          f"cold {windows['cold_years']}y"
          + (" (pilot: 90 days total)" if args.pilot else ""))
    print(f"hot: {len(plan['hot'])} events stay in {args.log}")
    print(f"warm: {len(plan['warm'])} events -> "
          f"{os.path.join(args.archive_dir, 'audit-warm.jsonl')}")
    print(f"cold: {len(plan['cold'])} events -> "
          f"{os.path.join(args.archive_dir, 'audit-cold.jsonl')}")
    if not args.apply:
        print("dry run — nothing moved (pass --apply to move events).")
        return 0
    result = apply_retention(args.log, args.archive_dir, hot_days, warm_days)
    print(f"applied: hot={result['hot']} warm={result['warm']} "
          f"cold={result['cold']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="audit.py",
        description="KeySentry agent audit trail (Pillar 3).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_log = sub.add_parser("log", help="append one event (JSON on stdin)")
    p_log.add_argument("--log", default=DEFAULT_LOG_PATH)
    p_log.set_defaults(func=cmd_log)

    p_verify = sub.add_parser("verify", help="recompute the hash chain")
    p_verify.add_argument("--log", default=DEFAULT_LOG_PATH)
    p_verify.set_defaults(func=cmd_verify)

    p_timeline = sub.add_parser("timeline", help="print events, filtered")
    p_timeline.add_argument("--log", default=DEFAULT_LOG_PATH)
    p_timeline.add_argument("--agent", default=None)
    p_timeline.add_argument("--session", default=None)
    p_timeline.add_argument("--run", default=None)
    p_timeline.set_defaults(func=cmd_timeline)

    p_detect = sub.add_parser("detect", help="run the five detectors")
    p_detect.add_argument("--log", default=DEFAULT_LOG_PATH)
    p_detect.set_defaults(func=cmd_detect)

    p_export = sub.add_parser("export", help="compliance / SIEM export")
    p_export.add_argument("--log", default=DEFAULT_LOG_PATH)
    p_export.add_argument("--format", required=True,
                          choices=["soc2", "iso27001", "eu-ai-act", "siem"])
    p_export.add_argument("--md", action="store_true",
                          help="render the report as Markdown")
    p_export.add_argument("--out", default=None)
    p_export.set_defaults(func=cmd_export)

    p_retention = sub.add_parser("retention", help="hot/warm/cold retention")
    p_retention.add_argument("--log", default=DEFAULT_LOG_PATH)
    p_retention.add_argument("--archive-dir", default=os.path.join("audit", "archive"))
    p_retention.add_argument("--apply", action="store_true")
    p_retention.add_argument("--hot-days", type=int, default=None)
    p_retention.add_argument("--warm-days", type=int, default=None)
    p_retention.add_argument("--pilot", action="store_true",
                             help="pilot policy: 90 days total retention")
    p_retention.set_defaults(func=cmd_retention)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
