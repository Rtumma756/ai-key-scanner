#!/usr/bin/env python3
"""fingerprint_watch.py — KeySentry fingerprint monitoring (CLI side).

Watches SHA-256 fingerprints (first 16 hex chars) of keys you own, so a
leaked key that resurfaces in a later scan is caught even after rotation.

HARD RULES (same as the web app):
  * Only fingerprints and prefix4-masked values are ever stored, logged,
    or transmitted. A raw key is read ONLY from stdin for `hash`, is never
    written anywhere, and never leaves the process.
  * Never call any provider API with a found key. Never unmask or
    ends-mask strangers' keys.

Subcommands:
  hash    Read ONE key from stdin (never argv), print its fingerprint
          (sha256, first 16 hex) and masked form, exit. Nothing is stored.
  pull    Fetch the fingerprint watch list from the web API and save ONLY
          the hashes to a local file (default fingerprints.json).
          Base URL from KEYSENTRY_URL (default
          https://key-sentry-inky.vercel.app).
  check   Load a scan-results JSON (same shape as
          results/CLASSIFY_FRESH_41.json), match each finding's fingerprint
          against the pulled list, print matches, and POST new matches to
          /api/matches. POST body carries fingerprint + provider + repo /
          file / line only — never raw or masked key material.
          Admin passphrase from KEYSENTRY_ADMIN_PASS.
  assign  Assign a match to a team member (POST /api/matches/assign).
          Assignee is a free-text name, max 100 chars; --clear removes
          the assignment. Admin passphrase from KEYSENTRY_ADMIN_PASS
          or --admin-pass.
  posture Fetch the per-repo posture report (GET /api/posture, counts
          only, no passphrase needed) and print it as a table.
          --export csv|json writes it to a file as well.
  selftest
          Sanity checks: known hash vector, matching logic (a present
          fingerprint matches, an absent one does not), and agreement with
          common.py value_hash()/mask_value() when importable.

Env vars (presence checked, values never printed):
  KEYSENTRY_URL        Web app base URL (default the live Vercel URL).
  KEYSENTRY_BASE_URL   Same as KEYSENTRY_URL; checked first by the
                       `assign`/`posture` subcommands (either works).
  KEYSENTRY_ADMIN_PASS Admin passphrase for POST /api/matches (same
                       VAULT_ADMIN_PASS as the web app).
  KEYSENTRY_ALERT_WEBHOOK is server-side only; this script never uses it.

Requires: Python 3.10+, stdlib only (urllib). No aiscan.py changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_BASE_URL = "https://key-sentry-inky.vercel.app"
DEFAULT_FINGERPRINTS_FILE = "fingerprints.json"

# Known test vector: sha256("TESTFAKE-gsk_example_key_12345")[:16].
TEST_KEY = "TESTFAKE-gsk_example_key_12345"
TEST_KEY_FINGERPRINT = "06fabb99a6b4976b"
TEST_KEY_MASKED = "TEST..."


def fingerprint(value: str) -> str:
    """First 16 hex chars of the SHA-256 of the key.

    Must match the web app (sha256Hex(value).slice(0,16)) and the CLI
    (common.value_hash(value)[:16])."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def mask_value(value: str) -> str:
    """Prefix4 masking, the default everywhere: first 4 chars + '...'."""
    return f"{value[:4]}..."


def _is_fingerprint(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 16
        and all(c in "0123456789abcdef" for c in value.lower())
    )


def split_repo_file(raw_file: str) -> tuple[str, str]:
    """Split a scan location like 'github:owner/repo/path/file.py' into
    (repo, file). Anything else is returned as ('', raw_file)."""
    if raw_file.startswith("github:"):
        rest = raw_file[len("github:"):]
        parts = rest.split("/", 2)
        if len(parts) == 3:
            return f"{parts[0]}/{parts[1]}", parts[2]
    return "", raw_file


def extract_rows(results: object) -> list[dict]:
    """Rows from a scan-results JSON: either a top-level list, or a dict
    with a 'rows' list (CLASSIFY_*.json shape)."""
    if isinstance(results, list):
        return [r for r in results if isinstance(r, dict)]
    if isinstance(results, dict):
        rows = results.get("rows")
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
    return []


def row_fingerprint(row: dict) -> str:
    """Fingerprint field, accepting both spellings used by CLI outputs:
    'fingerprint_sha256_16' (Finding.public_dict) and 'fingerprint'
    (CLASSIFY_*.json rows)."""
    for key in ("fingerprint_sha256_16", "fingerprint"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value.strip().lower()
    return ""


def find_matches(rows: list[dict], watched: set[str]) -> list[dict]:
    """Match rows against the watched fingerprint set. Returns one dict
    per matching row with fingerprint/provider/repo/file/line only —
    no key material of any kind."""
    matches = []
    for row in rows:
        fp = row_fingerprint(row)
        if fp and fp in watched:
            repo, file = split_repo_file(str(row.get("file", "") or ""))
            line = row.get("line")
            matches.append(
                {
                    "fingerprint": fp,
                    "provider": str(row.get("provider", "") or ""),
                    "repo": repo,
                    "file": file,
                    "line": int(line) if isinstance(line, int) else 0,
                }
            )
    return matches


def _http_json(url: str, payload: dict | None = None, timeout: int = 15) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


MAX_ASSIGNEE_LENGTH = 100


def base_url() -> str:
    """Web app base URL. KEYSENTRY_BASE_URL wins, KEYSENTRY_URL is the
    legacy name (both are accepted); default is the live Vercel app."""
    return (
        os.environ.get("KEYSENTRY_BASE_URL")
        or os.environ.get("KEYSENTRY_URL")
        or DEFAULT_BASE_URL
    ).rstrip("/")


def admin_pass_from(args: argparse.Namespace) -> str:
    """Admin passphrase: --admin-pass flag wins, then env. Never stored."""
    return getattr(args, "admin_pass", "") or os.environ.get(
        "KEYSENTRY_ADMIN_PASS", ""
    )


def normalize_assignee(value: str) -> str:
    """Trim a team-member name. Raises ValueError when it exceeds the
    server-side 100-char limit (same rule as assignMatch)."""
    trimmed = value.strip()
    if len(trimmed) > MAX_ASSIGNEE_LENGTH:
        raise ValueError(
            f"assignee must be at most {MAX_ASSIGNEE_LENGTH} characters "
            f"(got {len(trimmed)})."
        )
    return trimmed


def format_posture_table(posture: dict) -> str:
    """Render a posture payload (GET /api/posture) as a plain-text table."""
    repos = posture.get("repos") or []
    summary = posture.get("summary") or {}
    lines = []
    header = (f"{'repo':<32} {'total':>5} {'open':>5} {'resolv':>6} "
              f"{'<7d':>4} {'7-30d':>5} {'>30d':>5}  oldest open")
    lines.append(header)
    lines.append("-" * len(header))
    for repo in repos:
        age = repo.get("openByAge") or {}
        oldest = repo.get("oldestOpen") or "-"
        if oldest != "-":
            oldest = oldest[:10]  # date only
        lines.append(
            f"{str(repo.get('repo', ''))[:32]:<32} "
            f"{int(repo.get('total', 0)):>5} "
            f"{int(repo.get('open', 0)):>5} "
            f"{int(repo.get('resolved', 0)):>6} "
            f"{int(age.get('lt7d', 0)):>4} "
            f"{int(age.get('d7to30', 0)):>5} "
            f"{int(age.get('gt30d', 0)):>5}  {oldest}"
        )
        providers = repo.get("byProvider") or {}
        if providers:
            detail = ", ".join(
                f"{p}: {n}" for p, n in sorted(providers.items())
            )
            lines.append(f"{'':<32} by provider: {detail}")
    lines.append("-" * len(header))
    total = int(summary.get("totalMatches", 0) or 0)
    open_n = int(summary.get("openMatches", 0) or 0)
    rate = float(summary.get("openRate", 0) or 0) * 100
    lines.append(
        f"total {total} matches across "
        f"{int(summary.get('repoCount', 0) or 0)} repo(s); "
        f"{open_n} open ({rate:.0f}% open rate); "
        f"{int(summary.get('resolvedMatches', 0) or 0)} resolved."
    )
    return "\n".join(lines)


def _csv_cell(value: object) -> str:
    text = str(value)
    if any(c in text for c in (",", '"', "\n", "\r")):
        return '"' + text.replace('"', '""') + '"'
    return text


def posture_to_csv(posture: dict) -> str:
    """Per-repo posture rows as CSV (one row per repo)."""
    header = ["repo", "total", "open", "resolved", "open_lt7d",
              "open_7to30d", "open_gt30d", "oldest_open", "by_provider"]
    lines = [",".join(header)]
    for repo in posture.get("repos") or []:
        age = repo.get("openByAge") or {}
        providers = repo.get("byProvider") or {}
        detail = "; ".join(
            f"{p}: {n}" for p, n in sorted(providers.items())
        )
        lines.append(",".join(_csv_cell(v) for v in [
            repo.get("repo", ""),
            repo.get("total", 0),
            repo.get("open", 0),
            repo.get("resolved", 0),
            age.get("lt7d", 0),
            age.get("d7to30", 0),
            age.get("gt30d", 0),
            repo.get("oldestOpen") or "",
            detail,
        ]))
    return "\n".join(lines) + "\n"


def cmd_assign(args: argparse.Namespace) -> int:
    if args.clear:
        assignee = ""
    elif args.assignee is None:
        print("assign: give a team-member name, or --clear to unassign.",
              file=sys.stderr)
        return 2
    else:
        assignee = args.assignee
    try:
        assignee = normalize_assignee(assignee)
    except ValueError as exc:
        print(f"assign: {exc}", file=sys.stderr)
        return 2
    admin_pass = admin_pass_from(args)
    if not admin_pass:
        print("assign: KEYSENTRY_ADMIN_PASS is not set "
              "(or pass --admin-pass).", file=sys.stderr)
        return 2
    url = f"{base_url()}/api/matches/assign"
    try:
        resp = _http_json(url, {"id": args.id, "assignee": assignee,
                                "adminPass": admin_pass})
    except urllib.error.HTTPError as exc:
        print(f"assign: server answered HTTP {exc.code} for {url}.",
              file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"assign: could not reach {url}: {exc}", file=sys.stderr)
        return 1
    match = resp.get("match") or {}
    who = match.get("assignee") or "(unassigned)"
    print(f"assign: match {match.get('id')} in "
          f"{match.get('repo') or match.get('file') or '?'} "
          f"({match.get('status')}) -> {who}")
    history = resp.get("history") or []
    if history:
        print(f"  history: {len(history)} entr{'y' if len(history) == 1 else 'ies'}")
        last = history[-1]
        print(f"  latest: {last.get('oldStatus')} -> {last.get('newStatus')} "
              f"by {last.get('changedBy')}"
              + (f" — {last.get('note')}" if last.get("note") else ""))
    return 0


def cmd_posture(args: argparse.Namespace) -> int:
    url = f"{base_url()}/api/posture"
    try:
        posture = _http_json(url)
    except urllib.error.HTTPError as exc:
        print(f"posture: server answered HTTP {exc.code} for {url}. "
              "Is the app deployed and the DB configured?", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"posture: could not reach {url}: {exc}", file=sys.stderr)
        return 1
    print(format_posture_table(posture))
    if args.export:
        fmt = args.export
        out = args.out or f"keysentry-posture.{fmt}"
        try:
            with open(out, "w", encoding="utf-8") as fh:
                if fmt == "csv":
                    fh.write(posture_to_csv(posture))
                else:
                    json.dump(posture, fh, indent=2)
                    fh.write("\n")
        except OSError as exc:
            print(f"posture: could not write {out}: {exc}", file=sys.stderr)
            return 1
        print(f"posture: exported {fmt} to {out}")
    return 0


def cmd_hash(_args: argparse.Namespace) -> int:
    """Read ONE key from stdin, print fingerprint + masked form, exit."""
    raw = sys.stdin.read()
    value = raw.strip()
    if not value:
        print("hash: no key on stdin (pipe one key, e.g. echo -n '<key>' | ...).",
              file=sys.stderr)
        return 2
    if "\n" in value or "\r" in value:
        print("hash: stdin must contain exactly one key (one line).",
              file=sys.stderr)
        return 2
    # The raw value is used only in-memory for the two derived outputs.
    print(f"fingerprint: {fingerprint(value)}")
    print(f"masked: {mask_value(value)}")
    print("nothing stored.")
    return 0


def cmd_pull(args: argparse.Namespace) -> int:
    base = (os.environ.get("KEYSENTRY_URL") or DEFAULT_BASE_URL).rstrip("/")
    url = f"{base}/api/fingerprints"
    try:
        data = _http_json(url)
    except urllib.error.HTTPError as exc:
        print(f"pull: server answered HTTP {exc.code} for {url}. "
              "Is the app deployed and the DB configured?", file=sys.stderr)
        return 1
    except Exception as exc:  # network down, DNS, timeout, bad JSON
        print(f"pull: could not reach {url}: {exc}", file=sys.stderr)
        return 1
    entries = data.get("fingerprints") or []
    # Keep ONLY hashes (plus provider/label metadata the API returns).
    # Never write a raw or masked key here — the API sends none.
    out = {
        "source": base,
        "pulled_at_utc": datetime.now(timezone.utc).isoformat(),
        "fingerprints": [
            {
                "fingerprint": str(e.get("fingerprint", "")),
                "provider": str(e.get("provider", "") or ""),
                "label": str(e.get("label", "") or ""),
            }
            for e in entries
            if _is_fingerprint(str(e.get("fingerprint", "")))
        ],
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print(f"pull: saved {len(out['fingerprints'])} fingerprint(s) to {args.out} "
          f"(hashes only).")
    return 0


def _load_watched(path: str) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    watched = set()
    if isinstance(data, dict):
        entries = data.get("fingerprints") or []
    elif isinstance(data, list):
        entries = data
    else:
        entries = []
    for entry in entries:
        fp = entry.get("fingerprint") if isinstance(entry, dict) else entry
        if isinstance(fp, str) and _is_fingerprint(fp):
            watched.add(fp.lower())
    return watched


def cmd_check(args: argparse.Namespace) -> int:
    try:
        watched = _load_watched(args.fingerprints)
    except FileNotFoundError:
        print(f"check: fingerprints file not found: {args.fingerprints}. "
              "Run `pull` first.", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"check: could not read {args.fingerprints}: {exc}",
              file=sys.stderr)
        return 2
    try:
        with open(args.results, encoding="utf-8") as fh:
            results = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"check: could not read {args.results}: {exc}", file=sys.stderr)
        return 2

    rows = extract_rows(results)
    matches = find_matches(rows, watched)
    print(f"check: {len(rows)} finding(s) scanned, {len(watched)} "
          f"watched fingerprint(s), {len(matches)} match(es).")
    if not matches:
        return 0

    base = (os.environ.get("KEYSENTRY_URL") or DEFAULT_BASE_URL).rstrip("/")
    admin_pass = os.environ.get("KEYSENTRY_ADMIN_PASS") or ""
    posted_new = 0
    posted_known = 0
    post_failed = 0
    for match in matches:
        where = match["repo"] or match["file"]
        line = f":{match['line']}" if match["line"] else ""
        print(f"  MATCH {match['fingerprint']} ({match['provider']}) "
              f"in {where}{line}")
        if args.dry_run:
            continue
        if not admin_pass:
            print("    (not posted: KEYSENTRY_ADMIN_PASS is not set)",
                  file=sys.stderr)
            post_failed += 1
            continue
        try:
            resp = _http_json(
                f"{base}/api/matches",
                {**match, "adminPass": admin_pass},
            )
            if resp.get("isNew"):
                posted_new += 1
                print(f"    -> recorded as NEW match"
                      f"{' (alert sent)' if resp.get('alerted') else ''}")
            else:
                posted_known += 1
                print("    -> already recorded (last_seen refreshed)")
        except urllib.error.HTTPError as exc:
            post_failed += 1
            print(f"    -> POST failed: HTTP {exc.code}", file=sys.stderr)
        except Exception as exc:
            post_failed += 1
            print(f"    -> POST failed: {exc}", file=sys.stderr)

    if args.dry_run:
        print("check: dry run — nothing posted.")
    elif post_failed:
        print(f"check: {posted_new} new, {posted_known} already known, "
              f"{post_failed} not posted (see above).")
        return 1
    else:
        print(f"check: {posted_new} new match(es) recorded, "
              f"{posted_known} already known.")
    return 0


def cmd_selftest(_args: argparse.Namespace) -> int:
    failures = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              f"{' — ' + detail if detail and not ok else ''}")
        if not ok:
            failures.append(name)

    print("selftest: fingerprint_watch")
    # 1. Known hash vector (hardcoded expected value).
    check("hash vector TESTFAKE key",
          fingerprint(TEST_KEY) == TEST_KEY_FINGERPRINT,
          f"got {fingerprint(TEST_KEY)}, want {TEST_KEY_FINGERPRINT}")
    check("mask vector TESTFAKE key",
          mask_value(TEST_KEY) == TEST_KEY_MASKED,
          f"got {mask_value(TEST_KEY)}, want {TEST_KEY_MASKED}")
    # 2. Agreement with common.py when it is importable.
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import common  # noqa: PLC0415  (local CLI module, same dir)

        check("agrees with common.value_hash()[:16]",
              fingerprint(TEST_KEY) == common.value_hash(TEST_KEY)[:16])
        check("agrees with common.mask_value()",
              mask_value(TEST_KEY) == common.mask_value(TEST_KEY))
    except ImportError:
        print("  [SKIP] common.py not importable — agreement check skipped")

    # 3. Matching logic: present fingerprint matches, absent one does not.
    watched = {TEST_KEY_FINGERPRINT, "deadbeefdeadbeef"}
    rows = [
            {"fingerprint_sha256_16": TEST_KEY_FINGERPRINT,
             "provider": "Groq", "file": "github:acme/app/.env", "line": 7},
            {"fingerprint": "0123456789abcdef",
             "provider": "OpenAI", "file": "x.py", "line": 1},
            {"provider": "Anthropic", "file": "y.py", "line": 2},  # no fp
        ]
    matches = find_matches(rows, watched)
    check("present fingerprint is reported",
          len(matches) == 1 and matches[0]["fingerprint"] == TEST_KEY_FINGERPRINT,
          f"got {len(matches)} match(es)")
    check("absent fingerprint is not reported",
          all(m["fingerprint"] != "0123456789abcdef" for m in matches))
    check("row without fingerprint is skipped",
          all(m["fingerprint"] for m in matches))
    check("repo/file split for github: locations",
          matches and matches[0]["repo"] == "acme/app"
          and matches[0]["file"] == ".env",
          f"got {matches[0] if matches else None}")
    # 4. No key material survives in a match record.
    check("match record carries no key material",
          matches and set(matches[0].keys()) == {
              "fingerprint", "provider", "repo", "file", "line"})

    if failures:
        print(f"selftest: {len(failures)} failure(s).")
        return 1
    print("selftest: all checks passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fingerprint_watch.py",
        description="KeySentry fingerprint monitoring: watch SHA-256 "
                    "fingerprints of keys you own and catch them if they "
                    "resurface in a scan. Only hashes are stored or sent.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_hash = sub.add_parser("hash", help="print fingerprint + masked form "
                            "of one key read from stdin; stores nothing")
    p_hash.set_defaults(func=cmd_hash)

    p_pull = sub.add_parser("pull", help="fetch the watched fingerprint "
                            "list from the web API into a local file "
                            "(hashes only)")
    p_pull.add_argument("--out", default=DEFAULT_FINGERPRINTS_FILE,
                        help=f"output file (default {DEFAULT_FINGERPRINTS_FILE})")
    p_pull.set_defaults(func=cmd_pull)

    p_check = sub.add_parser("check", help="match a scan-results JSON "
                             "against the pulled fingerprints and POST new "
                             "matches to /api/matches")
    p_check.add_argument("results", help="scan-results JSON file "
                         "(e.g. results/CLASSIFY_FRESH_41.json)")
    p_check.add_argument("--fingerprints", default=DEFAULT_FINGERPRINTS_FILE,
                         help=f"pulled fingerprints file "
                              f"(default {DEFAULT_FINGERPRINTS_FILE})")
    p_check.add_argument("--dry-run", action="store_true",
                         help="print matches without POSTing them")
    p_check.set_defaults(func=cmd_check)

    p_self = sub.add_parser("selftest", help="sanity checks: hash vector, "
                            "matching logic, agreement with common.py")
    p_self.set_defaults(func=cmd_selftest)

    p_assign = sub.add_parser("assign", help="assign a match to a team "
                              "member (free-text name, max 100 chars) or "
                              "clear it with --clear; admin only")
    p_assign.add_argument("id", type=int, help="match id (from /api/matches)")
    p_assign.add_argument("assignee", nargs="?", default=None,
                          help="team-member name (omit with --clear)")
    p_assign.add_argument("--clear", action="store_true",
                          help="clear the assignment instead of setting one")
    p_assign.add_argument("--admin-pass", default="",
                          help="admin passphrase (else KEYSENTRY_ADMIN_PASS)")
    p_assign.set_defaults(func=cmd_assign)

    p_posture = sub.add_parser("posture", help="per-repo remediation "
                               "posture from GET /api/posture (counts only)")
    p_posture.add_argument("--export", choices=["csv", "json"],
                           help="also write the report to a file")
    p_posture.add_argument("--out", default="",
                           help="export path (default keysentry-posture.<fmt>)")
    p_posture.set_defaults(func=cmd_posture)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
