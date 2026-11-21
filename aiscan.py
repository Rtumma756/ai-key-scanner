#!/usr/bin/env python3
"""aiscan — provider-agnostic AI API leaked-key scanner (prototype).

Two modes, one codebase:
  Business mode : scan local <path> [--git-history]   (your own code)
  Internet mode : scan internet --query <pattern>     (live GitHub code search)
                  scan internet --demo                (bundled FAKE dataset)
                  scan internet --preset mcp|notebook (filename/extension
                  search for MCP configs or notebooks)
  Trial sources : scan dockerhub | gists | npm | pypi | pastebin |
                  stackoverflow | commoncrawl

Metrics are collected for every scan (items/lines/bytes scanned,
candidates, findings after dedup, breakdowns by provider/type/severity,
API requests, rate-limit events) and printed as a scorecard by default
(--no-metrics to suppress). With --output, a metrics JSON file is
written alongside the report.

Safety rules baked in:
  - Findings are shown MASKED everywhere (first 4 chars ... rest hidden).
    The full key never appears in terminal, JSON or Markdown output.
  - Verification (--verify) is OFF by default and uses read-only probes
    only (model-list / balance endpoints). It must only run on keys the
    user owns or is authorized to test. It never generates text or
    spends credits.
  - Internet/trial sources never invent a query: the user supplies their
    own key fingerprint/prefix, org name, or a test pattern. No bulk
    sweeping. Trial sources find candidates only — no validation of keys
    the user does not own.

Free tiers only: every source runs on free public access. No paid API
keys, no paid plans. See sources/roadmap.md for what is deliberately
not implemented (FOFA/Shodan/Censys, Pastebin PRO search, CI logs).

Usage:
  python3 aiscan.py scan local tests/fixtures
  python3 aiscan.py scan local ~/myrepo --git-history --format md --output report.md
  python3 aiscan.py scan internet --demo
  GITHUB_TOKEN=... python3 aiscan.py scan internet --query "sk-or-v1-" --max-pages 1
  python3 aiscan.py scan internet --preset mcp
  python3 aiscan.py scan dockerhub --query openai --max-images 2
  python3 aiscan.py scan gists --max-gists 5
  python3 aiscan.py scan npm --query openai --max-packages 3
  python3 aiscan.py scan pypi --query openai --max-packages 3
  python3 aiscan.py scan pastebin --max-pastes 5
  python3 aiscan.py scan stackoverflow --query "OPENAI_API_KEY"
  python3 aiscan.py scan commoncrawl --url-pattern "example.com/*" --max-records 3
  python3 aiscan.py metrics            # fixture precision/recall scorecard
  python3 aiscan.py selftest [--live]

  Continuous scanning (see continuous.py; ledger: results/coverage_ledger.json):
  python3 aiscan.py continuous sweep [--demo] [--token ...]
  python3 aiscan.py continuous expand [--demo] [--count 5]
  python3 aiscan.py continuous coverage
  python3 aiscan.py continuous stress [--demo] [--minutes 120]
      [--max-iterations N]   # loop sweep+expand until the budget is spent

  Encrypted vault (admin-only unmask; see vault.py):
  python3 aiscan.py vault init                       # set admin passphrase
  python3 aiscan.py scan local ~/myrepo --vault      # store OWN findings
  python3 aiscan.py scan internet --demo --vault     # store DEMO (fake) findings
  python3 aiscan.py vault list                       # masked only
  python3 aiscan.py vault reveal vlt_abc123         # admin passphrase; audit-logged
  python3 aiscan.py vault audit                      # append-only audit log
  python3 aiscan.py vault rotate vlt_abc123          # mark rotated
  python3 aiscan.py vault purge                      # drop rotated/expired >30d
  Live internet findings are NEVER vaulted — they belong to other people.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import SEVERITY_RANK  # noqa: E402
from engine import scan_source  # noqa: E402
from metrics import RunMetrics, fixture_scorecard, render_fixture_scorecard  # noqa: E402
from reporters import json_out, markdown, table  # noqa: E402
from sources import (  # noqa: E402
    CommonCrawlError, CommonCrawlSource, DemoSource, DockerHubError,
    DockerHubSource, GistError, GistSource, GitHistorySource, GitHubError,
    GitHubSource, LocalSource, NpmError, NpmSource, PastebinError,
    PastebinSource, PypiError, PypiSource, StackOverflowError,
    StackOverflowSource,
)

VERIFY_WARNING = (
    "WARNING: --verify sends each detected key to its provider as a "
    "read-only probe (model-list / balance endpoint). Only verify keys you "
    "own or are authorized to test. It never generates text or spends credits."
)

# Preset GitHub code-search queries for high-yield leak surfaces.
PRESETS = {
    "mcp": 'filename:.mcp.json "sk-"',
    "notebook": 'extension:ipynb "sk-"',
}


def _metrics_path(args) -> str | None:
    """Where the metrics JSON goes: explicit flag, else alongside --output."""
    if getattr(args, "metrics_file", None):
        return args.metrics_file
    if getattr(args, "output", None):
        base, _ext = os.path.splitext(args.output)
        return base + ".metrics.json"
    return None


def _finish_metrics(metrics: RunMetrics, args) -> None:
    """Print the scorecard (unless --no-metrics) and write metrics JSON."""
    if getattr(args, "metrics", True):
        print(file=sys.stderr)
        print("--- Metrics ---", file=sys.stderr)
        print(metrics.render_scorecard(), file=sys.stderr)
    path = _metrics_path(args)
    if path and (getattr(args, "metrics_file", None)
                 or getattr(args, "metrics", True)):
        with open(path, "w", encoding="utf-8") as f:
            f.write(metrics.to_json())
        print(f"Wrote metrics JSON to {path}", file=sys.stderr)


def _emit(findings, mode: str, fmt: str, output: str | None,
          verified: bool, metrics=None, verified_fingerprints=None):
    if fmt == "json":
        text = json_out.render_json(findings, mode, verified, metrics,
                                    verified_fingerprints)
    elif fmt == "md":
        text = markdown.render_markdown(findings, mode, verified, metrics,
                                        verified_fingerprints)
    else:
        text = table.render_table(findings, mode, verified, metrics,
                                  verified_fingerprints)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote {fmt} report to {output}")
        if fmt != "table":
            print(f"Findings: {len(findings)} "
                  f"(see {output} for the full report)")
    else:
        print(text, end="")


def _add_mask_mode_arg(p) -> None:
    p.add_argument("--mask-mode", choices=["prefix4", "ends"],
                   default="prefix4",
                   help="How keys are masked in output (default prefix4: "
                        "first 4 chars shown, rest hidden. ends: first 5 "
                        "and last 3 hidden, middle shown — exposes most of "
                        "a key; use only for keys you own, never for "
                        "strangers' keys in shared reports)")


def _add_common_scan_args(p) -> None:
    p.add_argument("--verify", action="store_true",
                   help="Read-only verification probes (OFF by default; "
                        "only for keys you own/are authorized to test)")
    p.add_argument("--format", choices=["table", "json", "md"],
                   default="table")
    p.add_argument("--output", help="Write the report to this file")
    p.add_argument("--metrics", dest="metrics", action="store_true",
                   default=True, help="Print the metrics scorecard "
                   "(default: on)")
    p.add_argument("--no-metrics", dest="metrics", action="store_false",
                   help="Suppress the metrics scorecard")
    p.add_argument("--metrics-file",
                   help="Write metrics JSON to this file (default: "
                        "<output>.metrics.json when --output is given)")
    p.add_argument("--verified-fingerprints",
                   help="JSON file of owner-verified fingerprints (16-hex "
                        "SHA-256 prefixes, as printed in reports). Findings "
                        "matching it count as owner-verified in the savings "
                        "split. Use `aiscan.py verified add` to mark one. "
                        "See README 'Owner-verified savings'.")
    _add_mask_mode_arg(p)


def _load_verified(args) -> set:
    """Load the --verified-fingerprints file, if given (else empty set).

    A bad path or bad JSON fails the command (exit 2) rather than
    silently reporting $0 owner-verified savings.
    """
    path = getattr(args, "verified_fingerprints", None)
    if not path:
        return set()
    from savings import load_verified_fingerprints
    try:
        fps, skipped = load_verified_fingerprints(path)
    except (OSError, ValueError) as e:
        print(f"error: --verified-fingerprints: {e}", file=sys.stderr)
        raise SystemExit(2)
    if skipped:
        print(f"note: --verified-fingerprints: skipped {skipped} invalid "
              f"entr(ies) in {path} (want 16-hex-char fingerprints)",
              file=sys.stderr)
    return fps


def _vault_paths(args) -> tuple[str, str]:
    from vault import default_audit_path, default_vault_path
    return (getattr(args, "vault_file", None) or default_vault_path(),
            getattr(args, "audit_file", None) or default_audit_path())


def _store_in_vault(findings, source_label: str, args) -> int:
    """Store scan findings in the encrypted vault (scope-checked by the
    caller: only local scans and demo data reach this function)."""
    from vault import VaultError, get_passphrase, store_finding
    vault_path, audit_path = _vault_paths(args)
    try:
        passphrase = get_passphrase()
        stored = []
        for f in findings:
            stored.append(store_finding(vault_path, passphrase, f,
                                        source_label, audit_path=audit_path))
    except VaultError as e:
        print(f"error: vault: {e}", file=sys.stderr)
        return 1
    print(f"Stored {len(stored)} finding(s) in vault {vault_path} "
          f"(masked ids: {', '.join(e['id'] for e in stored) or 'none'})")
    print("Vault rule: full keys live ONLY in the vault, encrypted. "
          "Reports and terminal output stay masked.", file=sys.stderr)
    return 0


def _refuse_live_vault() -> int:
    print("error: refusing --vault for live internet findings: those keys "
          "belong to other people. The vault only stores keys from scans "
          "you own or are authorized to handle (scan local) or demo data "
          "(scan internet --demo).", file=sys.stderr)
    return 2


def cmd_vault_init(args) -> int:
    from vault import VaultError, get_passphrase, init_vault
    vault_path, audit_path = _vault_paths(args)
    try:
        passphrase = get_passphrase(confirm=True)
        init_vault(vault_path, passphrase, audit_path=audit_path)
    except VaultError as e:
        print(f"error: vault: {e}", file=sys.stderr)
        return 1
    print(f"Vault created at {vault_path}")
    print("Passphrase is NOT stored anywhere. Lose it and the vault "
          "cannot be opened — there is no recovery.")
    return 0


def cmd_vault_store(args) -> int:
    """Manually vault one key. The full key is read from stdin (piped) or
    an interactive no-echo prompt — never as a CLI argument (it would leak
    into shell history and process listings)."""
    import getpass as _getpass
    from common import Finding
    from vault import VaultError, get_passphrase, store_finding
    vault_path, audit_path = _vault_paths(args)
    if not sys.stdin.isatty():
        value = sys.stdin.read().strip()
    else:
        value = _getpass.getpass("Full key to vault (no echo): ").strip()
    if not value:
        print("error: vault: no key supplied.", file=sys.stderr)
        return 2
    finding = Finding(provider=args.provider, credential_type="API key",
                      value=value, file_path=args.file or "",
                      line_number=args.line or 0,
                      severity=args.severity, source=args.source or "manual")
    try:
        passphrase = get_passphrase()
        entry = store_finding(vault_path, passphrase, finding,
                              args.source or "manual", audit_path=audit_path)
    except VaultError as e:
        print(f"error: vault: {e}", file=sys.stderr)
        return 1
    print(f"Stored {entry['provider']} key {entry['masked']} as {entry['id']}")
    return 0


def cmd_vault_list(args) -> int:
    from vault import VaultError, list_entries
    vault_path, _audit = _vault_paths(args)
    try:
        entries = list_entries(vault_path)
    except VaultError as e:
        print(f"error: vault: {e}", file=sys.stderr)
        return 1
    if not entries:
        print("Vault is empty.")
        return 0
    print(f"{'ID':16} {'PROVIDER':16} {'MASKED':24} {'STATUS':9} "
          f"{'SOURCE':28} STORED")
    for e in entries:
        print(f"{e['id']:16} {e['provider'][:16]:16} {e['masked']:24} "
              f"{e['status']:9} {e['source'][:28]:28} {e['stored_at_utc'][:19]}")
    print(f"\n{len(entries)} entr(ies). Full keys are never shown here — "
          "use `vault reveal <id>` as admin.")
    return 0


def cmd_vault_reveal(args) -> int:
    from vault import VaultError, get_passphrase, reveal_entry
    vault_path, audit_path = _vault_paths(args)
    try:
        passphrase = get_passphrase()
        _meta, value = reveal_entry(vault_path, passphrase, args.entry_id,
                                    audit_path=audit_path)
    except VaultError as e:
        print(f"error: vault: {e}", file=sys.stderr)
        return 1
    # The ONE place a full key is ever printed. Do not pipe this to a file.
    print(value)
    print("Reveal audit-logged. Rotate this key now if it was ever exposed.",
          file=sys.stderr)
    return 0


def cmd_vault_audit(args) -> int:
    import json as _json
    from vault import read_audit
    _vault, audit_path = _vault_paths(args)
    entries = read_audit(audit_path)
    if not entries:
        print("Audit log is empty.")
        return 0
    for e in entries:
        print(f"{e['ts_utc'][:19]}  {e['action']:8}  "
              f"{e.get('entry_id') or '-':16}  "
              f"{e.get('fingerprint_sha256_16') or '-':18}  "
              f"{e.get('detail', '')}")
    print(f"\n{len(entries)} audit entr(ies). Full keys are never in this log.")
    return 0


def cmd_vault_rotate(args) -> int:
    from vault import VaultError, set_entry_status
    vault_path, audit_path = _vault_paths(args)
    try:
        entry = set_entry_status(vault_path, args.entry_id, "rotated",
                                 audit_path=audit_path)
    except VaultError as e:
        print(f"error: vault: {e}", file=sys.stderr)
        return 1
    print(f"Marked {entry['id']} ({entry['masked']}) as rotated. "
          "Purge it with `vault purge` once the rotation is confirmed.")
    return 0


def cmd_vault_expire(args) -> int:
    from vault import VaultError, set_entry_status
    vault_path, audit_path = _vault_paths(args)
    try:
        entry = set_entry_status(vault_path, args.entry_id, "expired",
                                 audit_path=audit_path)
    except VaultError as e:
        print(f"error: vault: {e}", file=sys.stderr)
        return 1
    print(f"Marked {entry['id']} ({entry['masked']}) as expired.")
    return 0


def cmd_vault_purge(args) -> int:
    from vault import VaultError, purge_entries
    vault_path, audit_path = _vault_paths(args)
    try:
        purged = purge_entries(vault_path, days=args.days,
                               audit_path=audit_path)
    except VaultError as e:
        print(f"error: vault: {e}", file=sys.stderr)
        return 1
    print(f"Purged {len(purged)} rotated/expired entr(ies) older than "
          f"{args.days} day(s): {', '.join(purged) or 'none'}.")
    return 0


# --- Owner-verified fingerprints -------------------------------------------
# The file holds ONLY 16-hex-char SHA-256 fingerprint prefixes (the same
# value printed in every report). A fingerprint reveals nothing about the
# key itself, so the file is safe to keep, copy and version-control.
# Mark a fingerprint verified ONLY for a key you own and have confirmed
# live — provider console, or an authorized read-only --verify probe on
# your own assets. Never mark strangers' keys verified.

def _verified_file(args) -> str:
    from savings import default_verified_path
    return getattr(args, "file", None) or default_verified_path()


def _read_verified_file(path: str) -> set:
    from savings import load_verified_fingerprints
    if not os.path.exists(path):
        return set()
    fps, _skipped = load_verified_fingerprints(path)
    return fps


def _write_verified_file(path: str, fps: set) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sorted(fps), f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def cmd_verified_add(args) -> int:
    from savings import is_fingerprint
    fp = args.fingerprint.lower()
    if not is_fingerprint(fp):
        print("error: fingerprint must be 16 hex characters (the SHA-256 "
              "prefix shown in reports, e.g. 54329e534487d1bd)",
              file=sys.stderr)
        return 2
    path = _verified_file(args)
    fps = _read_verified_file(path)
    if fp in fps:
        print(f"already verified: {fp}")
        return 0
    fps.add(fp)
    _write_verified_file(path, fps)
    print(f"marked verified: {fp} (stored in {path})")
    print("Only mark fingerprints for keys YOU own and have confirmed "
          "live — provider console, or an authorized read-only --verify "
          "probe on your own assets. Never mark strangers' keys verified.")
    return 0


def cmd_verified_list(args) -> int:
    path = _verified_file(args)
    fps = _read_verified_file(path)
    if not fps:
        print(f"no verified fingerprints in {path}")
        return 0
    print(f"verified fingerprints ({len(fps)}) in {path}:")
    for fp in sorted(fps):
        print(f"  {fp}")
    return 0


def cmd_verified_remove(args) -> int:
    from savings import is_fingerprint
    fp = args.fingerprint.lower()
    if not is_fingerprint(fp):
        print("error: fingerprint must be 16 hex characters",
              file=sys.stderr)
        return 2
    path = _verified_file(args)
    fps = _read_verified_file(path)
    if fp not in fps:
        print(f"not verified: {fp}")
        return 0
    fps.discard(fp)
    _write_verified_file(path, fps)
    print(f"removed from verified: {fp}")
    return 0


def cmd_scan_local(args) -> int:
    if not os.path.exists(args.path):
        print(f"error: path does not exist: {args.path}", file=sys.stderr)
        return 2
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    metrics = RunMetrics(f"local:{args.path}")
    vf = _load_verified(args)
    sources = [LocalSource(args.path, respect_gitignore=not args.no_ignore,
                           include_lockfiles=args.include_lockfiles)]
    if args.git_history:
        sources.append(GitHistorySource(args.path,
                                        max_commits=args.max_commits))
    all_findings = []
    for src in sources:
        try:
            all_findings.extend(scan_source(src, verify=args.verify,
                                            metrics=metrics))
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    # Cross-source dedup (a key in the tree and in history is one finding).
    seen, unique = set(), []
    for f in all_findings:
        if f.fingerprint in seen:
            metrics.add_duplicates(1)
            continue
        seen.add(f.fingerprint)
        unique.append(f)
    unique.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file_path,
                               f.line_number))
    metrics.finalize(unique, vf)
    report_metrics = metrics if args.metrics else None
    _emit(unique, f"local:{args.path}", args.format, args.output,
          args.verify, report_metrics, vf)
    _finish_metrics(metrics, args)
    if getattr(args, "vault", False) and unique:
        return _store_in_vault(unique, f"local:{args.path}", args)
    return 0


def cmd_scan_internet(args) -> int:
    if args.demo:
        print("DEMO MODE: bundled FAKE dataset — no real credentials, "
              "no network calls.", file=sys.stderr)
        metrics = RunMetrics("internet:demo")
        vf = _load_verified(args)
        findings = scan_source(DemoSource(), verify=False, metrics=metrics)
        metrics.finalize(findings, vf)
        report_metrics = metrics if args.metrics else None
        _emit(findings, "internet:demo", args.format, args.output, False,
              report_metrics, vf)
        _finish_metrics(metrics, args)
        if getattr(args, "vault", False) and findings:
            return _store_in_vault(findings, "internet:demo", args)
        return 0
    if getattr(args, "vault", False):
        return _refuse_live_vault()
    query = args.query
    if not query and args.preset:
        query = PRESETS.get(args.preset)
        print(f"Preset '{args.preset}': using GitHub query {query!r}",
              file=sys.stderr)
    if not query:
        print("error: internet mode needs --query <pattern>, --preset "
              "mcp|notebook, or --demo.", file=sys.stderr)
        print("Supply your own key fingerprint/prefix, org name, or a test "
              "pattern. aiscan never invents a query.", file=sys.stderr)
        return 2
    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("error: GitHub code search needs a token. Set GITHUB_TOKEN "
              "or pass --token.", file=sys.stderr)
        return 2
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    metrics = RunMetrics(f"internet:github:{query}")
    vf = _load_verified(args)
    try:
        src = GitHubSource(query, token, max_pages=args.max_pages,
                           max_items=args.max_items)
        findings = scan_source(src, verify=args.verify, metrics=metrics)
    except GitHubError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if getattr(src, "rate_limit_hits", 0):
        print(f"note: hit GitHub rate limits {src.rate_limit_hits} time(s); "
              "backed off and continued.", file=sys.stderr)
    metrics.finalize(findings, vf)
    report_metrics = metrics if args.metrics else None
    _emit(findings, f"internet:github:{query}", args.format,
          args.output, args.verify, report_metrics, vf)
    _finish_metrics(metrics, args)
    return 0


def cmd_scan_dockerhub(args) -> int:
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    metrics = RunMetrics(f"dockerhub:{args.query}")
    vf = _load_verified(args)
    src = DockerHubSource(args.query, max_images=args.max_images)
    try:
        findings = scan_source(src, verify=args.verify, metrics=metrics)
    except DockerHubError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    metrics.errors.extend(src.skipped_reasons)
    metrics.finalize(findings, vf)
    report_metrics = metrics if args.metrics else None
    _emit(findings, f"dockerhub:{args.query}", args.format, args.output,
          args.verify, report_metrics, vf)
    _finish_metrics(metrics, args)
    return 0


def cmd_scan_gists(args) -> int:
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    token = args.token or os.environ.get("GITHUB_TOKEN")
    metrics = RunMetrics("gists:public")
    vf = _load_verified(args)
    src = GistSource(token, max_gists=args.max_gists,
                     max_pages=args.max_pages)
    try:
        findings = scan_source(src, verify=args.verify, metrics=metrics)
    except GistError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    metrics.finalize(findings, vf)
    report_metrics = metrics if args.metrics else None
    _emit(findings, "gists:public", args.format, args.output, args.verify,
          report_metrics, vf)
    _finish_metrics(metrics, args)
    return 0


def cmd_scan_npm(args) -> int:
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    metrics = RunMetrics(f"npm:{args.query}")
    vf = _load_verified(args)
    src = NpmSource(args.query, max_packages=args.max_packages)
    try:
        findings = scan_source(src, verify=args.verify, metrics=metrics)
    except NpmError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    metrics.errors.extend(src.skipped_reasons)
    metrics.finalize(findings, vf)
    report_metrics = metrics if args.metrics else None
    _emit(findings, f"npm:{args.query}", args.format, args.output,
          args.verify, report_metrics, vf)
    _finish_metrics(metrics, args)
    return 0


def cmd_scan_pypi(args) -> int:
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    metrics = RunMetrics(f"pypi:{args.query}")
    vf = _load_verified(args)
    src = PypiSource(args.query, max_packages=args.max_packages)
    try:
        findings = scan_source(src, verify=args.verify, metrics=metrics)
    except PypiError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    metrics.errors.extend(src.skipped_reasons)
    metrics.finalize(findings, vf)
    report_metrics = metrics if args.metrics else None
    _emit(findings, f"pypi:{args.query}", args.format, args.output,
          args.verify, report_metrics, vf)
    _finish_metrics(metrics, args)
    return 0


def cmd_scan_pastebin(args) -> int:
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    metrics = RunMetrics("pastebin:archive")
    vf = _load_verified(args)
    src = PastebinSource(max_pastes=args.max_pastes)
    try:
        findings = scan_source(src, verify=args.verify, metrics=metrics)
    except PastebinError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if src.limited:
        metrics.errors.append(
            "Pastebin rate limit hit — run stopped early (free tier).")
    metrics.finalize(findings, vf)
    report_metrics = metrics if args.metrics else None
    _emit(findings, "pastebin:archive", args.format, args.output,
          args.verify, report_metrics, vf)
    _finish_metrics(metrics, args)
    return 0


def cmd_scan_stackoverflow(args) -> int:
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    metrics = RunMetrics(f"stackoverflow:{args.query}")
    vf = _load_verified(args)
    src = StackOverflowSource(args.query, max_questions=args.max_questions)
    try:
        findings = scan_source(src, verify=args.verify, metrics=metrics)
    except StackOverflowError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    metrics.finalize(findings, vf)
    report_metrics = metrics if args.metrics else None
    _emit(findings, f"stackoverflow:{args.query}", args.format,
          args.output, args.verify, report_metrics, vf)
    _finish_metrics(metrics, args)
    return 0


def cmd_scan_commoncrawl(args) -> int:
    if args.verify:
        print(VERIFY_WARNING, file=sys.stderr)
    metrics = RunMetrics(f"commoncrawl:{args.url_pattern}")
    vf = _load_verified(args)
    src = CommonCrawlSource(args.url_pattern, max_records=args.max_records)
    try:
        findings = scan_source(src, verify=args.verify, metrics=metrics)
    except CommonCrawlError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    metrics.finalize(findings, vf)
    report_metrics = metrics if args.metrics else None
    _emit(findings, f"commoncrawl:{args.url_pattern}", args.format,
          args.output, args.verify, report_metrics, vf)
    _finish_metrics(metrics, args)
    return 0


def cmd_metrics(args) -> int:
    """Fixture precision/recall scorecard (reuses selftest expectations).

    Scans the fixtures in detection mode (allow_examples=True): the
    scorecard measures whether the detectors still match the planted
    values. With the example-key filter on, the same fixtures report
    0 findings by design (see selftest.fixture_scorecard).
    """
    from sources import LocalSource
    metrics = RunMetrics("metrics:fixtures")
    findings = scan_source(LocalSource("tests/fixtures"),
                           allow_examples=True, metrics=metrics)
    metrics.finalize(findings)
    score = fixture_scorecard(findings)
    print(render_fixture_scorecard(score))
    print()
    print("--- Metrics ---")
    print(metrics.render_scorecard())
    ok = score["recall"] == 1.0 and score["precision"] == 1.0 \
        and score["decoy_hits"] == 0
    return 0 if ok else 1


def cmd_selftest(args) -> int:
    from selftest import run_selftest
    return run_selftest(live=args.live)


def cmd_continuous_sweep(args) -> int:
    import continuous
    return continuous.cmd_sweep(args)


def cmd_continuous_expand(args) -> int:
    import continuous
    return continuous.cmd_expand(args)


def cmd_continuous_coverage(args) -> int:
    import continuous
    return continuous.cmd_coverage(args)


def cmd_continuous_stress(args) -> int:
    import continuous
    return continuous.cmd_stress(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aiscan",
        description="Provider-agnostic AI API leaked-key scanner. "
                    "Business mode scans your own code; internet and trial "
                    "modes scan public sources. Findings are always masked. "
                    "Free tiers only — no paid services.",
        epilog="Verification (--verify) is read-only and must only run on "
               "keys you own or are authorized to test.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a scan")
    scan_sub = scan.add_subparsers(dest="scan_mode", required=True)

    local = scan_sub.add_parser("local", help="Business mode: scan a directory tree")
    local.add_argument("path", help="Directory (or file) to scan")
    local.add_argument("--git-history", action="store_true",
                       help="Also scan git log -p history")
    local.add_argument("--max-commits", type=int, default=500,
                       help="Max commits to scan in history (default 500)")
    local.add_argument("--no-ignore", action="store_true",
                       help="Do not respect .gitignore")
    local.add_argument("--include-lockfiles", action="store_true",
                       help="Also scan lockfiles (skipped by default)")
    local.add_argument("--vault", action="store_true",
                       help="Store findings in the encrypted vault (your "
                            "own code only — see `vault` commands)")
    _add_common_scan_args(local)
    local.set_defaults(func=cmd_scan_local)

    inet = scan_sub.add_parser("internet", help="Internet mode: live GitHub code search")
    inet.add_argument("--query", help="Search pattern (your own key "
                      "fingerprint/prefix, org name, or test pattern)")
    inet.add_argument("--preset", choices=["mcp", "notebook"],
                      help="Preset query: mcp = filename:.mcp.json, "
                           "notebook = .ipynb files with key patterns")
    inet.add_argument("--demo", action="store_true",
                      help="Run against the bundled FAKE dataset (no token, "
                           "no network)")
    inet.add_argument("--token", help="GitHub token (or env GITHUB_TOKEN)")
    inet.add_argument("--max-pages", type=int, default=1,
                      help="GitHub result pages to fetch (default 1)")
    inet.add_argument("--max-items", type=int, default=150,
                      help="Max code-search results to process (default 150)")
    inet.add_argument("--vault", action="store_true",
                      help="Store findings in the encrypted vault — ONLY "
                           "with --demo (fake data). Refused for live "
                           "internet findings (other people's keys).")
    _add_common_scan_args(inet)
    inet.set_defaults(func=cmd_scan_internet)

    dh = scan_sub.add_parser("dockerhub", help="Trial source: public Docker Hub images")
    dh.add_argument("--query", required=True,
                    help="Image search term (e.g. openai, langchain)")
    dh.add_argument("--max-images", type=int, default=5,
                    help="Max images to pull and scan (default 5)")
    _add_common_scan_args(dh)
    dh.set_defaults(func=cmd_scan_dockerhub)

    gi = scan_sub.add_parser("gists", help="Trial source: recent public GitHub gists")
    gi.add_argument("--max-gists", type=int, default=10,
                    help="Max gists to fetch (default 10)")
    gi.add_argument("--max-pages", type=int, default=1,
                    help="Gist list pages to fetch (default 1)")
    gi.add_argument("--token", help="GitHub token (or env GITHUB_TOKEN; "
                    "optional — raises the 60/hr anonymous limit)")
    _add_common_scan_args(gi)
    gi.set_defaults(func=cmd_scan_gists)

    npm = scan_sub.add_parser("npm", help="Trial source: public npm package tarballs")
    npm.add_argument("--query", required=True,
                     help="Package search term (e.g. openai)")
    npm.add_argument("--max-packages", type=int, default=5,
                     help="Max packages to download and scan (default 5)")
    _add_common_scan_args(npm)
    npm.set_defaults(func=cmd_scan_npm)

    pypi = scan_sub.add_parser("pypi", help="Trial source: public PyPI distributions")
    pypi.add_argument("--query", required=True,
                      help="Package search term (e.g. openai)")
    pypi.add_argument("--max-packages", type=int, default=5,
                      help="Max packages to download and scan (default 5)")
    _add_common_scan_args(pypi)
    pypi.set_defaults(func=cmd_scan_pypi)

    pb = scan_sub.add_parser("pastebin", help="Trial source: recent public Pastebin pastes")
    pb.add_argument("--max-pastes", type=int, default=5,
                    help="Max pastes to fetch from the public archive "
                         "(default 5; free tier has no search API)")
    _add_common_scan_args(pb)
    pb.set_defaults(func=cmd_scan_pastebin)

    so = scan_sub.add_parser("stackoverflow", help="Trial source: Stack Overflow questions")
    so.add_argument("--query", required=True,
                    help="Question search term (e.g. OPENAI_API_KEY)")
    so.add_argument("--max-questions", type=int, default=10,
                    help="Max questions to fetch (default 10)")
    _add_common_scan_args(so)
    so.set_defaults(func=cmd_scan_stackoverflow)

    cc = scan_sub.add_parser("commoncrawl", help="Trial source: Common Crawl archive sample")
    cc.add_argument("--url-pattern", required=True,
                    help="URL pattern for the index, wildcards allowed "
                         "(e.g. example.com/*)")
    cc.add_argument("--max-records", type=int, default=3,
                    help="Max WARC records to fetch (default 3; keep tiny)")
    _add_common_scan_args(cc)
    cc.set_defaults(func=cmd_scan_commoncrawl)

    mt = sub.add_parser("metrics", help="Fixture precision/recall scorecard")
    mt.set_defaults(func=cmd_metrics)

    vault_p = sub.add_parser("vault", help="Encrypted vault (admin-only unmask)")
    vault_p.add_argument("--vault-file",
                         help="Vault file (default ~/.aiscan/vault.json)")
    vault_p.add_argument("--audit-file",
                         help="Audit log (default ~/.aiscan/vault-audit.jsonl)")
    vsub = vault_p.add_subparsers(dest="vault_cmd", required=True)

    vi = vsub.add_parser("init", help="Create the vault (set passphrase)")
    vi.set_defaults(func=cmd_vault_init)

    vs = vsub.add_parser("store", help="Vault one key (read from stdin "
                         "or a no-echo prompt — never as an argument)")
    vs.add_argument("--provider", required=True, help="Provider name")
    vs.add_argument("--file", default="", help="Where the key was found")
    vs.add_argument("--line", type=int, default=0)
    vs.add_argument("--severity", default="high",
                    choices=["critical", "high", "medium", "low"])
    vs.add_argument("--source", default="manual",
                    help="Scan/source label for the entry")
    vs.set_defaults(func=cmd_vault_store)

    vl = vsub.add_parser("list", help="List vaulted entries (masked only)")
    vl.set_defaults(func=cmd_vault_list)

    vr = vsub.add_parser("reveal", help="Show one full key (admin; "
                         "audit-logged)")
    vr.add_argument("entry_id", help="Entry id, e.g. vlt_abc123def456")
    vr.set_defaults(func=cmd_vault_reveal)

    va = vsub.add_parser("audit", help="Show the append-only audit log")
    va.set_defaults(func=cmd_vault_audit)

    vro = vsub.add_parser("rotate", help="Mark an entry rotated")
    vro.add_argument("entry_id")
    vro.set_defaults(func=cmd_vault_rotate)

    ve = vsub.add_parser("expire", help="Mark an entry expired")
    ve.add_argument("entry_id")
    ve.set_defaults(func=cmd_vault_expire)

    vp = vsub.add_parser("purge", help="Delete rotated/expired entries "
                         "older than N days")
    vp.add_argument("--days", type=int, default=30)
    vp.set_defaults(func=cmd_vault_purge)

    ver_p = sub.add_parser("verified", help="Mark keys owner-verified "
                           "(by fingerprint) for the savings split")
    ver_p.add_argument("--file",
                       help="Verified-fingerprints file (default "
                            "~/.aiscan/verified-fingerprints.json)")
    ver_sub = ver_p.add_subparsers(dest="verified_cmd", required=True)

    va_add = ver_sub.add_parser("add", help="Mark a fingerprint verified "
                                "(own key, confirmed live only)")
    va_add.add_argument("fingerprint", help="16-hex-char SHA-256 prefix "
                        "from a report, e.g. 54329e534487d1bd")
    va_add.add_argument("--file",
                        help="Verified-fingerprints file (default "
                             "~/.aiscan/verified-fingerprints.json)")
    va_add.set_defaults(func=cmd_verified_add)

    va_list = ver_sub.add_parser("list", help="List verified fingerprints")
    va_list.add_argument("--file",
                         help="Verified-fingerprints file (default "
                              "~/.aiscan/verified-fingerprints.json)")
    va_list.set_defaults(func=cmd_verified_list)

    va_rm = ver_sub.add_parser("remove", help="Unmark a fingerprint")
    va_rm.add_argument("fingerprint")
    va_rm.add_argument("--file",
                       help="Verified-fingerprints file (default "
                            "~/.aiscan/verified-fingerprints.json)")
    va_rm.set_defaults(func=cmd_verified_remove)

    st = sub.add_parser("selftest", help="Precision/recall scorecard on fixtures")
    st.add_argument("--live", action="store_true",
                    help="Also run the live GitHub smoke test (needs "
                         "GITHUB_TOKEN; skipped without one)")
    st.set_defaults(func=cmd_selftest)

    cont = sub.add_parser("continuous", help="Continuous scanning: "
                          "re-sweep known areas for NEW detections and "
                          "expand query coverage (ledger: "
                          "results/coverage_ledger.json)")
    cont_sub = cont.add_subparsers(dest="continuous_cmd", required=True)

    csw = cont_sub.add_parser("sweep", help="Re-sweep the seed queries; "
                              "alert only on NEW or ROTATED detections")
    csw.add_argument("--token", help="GitHub token (or env GITHUB_TOKEN)")
    csw.add_argument("--demo", action="store_true",
                     help="Offline test: sweep the bundled FAKE dataset "
                          "(no token, no network)")
    csw.add_argument("--ledger", help="Ledger file (default "
                     "results/coverage_ledger.json)")
    _add_mask_mode_arg(csw)
    csw.set_defaults(func=cmd_continuous_sweep)

    cex = cont_sub.add_parser("expand", help="Run the next unrun queries; "
                              "shard anything over GitHub's 1,000-result cap")
    cex.add_argument("--count", type=int, default=5,
                     help="Queries to run (default 5)")
    cex.add_argument("--token", help="GitHub token (or env GITHUB_TOKEN)")
    cex.add_argument("--demo", action="store_true",
                     help="Offline test: expand over the bundled FAKE "
                          "dataset (no token, no network)")
    cex.add_argument("--ledger", help="Ledger file (default "
                     "results/coverage_ledger.json)")
    _add_mask_mode_arg(cex)
    cex.set_defaults(func=cmd_continuous_expand)

    ccov = cont_sub.add_parser("coverage", help="Print the coverage ledger "
                               "table with totals")
    ccov.add_argument("--ledger", help="Ledger file (default "
                      "results/coverage_ledger.json)")
    ccov.set_defaults(func=cmd_continuous_coverage)

    cst = cont_sub.add_parser("stress", help="Loop sweep + expand until "
                              "the wall-clock budget is spent (default "
                              "120 minutes); one JSON line per iteration "
                              "in results/stress_log.jsonl")
    cst.add_argument("--minutes", type=float, default=120,
                     help="Wall-clock budget in minutes (default 120)")
    cst.add_argument("--max-iterations", type=int, default=None,
                     help="Stop after N iterations (overrides the time "
                           "budget; used by the selftest)")
    cst.add_argument("--expand-count", type=int, default=5,
                     help="Queries per expand step (default 5)")
    cst.add_argument("--token", help="GitHub token (or env GITHUB_TOKEN)")
    cst.add_argument("--demo", action="store_true",
                     help="Offline test: stress over the bundled FAKE "
                          "dataset (no token, no network)")
    cst.add_argument("--ledger", help="Ledger file (default "
                     "results/coverage_ledger.json)")
    cst.add_argument("--log", help="Stress log file (default "
                     "results/stress_log.jsonl)")
    _add_mask_mode_arg(cst)
    cst.set_defaults(func=cmd_continuous_stress)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "mask_mode", None):
        import common
        common.set_mask_mode(args.mask_mode)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
