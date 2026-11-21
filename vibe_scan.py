#!/usr/bin/env python3
"""vibe_scan.py — KeySentry Pillar 2: vibe-code security scanner (CLI).

Scans a local repo (or a public GitHub repo URL) for:

  (a) leaked AI API keys — the EXISTING engine/detectors (scan_line),
      reported with confidence scores;
  (b)-(f) OWASP-style vibe-app config flaws — vibe_checks.py.

Usage:
  python3 vibe_scan.py <repo-path-or-public-github-url>
  python3 vibe_scan.py ~/myapp --output myapp-vibe-report
  python3 vibe_scan.py https://github.com/owner/repo --format md

Output: <output>.json (masked-only) + <output>.md, plus one audit event
per finding appended to ./audit/audit.jsonl (hash-chained, Pillar 3
schema — see vibe_checks.build_audit_events).

Safety: reports are MASKED-ONLY (prefix4 + SHA-256 fingerprints).
A raw secret is never printed, written to a report, or put in an audit
event. Example/test keys are filtered by detectors.is_example_key —
that filter is never weakened.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import mask_value  # noqa: E402
from engine import scan_source  # noqa: E402
from sources import LocalSource  # noqa: E402
from sources.local import DEFAULT_SKIP_DIRS  # noqa: E402
from vibe_checks import SEVERITY_ORDER, build_audit_events, check_files

VERSION = "0.1.0"
DEFAULT_AUDIT_LOG = os.path.join("audit", "audit.jsonl")

SECRET_FIX_TEMPLATE = (
    "This secret key is visible in the code — anyone who sees the "
    "project can copy it and use it as you. Revoke it now at {console} "
    "and issue a new one, then take it out of the code (and out of git "
    "history) and store the new key in your hosting provider's secret "
    "settings instead."
)


# ---------------------------------------------------------------------------
# Repo acquisition
# ---------------------------------------------------------------------------

def is_github_url(target: str) -> bool:
    return target.startswith(("https://github.com/",
                              "http://github.com/", "git@github.com:"))


def fetch_github_repo(url: str, tmpdir: str) -> str:
    """Shallow-clone a public GitHub repo into tmpdir; fall back to the
    codeload tarball when git is unavailable. Returns the repo dir."""
    dest = os.path.join(tmpdir, "repo")
    git = shutil.which("git")
    if git:
        result = subprocess.run(
            [git, "clone", "--depth", "1", url, dest],
            capture_output=True, text=True, timeout=300)
        if result.returncode == 0 and os.path.isdir(dest):
            return dest
    # Fallback: codeload tarball of the default branch.
    parts = url.rstrip("/").replace(".git", "").split("github.com/")[-1]
    owner, repo = parts.split("/")[:2]
    tarball = (f"https://codeload.github.com/{owner}/{repo}/"
               "tar.gz/refs/heads/main")
    archive = os.path.join(tmpdir, "repo.tar.gz")
    try:
        urllib.request.urlretrieve(tarball, archive)
    except Exception as exc:
        raise RuntimeError(
            f"could not fetch {url}: git clone failed and the tarball "
            f"download failed ({exc})") from exc
    shutil.unpack_archive(archive, tmpdir)
    entries = [os.path.join(tmpdir, d) for d in os.listdir(tmpdir)
               if os.path.isdir(os.path.join(tmpdir, d))]
    if not entries:
        raise RuntimeError(f"could not unpack repo archive for {url}")
    return entries[0]


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def scan_repo(root: str, repo_label: str) -> dict:
    """Run secret + config scans over a local directory. Masked-only."""
    source = LocalSource(root)
    secret_findings = scan_source(source)
    files_scanned = source.stats.get("files_scanned", 0)

    # Second walk: full file texts for the vibe config checks.
    files: list = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in DEFAULT_SKIP_DIRS)
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root)
            if filename in ("package-lock.json", "yarn.lock",
                            "pnpm-lock.yaml", "Pipfile.lock",
                            "poetry.lock", "Cargo.lock", "Gemfile.lock",
                            "composer.lock"):
                continue
            try:
                if os.path.getsize(full) > 2_000_000:
                    continue
                with open(full, "rb") as f:
                    head = f.read(8192)
                    if b"\x00" in head:
                        continue
                    f.seek(0)
                    text = f.read().decode("utf-8", errors="replace")
            except OSError:
                continue
            files.append((rel, text))

    config_findings = check_files(files)

    findings: list = []
    for f in secret_findings:
        pub = f.public_dict()
        findings.append({
            "id": "vibe-leaked-secret",
            "title": f"Leaked {pub['provider']} {pub['credential_type']}",
            "severity": pub["severity"],
            "file": pub["file"],
            "line": pub["line"],
            "evidence": pub["snippet"],
            "fix": SECRET_FIX_TEMPLATE.format(
                console=pub["console_url"] or "the provider console"),
            "masked": pub["masked"],
            "fingerprint": pub["fingerprint_sha256_16"],
            "provider": pub["provider"],
            "confidence": pub["confidence"],
            "confidence_evidence": pub["confidence_evidence"],
        })
    for f in config_findings:
        findings.append({
            "id": f["id"],
            "title": f["title"],
            "severity": f["severity"],
            "file": f["file"],
            "line": f["line"],
            "evidence": f["evidence"],
            "fix": f["fix"],
            "masked": None,
            "fingerprint": None,
            "provider": None,
            "confidence": None,
            "confidence_evidence": [],
        })
    findings.sort(key=lambda d: (SEVERITY_ORDER.get(d["severity"], 3),
                                 d["file"], d["line"]))

    by_severity: dict = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    report_id = hashlib.sha256(
        (repo_label + "|" +
         datetime.now(timezone.utc).isoformat()).encode("utf-8")
    ).hexdigest()[:16]
    return {
        "tool": "vibe-scan",
        "version": VERSION,
        "report_id": report_id,
        "repo": repo_label,
        "scanned_at": datetime.now(timezone.utc).isoformat()
                       .replace("+00:00", "Z"),
        "files_scanned": files_scanned,
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Reporters (masked-only by construction: findings carry no raw values)
# ---------------------------------------------------------------------------

def render_markdown(report: dict) -> str:
    lines = [f"# Vibe-code security report — {report['repo']}",
             "",
             f"Scanned {report['scanned_at']} · "
             f"{report['files_scanned']} files · "
             f"{report['summary']['total']} findings",
             ""]
    by_sev = report["summary"]["by_severity"]
    for sev in ("critical", "high", "medium", "low"):
        if by_sev.get(sev):
            lines.append(f"- **{sev}**: {by_sev[sev]}")
    lines.append("")
    if not report["findings"]:
        lines.append("No issues found. 🎉")
        return "\n".join(lines) + "\n"
    lines.append("| Severity | Issue | Where | What to do |")
    lines.append("|---|---|---|---|")
    for f in report["findings"]:
        where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        masked = f" `{f['masked']}`" if f.get("masked") else ""
        lines.append(f"| {f['severity']} | {f['title']}{masked} | "
                     f"`{where}` | {f['fix']} |")
    lines.append("")
    lines.append("Masked values show only the first 4 characters; full "
                 "keys are never shown. Fingerprints are SHA-256 (first "
                 "16 hex chars).")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Audit log (append-only, hash-chained across runs)
# ---------------------------------------------------------------------------

def _last_audit_hash(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            last = None
            for line in f:
                line = line.strip()
                if line:
                    last = line
            if last:
                return json.loads(last).get("event_hash")
    except (OSError, json.JSONDecodeError):
        return None
    return None


def append_audit_events(report: dict, audit_log: str) -> list:
    prev = _last_audit_hash(audit_log)
    events = build_audit_events(report["findings"], report["repo"],
                                report["report_id"], prev_hash=prev)
    if not events:
        return events
    os.makedirs(os.path.dirname(audit_log) or ".", exist_ok=True)
    with open(audit_log, "a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, sort_keys=True) + "\n")
    return events


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="KeySentry vibe-code security scanner "
                    "(leaked keys + OWASP-style config checks).")
    parser.add_argument("target",
                        help="local repo path or public GitHub repo URL")
    parser.add_argument("--output", default="vibe-report",
                        help="report base path without extension "
                             "(default: vibe-report)")
    parser.add_argument("--format", choices=("json", "md", "both"),
                        default="both")
    parser.add_argument("--audit-log", default=DEFAULT_AUDIT_LOG,
                        help="audit JSONL path (default: ./audit/audit.jsonl)")
    parser.add_argument("--no-audit", action="store_true",
                        help="skip writing audit events")
    args = parser.parse_args(argv)

    target = args.target
    if is_github_url(target):
        tmpdir = tempfile.mkdtemp(prefix="vibe-scan-")
        try:
            root = fetch_github_repo(target, tmpdir)
            report = scan_repo(root, target)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    elif os.path.exists(target):
        report = scan_repo(os.path.abspath(target), target)
    else:
        print(f"error: no such path or GitHub URL: {target}",
              file=sys.stderr)
        return 2

    if args.format in ("json", "both"):
        json_path = args.output + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"wrote {json_path}")
    if args.format in ("md", "both"):
        md_path = args.output + ".md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(render_markdown(report))
        print(f"wrote {md_path}")

    if not args.no_audit:
        events = append_audit_events(report, args.audit_log)
        print(f"appended {len(events)} audit event(s) to {args.audit_log}")

    print(f"{report['summary']['total']} finding(s) in "
          f"{report['files_scanned']} file(s): "
          + ", ".join(f"{k}={v}" for k, v in
                      sorted(report["summary"]["by_severity"].items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
