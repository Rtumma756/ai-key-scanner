#!/usr/bin/env python3
"""repos.py — connect a GitHub org/user's repositories and scan them with
the existing aiscan detector engine (business / repo-connection mode).

What this is
------------
Given a GitHub personal access token (PAT) supplied ONLY via the
``GITHUB_TOKEN`` environment variable — never stored, never printed, never
written to any file — this script:

1. lists repositories for an org (``--org``) or a user (``--user``), or
   targets specific repositories (``--repo owner/name``, repeatable),
   paginated via api.github.com;
2. fetches each repo's default-branch file listing (git trees API);
3. fetches raw file contents (contents API, ``Accept: ...raw``) and runs
   the EXISTING detector engine (``engine.scan_source`` /
   ``detectors.scan_line``) over them — detection is NOT reimplemented
   here;
4. emits findings as masked-only JSON in the same shape as aiscan's
   other reports (``reporters.json_out.render_json``: provider, masked,
   fingerprint_sha256_16, file, line, severity, detected_via — never a
   raw value).

``--dry-run`` lists the repositories that WOULD be scanned and stops
before fetching any file contents.

Security rules (same as the rest of aiscan)
-------------------------------------------
- The token comes from the environment only. It is never printed, logged,
  or included in any output, error message, or file. A 401 is reported as
  "GitHub rejected the token (401)" with no token material.
- Only repositories the token can access are listed/scanned. This scans
  the repos the USER connects — their own org / their own account — not
  strangers' code. (Bulk internet sweeping is a different mode and lives
  in ``sources/github.py``.)
- Findings output is masked-only by construction (``Finding.public_dict``
  via ``render_json``, which also asserts no full secret is present).

GitHub App path (future — NOT attempted here)
---------------------------------------------
For production use this PAT flow should be replaced by a GitHub App:
server-to-server auth (short-lived installation tokens), per-repo
install, no long-lived PAT sitting in a shell, and webhook-driven scans
on push. Creating a GitHub App requires the user's GitHub account in a
browser (App settings -> Developer settings -> New GitHub App, then
install it on the org/repos) — that step needs the user/browser and is
recorded as a BLOCKER, not attempted by this script.

Usage
-----
  GITHUB_TOKEN=<token> python3 repos.py --org my-org --dry-run
  GITHUB_TOKEN=<token> python3 repos.py --org my-org --max-files 100
  GITHUB_TOKEN=<token> python3 repos.py --repo octo/hello-world --repo octo/other
  GITHUB_TOKEN=<token> python3 repos.py --user someuser --output results/REPO_SCAN.json

  # A fine-grained PAT with read-only access to the repos (Contents: Read,
  # Metadata: Read) is enough. Classic PATs need at least `repo` (private
  # repos) or `public_repo` (public repos) scope.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import scan_source  # noqa: E402
from reporters.json_out import render_json  # noqa: E402
from sources.base import Source  # noqa: E402

API_BASE = "https://api.github.com"
USER_AGENT = "aiscan-repos/0.1"
API_VERSION = "2022-11-28"
DEFAULT_MAX_FILES = 100
DEFAULT_PER_PAGE = 100

# Extensions that are never source/config text — skip before fetching.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ogg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".class", ".jar", ".war",
    ".db", ".sqlite", ".sqlite3",
    ".lock",  # lockfiles are huge and rarely hold keys; skip by default
}
MAX_FILE_BYTES = 500_000  # skip files larger than this (contents API `size`)


class RepoError(RuntimeError):
    """Any GitHub API / repo-connection failure. Never carries the token."""


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable without network)
# ---------------------------------------------------------------------------

def parse_repos_response(data) -> list:
    """Parse a GitHub list-repos API response into plain repo records.

    Input: the decoded JSON list from ``/orgs/{org}/repos``,
    ``/users/{user}/repos``, ``/user/repos`` or a single-repo ``GET
    /repos/{owner}/{repo}`` (a dict is accepted and wrapped in a list).
    Output: one dict per repo with only the fields this tool needs —
    full_name, default_branch, private, fork, archived, html_url.
    Malformed entries (not a dict, no full_name) are skipped, never fatal.
    """
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise RepoError("unexpected GitHub API response: expected a JSON list")
    repos = []
    for item in data:
        if not isinstance(item, dict):
            continue
        full_name = item.get("full_name")
        if not full_name:
            continue
        repos.append({
            "full_name": full_name,
            "default_branch": item.get("default_branch") or "main",
            "private": bool(item.get("private", False)),
            "fork": bool(item.get("fork", False)),
            "archived": bool(item.get("archived", False)),
            "html_url": item.get("html_url", ""),
        })
    return repos


def select_repos_for_scan(repos: list) -> list:
    """Repos worth scanning: archived repos are skipped (frozen code)."""
    return [r for r in repos if not r.get("archived")]


def is_scannable_path(path: str, size: int | None = None) -> bool:
    """True for text-ish files small enough to fetch and scan."""
    if size is not None and size > MAX_FILE_BYTES:
        return False
    _, ext = os.path.splitext(path.lower())
    if ext in BINARY_EXTENSIONS:
        return False
    return True


def parse_tree_response(data) -> list:
    """Parse a git-trees API response (recursive=1) into scannable paths.

    Returns [{path, size}] for blobs only, in tree order. The trees API
    does not reliably include `size`, so a missing size means "unknown",
    not "large" — the contents fetch re-checks size before scanning.
    """
    if not isinstance(data, dict) or not isinstance(data.get("tree"), list):
        raise RepoError("unexpected GitHub API response: expected a tree object")
    out = []
    for entry in data["tree"]:
        if not isinstance(entry, dict) or entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if not path:
            continue
        size = entry.get("size")
        if not is_scannable_path(path, size if isinstance(size, int) else None):
            continue
        out.append({"path": path, "size": size})
    return out


# ---------------------------------------------------------------------------
# GitHub API client (token via env only; token never appears in errors)
# ---------------------------------------------------------------------------

class GitHubClient:
    """Minimal api.github.com client. The token is held in memory only."""

    def __init__(self, token: str):
        if not token:
            raise RepoError(
                "GITHUB_TOKEN is not set. Supply a GitHub PAT via the "
                "environment only, e.g.:\n"
                "  GITHUB_TOKEN=<token> python3 repos.py --org my-org --dry-run\n"
                "The token is never stored or printed.")
        self._token = token
        self.api_requests = 0

    def _headers(self, accept: str = "application/vnd.github+json") -> dict:
        return {
            "Accept": accept,
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }

    def _get(self, url: str, accept: str = "application/vnd.github+json"):
        """One GET. Returns decoded JSON (or raw bytes for `...raw`)."""
        req = urllib.request.Request(url, headers=self._headers(accept))
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
                if accept == "application/vnd.github.raw":
                    return resp.status, body
                return resp.status, json.loads(body.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            # Read the body for the message but NEVER include auth material.
            detail = e.read().decode("utf-8", errors="replace")[:200]
            if e.code == 401:
                raise RepoError(
                    "GitHub rejected the token (401). Check GITHUB_TOKEN — "
                    "it must be a valid personal access token with access "
                    "to these repositories.") from None
            if e.code == 403:
                raise RepoError(
                    f"GitHub refused the request (403): {detail}. This is "
                    "usually a rate limit or a missing permission on the "
                    "token.") from None
            if e.code == 404:
                raise RepoError(
                    f"GitHub resource not found (404): {url.split('?', 1)[0]}. "
                    "Check the org/user/repo name and that the token can "
                    "see it.") from None
            if e.code == 429:
                raise RepoError(
                    f"GitHub rate limit (429): {detail}. Wait and retry.") from None
            raise RepoError(f"GitHub API error HTTP {e.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            raise RepoError(f"Network error reaching api.github.com: {e}") from None

    def list_repos(self, org: str | None, user: str | None,
                   per_page: int = DEFAULT_PER_PAGE) -> list:
        """Paginated repo listing for an org, a user, or the authed user."""
        if org:
            base = f"{API_BASE}/orgs/{urllib.parse.quote(org)}/repos"
        elif user:
            base = f"{API_BASE}/users/{urllib.parse.quote(user)}/repos"
        else:
            base = f"{API_BASE}/user/repos"
        repos, page = [], 1
        while True:
            params = urllib.parse.urlencode(
                {"per_page": per_page, "page": page, "type": "all"})
            _, data = self._get(f"{base}?{params}")
            batch = parse_repos_response(data)
            if not batch:
                break
            repos.extend(batch)
            if len(batch) < per_page:
                break
            page += 1
            time.sleep(0.2)  # be polite between pages
        return repos

    def get_repo(self, full_name: str) -> dict:
        """Single-repo lookup (validates a --repo name, gets its branch)."""
        owner, _, name = full_name.partition("/")
        if not owner or not name:
            raise RepoError(
                f"--repo wants 'owner/name', got {full_name!r}.")
        _, data = self._get(
            f"{API_BASE}/repos/{urllib.parse.quote(owner)}/"
            f"{urllib.parse.quote(name)}")
        parsed = parse_repos_response(data)
        if not parsed:
            raise RepoError(f"GitHub returned no repo for {full_name!r}.")
        return parsed[0]

    def list_files(self, full_name: str, branch: str) -> list:
        """Default-branch file listing via the recursive git-trees API."""
        owner, _, name = full_name.partition("/")
        url = (
            f"{API_BASE}/repos/{urllib.parse.quote(owner)}/"
            f"{urllib.parse.quote(name)}/git/trees/"
            f"{urllib.parse.quote(branch)}?recursive=1")
        _, data = self._get(url)
        return parse_tree_response(data)

    def fetch_file_raw(self, full_name: str, path: str, branch: str) -> bytes:
        """Raw contents of one file (contents API, Accept: ...raw)."""
        owner, _, name = full_name.partition("/")
        url = (
            f"{API_BASE}/repos/{urllib.parse.quote(owner)}/"
            f"{urllib.parse.quote(name)}/contents/"
            + urllib.parse.quote(path)
            + f"?ref={urllib.parse.quote(branch)}")
        _, body = self._get(url, accept="application/vnd.github.raw")
        return body


# ---------------------------------------------------------------------------
# Scanning: reuse engine.scan_source over fetched file contents
# ---------------------------------------------------------------------------

class _RepoFileSource(Source):
    """A Source adapter over already-fetched (path, text) file contents."""

    name = "repo"

    def __init__(self, repo_full_name: str, files: list):
        # files: [(display_path, text)]
        self.repo = repo_full_name
        self.files = files

    def iter_lines(self):
        for display_path, text in self.files:
            for line_no, line in enumerate(text.splitlines(), 1):
                yield (display_path, line_no, line,
                       {"source": "repo", "repo": self.repo})


def scan_repo(client: GitHubClient, repo: dict, max_files: int) -> list:
    """Fetch + scan one repo's default-branch files. Returns Findings."""
    full_name = repo["full_name"]
    branch = repo["default_branch"]
    files = client.list_files(full_name, branch)
    files = files[:max_files]
    fetched = []
    for entry in files:
        try:
            raw = client.fetch_file_raw(full_name, entry["path"], branch)
        except RepoError as e:
            print(f"  ! {full_name}/{entry['path']}: skipped ({e})",
                  file=sys.stderr)
            continue
        if len(raw) > MAX_FILE_BYTES:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue  # binary content slipped through the extension filter
        display = f"github:{full_name}/{entry['path']}"
        fetched.append((display, text))
        time.sleep(0.05)  # light pacing between content fetches
    if not fetched:
        return []
    return scan_source(_RepoFileSource(full_name, fetched))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="repos.py",
        description=(
            "Connect a GitHub org/user's repositories and scan them with "
            "the aiscan detector engine. Token via GITHUB_TOKEN env only — "
            "never stored, never printed."),
        epilog=(
            "GitHub App path (future): replace the PAT with a GitHub App "
            "(server-to-server auth, per-repo install, no long-lived token "
            "in a shell). Creating the App needs the user in a browser — "
            "recorded as a blocker, not attempted here."))
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--org", metavar="ORG",
                       help="GitHub organization to list repositories for")
    group.add_argument("--user", metavar="USER",
                       help="GitHub user to list repositories for "
                            "(omit for the token owner's own repos: use "
                            "--user with your username, or --repo)")
    group.add_argument("--repo", metavar="OWNER/NAME", action="append",
                       dest="repos", default=[],
                       help="specific repository to scan; repeatable")
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                   help=f"max files fetched per repo (default {DEFAULT_MAX_FILES})")
    p.add_argument("--dry-run", action="store_true",
                   help="list the repositories that would be scanned and stop "
                        "before fetching any file contents")
    p.add_argument("--output", metavar="FILE",
                   help="write the masked-only JSON report to FILE "
                        "(default: print to stdout)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        client = GitHubClient(os.environ.get("GITHUB_TOKEN", ""))
    except RepoError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    try:
        if args.repos:
            repos = [client.get_repo(name) for name in args.repos]
        elif args.org:
            repos = client.list_repos(org=args.org, user=None)
        else:
            repos = client.list_repos(org=None, user=args.user)
    except RepoError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if not repos:
        print("No repositories found (or none visible to this token).")
        return 0

    scannable = select_repos_for_scan(repos)
    skipped_archived = len(repos) - len(scannable)

    if args.dry_run:
        print(f"Repositories visible to this token: {len(repos)} "
              f"({len(scannable)} scannable, {skipped_archived} archived — skipped)")
        for r in repos:
            tag = " [archived — skipped]" if r["archived"] else ""
            vis = "private" if r["private"] else "public"
            print(f"  {r['full_name']}  (default branch: {r['default_branch']}, "
                  f"{vis}{', fork' if r['fork'] else ''}){tag}")
        print("Dry run — no file contents were fetched, nothing was scanned.")
        return 0

    all_findings = []
    for repo in scannable:
        print(f"Scanning {repo['full_name']} "
              f"(branch {repo['default_branch']}) ...", file=sys.stderr)
        try:
            findings = scan_repo(client, repo, args.max_files)
        except RepoError as e:
            print(f"  ! {repo['full_name']}: skipped ({e})", file=sys.stderr)
            continue
        print(f"  {len(findings)} finding(s)", file=sys.stderr)
        all_findings.extend(findings)

    report = render_json(all_findings, mode="repo", verified=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Wrote {len(all_findings)} masked finding(s) to {args.output}")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
