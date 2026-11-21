"""Git-history source: scan added lines across ``git log -p`` output.

Findings are attributed to the commit that introduced the line; the commit
hash is embedded in the reported path because a historical line has no
current line number (line_no is 0).
"""
from __future__ import annotations

import subprocess

from .base import Source


class GitHistorySource(Source):
    name = "git-history"

    def __init__(self, repo_path: str, max_commits: int = 500):
        self.repo_path = repo_path
        self.max_commits = max_commits
        self.commits_scanned = 0

    def iter_lines(self):
        try:
            proc = subprocess.run(
                ["git", "-C", self.repo_path, "log", "-p", "--all",
                 f"--max-count={self.max_commits}"],
                capture_output=True, text=True, errors="replace", timeout=180,
            )
        except FileNotFoundError:
            raise RuntimeError("git is not installed; cannot scan git history.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("git log timed out; try a smaller --max-commits.")
        if proc.returncode != 0:
            err = (proc.stderr or "").strip().splitlines()
            raise RuntimeError(
                f"git log failed in {self.repo_path}: "
                f"{err[0] if err else 'unknown error'} "
                "(is this a git repository?)"
            )
        commit = "?"
        current_file = "?"
        for line in proc.stdout.splitlines():
            if line.startswith("commit "):
                commit = line.split()[1][:12]
                self.commits_scanned += 1
            elif line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                path = f"{current_file} (commit {commit})"
                yield (path, 0, line[1:], {"source": "git-history", "commit": commit})

    @property
    def stats(self) -> dict:
        return {"commits_scanned": self.commits_scanned}
