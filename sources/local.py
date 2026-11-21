"""Local filesystem source: walk a directory tree and yield text lines.

- Respects .gitignore by default (use --no-ignore to override).
- Skips binary files (NUL byte in the first 8 KB) and lockfiles by default.
- Skips VCS / build / dependency directories.
- Caps file size to keep scans cheap.
"""
from __future__ import annotations

import fnmatch
import os

from .base import Source

DEFAULT_SKIP_DIRS = {
    ".git", ".svn", ".hg", ".venv", "venv", "node_modules", "__pycache__",
    ".tox", "dist", "build", "target", ".next", ".idea", ".eggs",
}
DEFAULT_SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock",
    "poetry.lock", "Cargo.lock", "Gemfile.lock", "composer.lock",
}
MAX_FILE_BYTES = 2_000_000
BINARY_PROBE_BYTES = 8192


def _parse_gitignore(path: str) -> list:
    patterns = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    except OSError:
        pass
    return patterns


def _pattern_matches(pattern: str, rel_path: str) -> bool:
    """Simplified gitignore matching (good enough for a scanner).

    ``pattern`` must already have any leading '!' stripped by the caller.
    Returns True when the pattern matches the relative path.
    """
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    pat = pattern.lstrip("/")
    is_dir = pat.endswith("/")
    pat = pat.rstrip("/")
    if anchored or is_dir:
        return bool(fnmatch.fnmatch(rel_path, pat)
                    or rel_path.startswith(pat + "/"))
    if fnmatch.fnmatch(rel_path, pat):
        return True
    return any(fnmatch.fnmatch(part, pat) for part in rel_path.split("/"))


def _is_ignored(rel_path: str, patterns: list) -> bool:
    """Last matching pattern wins; '!' re-includes."""
    ignored = False
    for raw in patterns:
        negated = raw.startswith("!")
        pat = raw[1:] if negated else raw
        if _pattern_matches(pat, rel_path):
            ignored = not negated
    return ignored


class LocalSource(Source):
    name = "local"

    def __init__(self, root: str, respect_gitignore: bool = True,
                 include_lockfiles: bool = False):
        self.root = os.path.abspath(root)
        self.respect_gitignore = respect_gitignore
        self.include_lockfiles = include_lockfiles
        self.skipped_binary = 0
        self.skipped_lockfile = 0
        self.skipped_ignored = 0
        self.skipped_large = 0
        self.files_scanned = 0

    def iter_lines(self):
        if os.path.isfile(self.root):
            yield from self._scan_file(self.root, os.path.basename(self.root))
            return
        gitignore_patterns = []
        if self.respect_gitignore:
            gitignore_patterns = _parse_gitignore(os.path.join(self.root, ".gitignore"))
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in DEFAULT_SKIP_DIRS)
            for filename in sorted(filenames):
                full = os.path.join(dirpath, filename)
                rel = os.path.relpath(full, self.root)
                if self.respect_gitignore and _is_ignored(rel, gitignore_patterns):
                    self.skipped_ignored += 1
                    continue
                if not self.include_lockfiles and filename in DEFAULT_SKIP_FILES:
                    self.skipped_lockfile += 1
                    continue
                yield from self._scan_file(full, rel)

    def _scan_file(self, full_path: str, display_path: str):
        try:
            size = os.path.getsize(full_path)
        except OSError:
            return
        if size > MAX_FILE_BYTES:
            self.skipped_large += 1
            return
        try:
            with open(full_path, "rb") as f:
                head = f.read(BINARY_PROBE_BYTES)
                if b"\x00" in head:
                    self.skipped_binary += 1
                    return
                f.seek(0)
                text = f.read().decode("utf-8", errors="replace")
        except OSError:
            return
        self.files_scanned += 1
        for i, line in enumerate(text.splitlines(), 1):
            yield (display_path, i, line, {"source": "local"})

    @property
    def stats(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "skipped_binary": self.skipped_binary,
            "skipped_lockfile": self.skipped_lockfile,
            "skipped_ignored": self.skipped_ignored,
            "skipped_large": self.skipped_large,
        }
