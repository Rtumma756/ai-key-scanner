"""Source interface: every source yields (path, line_no, line, meta) tuples.

line_no is 0 when there is no meaningful line number (e.g. a git-history
finding, where the commit hash is embedded in the path instead).
"""
from __future__ import annotations


class Source:
    name = "base"

    def iter_lines(self):
        raise NotImplementedError
