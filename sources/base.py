"""Source interface: every source yields (path, line_no, line, meta) tuples.

line_no is 0 when there is no meaningful line number (e.g. a git-history
finding, where the commit hash is embedded in the path instead).
"""
from __future__ import annotations


class Source:
    name = "base"
    # When True, the scan engine passes allow_examples=True to the
    # detector, so example-marked values are reported as findings.
    # Only the bundled demo source sets this: its content is synthetic
    # demonstration data. Every real scan source leaves it False, so
    # example keys in real code are filtered from findings.
    allow_examples = False

    def iter_lines(self):
        raise NotImplementedError
