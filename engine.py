"""Scan engine: run detectors over a source, dedupe, classify, verify.

Dedup is global (SHA-256 of the candidate string), so the same key planted
in two files is one finding, attributed to its first occurrence.
"""
from __future__ import annotations

from common import Finding, SEVERITY_RANK, mask_value, value_hash
from detectors import scan_line
from verifiers import verify_key

MAX_SNIPPET_CHARS = 160


def _redact_snippet(line: str, value: str) -> str:
    """Redact EVERY detected credential on the line, not just this finding's.

    A single line (e.g. one-line JSON) can hold several keys; masking only
    the finding's own value would leak the others through the snippet.
    Detection runs with allow_examples=True here so example-marked values
    on the same line are redacted too, even though they are not findings.
    """
    snippet = line
    for raw in scan_line(line, allow_examples=True):
        snippet = snippet.replace(raw.value, mask_value(raw.value))
    snippet = snippet.strip()
    if len(snippet) > MAX_SNIPPET_CHARS:
        snippet = snippet[:MAX_SNIPPET_CHARS] + "…"
    return snippet


def scan_source(source, verify: bool = False, metrics=None,
                allow_examples: bool | None = None) -> list:
    """Run the full pipeline over a source. Returns sorted Findings.

    ``allow_examples``: when None (default), the source decides — sources
    declare ``allow_examples`` (only the bundled demo source sets it).
    An explicit True/False here overrides the source; the self-test uses
    True to prove detection still works on marked fixture values.
    Example-marked values are otherwise dropped from the findings.

    When ``metrics`` (a metrics.RunMetrics) is given, the engine records
    lines/bytes scanned, candidates before dedup, duplicates removed,
    verification outcomes, and merges the source's ``stats`` dict after
    iteration.
    """
    if allow_examples is None:
        allow_examples = bool(getattr(source, "allow_examples", False))
    findings: list = []
    seen: set = set()
    for path, line_no, line, meta in source.iter_lines():
        if metrics is not None:
            metrics.lines_scanned += 1
            metrics.bytes_scanned += len(line.encode("utf-8", errors="replace"))
        for raw in scan_line(line, allow_examples=allow_examples):
            digest = value_hash(raw.value)
            if digest in seen:
                if metrics is not None:
                    metrics.duplicates_removed += 1
                continue
            seen.add(digest)
            finding = Finding(
                provider=raw.provider,
                credential_type=raw.cred_type,
                value=raw.value,
                file_path=path,
                line_number=line_no,
                snippet=_redact_snippet(line, raw.value),
                severity=raw.severity,
                source=getattr(source, "name", "unknown"),
                console_url=raw.console_url,
                detected_via=raw.via,
            )
            if verify and raw.verify_key:
                status, detail = verify_key(raw.verify_key, raw.value)
                finding.verification = status
                finding.verification_detail = detail
                if metrics is not None:
                    metrics.verification[status] += 1
                if status in ("live", "no_quota"):
                    finding.severity = "critical"
            findings.append(finding)
    if metrics is not None:
        stats = getattr(source, "stats", None)
        if isinstance(stats, dict):
            metrics.merge_source_stats(stats)
        elif callable(stats):
            metrics.merge_source_stats(stats())
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file_path,
                                 f.line_number))
    return findings
