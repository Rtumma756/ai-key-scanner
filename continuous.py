"""Continuous scanning: re-sweep known areas for NEW detections, and expand
the query space until the ocean is covered.

Design: results/OCEAN_AND_CONTINUOUS_SCAN.md. Two loops, one ledger:

  1. sweep  — re-run the seed queries (the known areas). Findings are
     classified against the ledger by SHA-256 fingerprint: "new" (never
     seen), "rotated" (same file + provider as a seen fingerprint, different
     fingerprint), "seen" (already known). Only new + rotated are reported.
  2. expand — run the next unrun queries from the enumerated query space.
     A query whose total_count exceeds GitHub's 1,000-result cap is split
     into shards (one qualifier appended at a time) until each shard is
     under the cap; the shards are run instead of the parent.
  3. stress — loop sweep + expand for a wall-clock budget (default 2 h),
     appending one JSON line per iteration to results/stress_log.jsonl.
     The ledger is saved after every iteration, so a killed run resumes
     cleanly. A rejected token (401) stops the run with a final summary.

"Covered" means: every query in the known query space has been run, and
every query over the 1,000-result cap has been sharded under it. It does
not mean all of GitHub — 395M public repos growing at 230/min against a
10 req/min code-search limit makes literal coverage impossible.

Safety invariants (same as the rest of aiscan):
  - Output uses f.masked only. This module never touches f.value.
  - Verification is OFF everywhere here; nothing is tested against a
    provider. Findings are candidates only.
  - Tokens come from env GITHUB_TOKEN or --token, never from a file.
  - Only fingerprints (SHA-256 first 16 hex) are stored in the ledger.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import value_hash  # noqa: E402
from engine import scan_source  # noqa: E402
from reporters import table as table_reporter  # noqa: E402
from sources import DemoSource, GitHubError, GitHubSource  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LEDGER_PATH = os.path.join(ROOT, "results", "coverage_ledger.json")
DEFAULT_STRESS_LOG = os.path.join(ROOT, "results", "stress_log.jsonl")

GITHUB_RESULT_CAP = 1000  # GitHub returns at most 1,000 results per query
RESWEEP_INTERVAL_HOURS = 24

# ---------------------------------------------------------------------------
# Query space
# ---------------------------------------------------------------------------

# (query, start_page, max_pages, max_items) — the 23 trial queries from
# trial_run3.py PATTERNS (13) + phase2_trial3.py PHASE2 (10). Two entries
# are the same search ('filename:.mcp.json "sk-"' pages 1-3, listed once in
# each phase); the ledger dedupes identical (query, start_page) pairs, so
# they seed 22 records. start_page matters: pages 1-3 and 4-6 of the same
# query cover different result windows.
SEED_QUERIES = [
    ("sk-proj-", 1, 3, 90),
    ("sk-svcacct-", 1, 3, 90),
    ("sk-ant-api03-", 1, 3, 90),
    ("gsk_", 1, 3, 90),
    ("sk-or-v1-", 1, 3, 90),
    ("AIza", 1, 3, 90),
    ("hf_", 1, 3, 90),
    ("pplx-", 1, 3, 90),
    ("xai-", 1, 3, 90),
    ("r8_", 1, 3, 90),
    ("sk-", 1, 2, 60),
    ('filename:.mcp.json "sk-"', 1, 3, 90),
    ('extension:ipynb "sk-"', 1, 3, 90),
    ("sk-proj-", 4, 3, 90),
    ("sk-ant-api03-", 4, 3, 90),
    ('filename:.env "sk-proj-"', 1, 3, 90),
    ('filename:.env "sk-ant-api03-"', 1, 3, 90),
    ('filename:.env "gsk_"', 1, 3, 90),
    ('filename:.env "AIza"', 1, 2, 60),
    ('extension:py "sk-proj-"', 1, 3, 90),
    ('extension:js "sk-ant-api03-"', 1, 2, 60),
    ('filename:config.py "sk-proj-"', 1, 2, 60),
    ('filename:.mcp.json "sk-"', 1, 3, 90),
]

PROVIDER_PREFIXES = [
    "sk-proj-", "sk-ant-api03-", "gsk_", "sk-or-v1-", "AIza", "hf_",
    "pplx-", "xai-", "r8_", "sk-svcacct-", "sk-",
]

FILE_QUALIFIERS = [
    "filename:.env", "extension:py", "extension:js", "extension:ts",
    "extension:json", "filename:.mcp.json", "extension:ipynb",
    "filename:config.py", "extension:txt", "extension:md",
]

# Qualifiers used to shard a query whose total_count exceeds the 1,000 cap,
# tried in order. A shard is accepted when its total_count drops under the cap.
SHARD_QUALIFIERS = [
    "language:Python", "language:JavaScript", "language:TypeScript",
    "extension:py", "extension:js", "extension:json", "filename:.env",
]


def enumerate_query_space() -> list:
    """All queries the product knows about, in deterministic order: the
    seed queries first (trial order), then every provider prefix crossed
    with every file qualifier, sorted. Identical (query, start_page) pairs
    appear once."""
    seen: set = set()
    out = []
    for query, start_page, max_pages, max_items in SEED_QUERIES:
        key = (query, start_page)
        if key in seen:
            continue
        seen.add(key)
        out.append({"query": query, "start_page": start_page,
                    "max_pages": max_pages, "max_items": max_items,
                    "seed": True})
    generated = []
    for prefix in PROVIDER_PREFIXES:
        for qual in FILE_QUALIFIERS:
            query = f"{prefix} {qual}"
            if (query, 1) in seen:
                continue
            seen.add((query, 1))
            generated.append({"query": query, "start_page": 1,
                              "max_pages": 3, "max_items": 90,
                              "seed": False})
    generated.sort(key=lambda g: g["query"])
    return out + generated


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_record(query: str, start_page: int, max_pages: int,
                max_items: int, seed: bool) -> dict:
    return {
        "source": "github",
        "query": query,
        "start_page": start_page,
        "max_pages": max_pages,
        "max_items": max_items,
        "seed": seed,
        "status": "unrun",  # unrun | partial | covered | sharded
        "total_count": None,
        "scanned": 0,  # items seen across DISTINCT pages (see pages)
        "pages": {},   # page number (str) -> items returned on that page
        "findings": 0,  # lifetime unique fingerprints first seen here
        "new_findings": 0,
        "rotated_findings": 0,
        "fingerprints": [],  # fingerprints first seen via this record
        "last_run_utc": None,
        "next_run_utc": None,
        "next_page": None,  # where expand continues paging, if partial
        "runs": 0,
        "shards": [],  # shard query strings, if this record was sharded
    }


class TokenRejectedError(RuntimeError):
    """GitHub rejected the token (401). Stop the run; do not retry."""


class CoverageLedger:
    """JSON store at results/coverage_ledger.json. One record per
    (source, query, start_page) — the page window matters, because pages
    1-3 and 4-6 of one query cover different results. Global dedup state
    (fingerprints + locations) lives at the top level so a key found under
    one query never alerts again under another."""

    def __init__(self, path: str | None = None):
        self.path = path or os.environ.get("AISCAN_LEDGER_PATH") \
            or DEFAULT_LEDGER_PATH
        self.data = {
            "version": 1,
            "updated_utc": None,
            "seen_fingerprints": [],  # SHA-256 first-16-hex, all records
            "locations": {},  # "file_path\x1fprovider" -> [fingerprints]
            "records": [],
        }
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict) and loaded.get("version") == 1:
                self.data = loaded
        self._ensure_space()

    # -- structure ------------------------------------------------------
    def _ensure_space(self) -> None:
        """Add any query-space entries missing from the ledger (idempotent).
        Seeds keep trial order; generated queries are appended sorted."""
        existing = {(r["query"], r["start_page"]) for r in self.data["records"]}
        for spec in enumerate_query_space():
            key = (spec["query"], spec["start_page"])
            if key not in existing:
                self.data["records"].append(_new_record(
                    spec["query"], spec["start_page"], spec["max_pages"],
                    spec["max_items"], spec["seed"]))
                existing.add(key)

    @property
    def records(self) -> list:
        return self.data["records"]

    def find(self, query: str, start_page: int = 1,
             source: str = "github") -> dict | None:
        for r in self.data["records"]:
            if (r["source"] == source and r["query"] == query
                    and r["start_page"] == start_page):
                return r
        return None

    def get_or_create(self, query: str, start_page: int = 1,
                      max_pages: int = 3, max_items: int = 90,
                      seed: bool = False) -> dict:
        rec = self.find(query, start_page)
        if rec is None:
            rec = _new_record(query, start_page, max_pages, max_items, seed)
            self.data["records"].append(rec)
        return rec

    # -- classification ---------------------------------------------------
    def classify(self, finding) -> str:
        """'new' (fingerprint never seen), 'rotated' (same file + provider
        as a seen fingerprint, different fingerprint), 'seen'."""
        fp = finding.fingerprint
        if fp in self.data["seen_fingerprints"]:
            return "seen"
        loc = f"{finding.file_path}\x1f{finding.provider}"
        if self.data["locations"].get(loc):
            return "rotated"
        return "new"

    def note_finding(self, record: dict, finding, cls: str) -> None:
        """Record a new/rotated fingerprint globally and on the record."""
        fp = finding.fingerprint
        if fp not in self.data["seen_fingerprints"]:
            self.data["seen_fingerprints"].append(fp)
        loc = f"{finding.file_path}\x1f{finding.provider}"
        self.data["locations"].setdefault(loc, [])
        if fp not in self.data["locations"][loc]:
            self.data["locations"][loc].append(fp)
        record["fingerprints"].append(fp)
        record["findings"] += 1
        if cls == "new":
            record["new_findings"] += 1
        else:
            record["rotated_findings"] += 1

    # -- run bookkeeping ----------------------------------------------------
    def apply_run(self, record: dict, start_page_used: int, run: dict) -> None:
        """Fold one query run into its record. `scanned` counts items seen
        across DISTINCT pages only, so re-sweeping the same window does not
        inflate coverage. `total_count` is only ever set from the API."""
        record["runs"] += 1
        record["last_run_utc"] = _utcnow()
        record["next_run_utc"] = (
            datetime.now(timezone.utc)
            + timedelta(hours=RESWEEP_INTERVAL_HOURS)).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
        if run["total_count"] is not None:
            record["total_count"] = run["total_count"]
        for page, count in run["pages"].items():
            key = str(page)
            record["pages"][key] = max(record["pages"].get(key, 0), count)
        record["scanned"] = sum(record["pages"].values())
        tc = record["total_count"]
        if tc is None:
            record["status"] = "covered"  # demo: whole dataset scanned
            record["next_page"] = None
        elif record["scanned"] >= min(tc, GITHUB_RESULT_CAP):
            record["status"] = "covered"
            record["next_page"] = None
        else:
            record["status"] = "partial"
            record["next_page"] = start_page_used + record["max_pages"]

    def save(self) -> None:
        """Atomic save (temp file + rename) so a killed run never leaves a
        torn ledger behind."""
        self.data["updated_utc"] = _utcnow()
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    # -- totals ---------------------------------------------------------------
    def totals(self) -> dict:
        recs = self.data["records"]
        covered = sum(1 for r in recs if r["status"] == "covered")
        remaining = sum(1 for r in recs if r["status"] in ("unrun", "partial"))
        return {
            "queries_total": len(recs),
            "queries_covered": covered,
            "queries_remaining": remaining,
            "queries_sharded": sum(1 for r in recs
                                   if r["status"] == "sharded"),
            "files_scanned": sum(r["scanned"] for r in recs),
            "new_keys_lifetime": sum(r["new_findings"] for r in recs),
            "rotated_keys_lifetime": sum(r["rotated_findings"] for r in recs),
            "fingerprints_seen": len(self.data["seen_fingerprints"]),
        }


# ---------------------------------------------------------------------------
# Running one query
# ---------------------------------------------------------------------------

def run_query(record: dict, start_page: int, token: str | None = None,
              demo: bool = False, extra_demo_files=None) -> dict:
    """Run one ledger record. Returns findings + counts. Never verifies
    (verification stays OFF); never prints a full key — callers only ever
    use f.masked / f.fingerprint. Raises GitHubError on API failure."""
    if demo:
        src = DemoSource(extra_files=extra_demo_files)
        findings = scan_source(src, verify=False)
        n = len(src.files)
        return {"findings": findings, "items_seen": n, "total_count": None,
                "pages": {"demo": n}, "api_calls": 0, "rate_limit_hits": 0}
    src = GitHubSource(record["query"], token,
                       max_pages=record["max_pages"],
                       max_items=record["max_items"],
                       start_page=start_page)
    findings = scan_source(src, verify=False)
    return {"findings": findings, "items_seen": src.items_seen,
            "total_count": src.total_count,
            "pages": dict(src.pages_seen),
            "api_calls": src.api_requests,
            "rate_limit_hits": src.rate_limit_hits}


def probe_total_count(query: str, token: str) -> int | None:
    """One cheap API call (per_page=1) to learn a query's total_count.
    Returns None when the count cannot be learned. Raises
    TokenRejectedError on 401."""
    try:
        src = GitHubSource(query, token, max_pages=1, per_page=1,
                           max_items=1)
        it = src.iter_lines()
        try:
            next(it)
        except StopIteration:
            pass
        return src.total_count
    except GitHubError as e:
        if "401" in str(e):
            raise TokenRejectedError(str(e))
        return None


def _classify_run(ledger: CoverageLedger, record: dict,
                  findings: list) -> tuple[list, list, list]:
    """Classify one run's findings against the ledger, recording new and
    rotated ones. Returns (new, rotated, seen)."""
    new, rotated, seen = [], [], []
    for f in findings:
        cls = ledger.classify(f)
        if cls == "new":
            new.append(f)
            ledger.note_finding(record, f, "new")
        elif cls == "rotated":
            rotated.append(f)
            ledger.note_finding(record, f, "rotated")
        else:
            seen.append(f)
    return new, rotated, seen


def _empty_result() -> dict:
    return {"queries_run": 0, "api_calls": 0, "rate_limit_hits": 0,
            "files_scanned": 0, "new": 0, "rotated": 0, "seen": 0,
            "errors": [], "alerts": [], "sharded": []}


def _run_record(ledger: CoverageLedger, record: dict, start_page: int,
                result: dict, token=None, demo=False,
                extra_demo_files=None) -> bool:
    """Run one record, fold it into the ledger and `result`. Returns False
    when the query errored (error recorded, run continues); raises
    TokenRejectedError on 401."""
    try:
        run = run_query(record, start_page, token, demo, extra_demo_files)
    except GitHubError as e:
        if "401" in str(e):
            raise TokenRejectedError(str(e))
        result["errors"].append(f"{record['query']}: {e}")
        return False
    except Exception as e:
        # Safety net: one bad query (malformed response, unexpected
        # error) must never kill a long run — record it and continue.
        result["errors"].append(
            f"{record['query']}: unexpected {type(e).__name__}: {e}")
        return False
    result["queries_run"] += 1
    result["api_calls"] += run["api_calls"]
    result["rate_limit_hits"] += run["rate_limit_hits"]
    result["files_scanned"] += run["items_seen"]
    new, rotated, seen = _classify_run(ledger, record, run["findings"])
    result["new"] += len(new)
    result["rotated"] += len(rotated)
    result["seen"] += len(seen)
    result["alerts"].extend(new)
    result["alerts"].extend(rotated)
    ledger.apply_run(record, start_page, run)
    return True


# ---------------------------------------------------------------------------
# Loop 1: sweep — re-run the known areas, alert only on NEW detections
# ---------------------------------------------------------------------------

def sweep_ledger(ledger: CoverageLedger, token: str | None = None,
                 demo: bool = False, extra_demo_files=None) -> dict:
    """Re-sweep every seed query (the known areas) from its original
    window. Sharded parents are skipped — their shards are the queries now.
    Returns counts + the alert findings (new + rotated, masked only)."""
    result = _empty_result()
    for record in list(ledger.records):
        if not record.get("seed") or record["status"] == "sharded":
            continue
        _run_record(ledger, record, record["start_page"], result,
                    token, demo, extra_demo_files)
    return result


# ---------------------------------------------------------------------------
# Loop 2: expand — run unrun queries; shard anything over the 1,000 cap
# ---------------------------------------------------------------------------

def shard_query(query: str, token: str | None, probe=None) -> list:
    """Split an over-cap query by appending one qualifier at a time.
    Returns [(shard_query, total_count)] for shards under the cap. A shard
    still over the cap gets one deeper qualifier tried (first success only).
    `probe` is an injectable total_count function (used by the selftest);
    without it, live probing is used (None in demo mode = cannot judge)."""
    shards = []
    for qual in SHARD_QUALIFIERS:
        cand = f"{query} {qual}"
        tc = probe(cand) if probe is not None else (
            probe_total_count(cand, token) if token else None)
        if tc is None:
            continue
        if tc < GITHUB_RESULT_CAP:
            shards.append((cand, tc))
            continue
        for qual2 in SHARD_QUALIFIERS:
            if qual2 == qual:
                continue
            cand2 = f"{cand} {qual2}"
            tc2 = probe(cand2) if probe is not None else (
                probe_total_count(cand2, token) if token else None)
            if tc2 is not None and tc2 < GITHUB_RESULT_CAP:
                shards.append((cand2, tc2))
                break
    return shards


def expand_ledger(ledger: CoverageLedger, count: int = 5,
                  token: str | None = None, demo: bool = False,
                  probe=None, extra_demo_files=None) -> dict:
    """Run the next `count` unrun queries (then partial ones, continuing
    their paging). Over-cap queries are sharded and the shards are run
    instead of the parent. Returns counts + shard list."""
    result = _empty_result()
    targets = [r for r in ledger.records if r["status"] == "unrun"][:count]
    if len(targets) < count:
        targets += [r for r in ledger.records
                    if r["status"] == "partial"][:count - len(targets)]
    for record in targets:
        start = record.get("next_page") or record["start_page"]
        ok = _run_record(ledger, record, start, result,
                         token, demo, extra_demo_files)
        if not ok:
            continue
        tc = record["total_count"]
        if tc is None and probe is not None:
            tc = probe(record["query"])
            if tc is not None:
                record["total_count"] = tc
        if tc is not None and tc > GITHUB_RESULT_CAP:
            shards = shard_query(record["query"], token, probe)
            record["shards"] = [s[0] for s in shards]
            record["status"] = "sharded"
            record["next_page"] = None
            result["sharded"].append(record["query"])
            for shard_q, shard_tc in shards:
                srec = ledger.get_or_create(shard_q, 1, 3, 90, seed=False)
                srec["total_count"] = shard_tc
                _run_record(ledger, srec, 1, result,
                            token, demo, extra_demo_files)
        elif tc is None and not demo and token:
            # Live run with no total_count (e.g. empty first page): keep
            # the record partial so expand revisits it.
            record["status"] = "partial"
    return result


# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------

def coverage_pct(record: dict) -> str:
    tc = record["total_count"]
    if tc is None:
        return "n/a"
    cap = min(tc, GITHUB_RESULT_CAP)
    if cap <= 0:
        return "n/a"
    return f"{min(100.0, 100.0 * record['scanned'] / cap):.0f}%"


def render_coverage(ledger: CoverageLedger) -> str:
    lines = []
    lines.append(f"{'QUERY':42} {'STATUS':9} {'TOTAL':>7} {'SCANNED':>7} "
                 f"{'FIND':>5} {'NEW':>4} {'COVER':>6}  LAST RUN")
    lines.append("-" * 110)
    for r in ledger.records:
        q = r["query"]
        if len(q) > 40:
            q = q[:37] + "..."
        tc = "-" if r["total_count"] is None else str(r["total_count"])
        lines.append(f"{q:42} {r['status']:9} {tc:>7} {r['scanned']:>7} "
                     f"{r['findings']:>5} {r['new_findings']:>4} "
                     f"{coverage_pct(r):>6}  {r['last_run_utc'] or '-'}")
    t = ledger.totals()
    lines.append("-" * 110)
    lines.append(f"Totals: {t['queries_covered']}/{t['queries_total']} "
                 f"queries covered, {t['queries_remaining']} remaining "
                 f"({t['queries_sharded']} sharded), "
                 f"{t['files_scanned']} files scanned, "
                 f"{t['new_keys_lifetime']} new keys lifetime "
                 f"({t['rotated_keys_lifetime']} rotated), "
                 f"{t['fingerprints_seen']} fingerprints seen.")
    lines.append("Covered = every query in the known space run, and every "
                 "query over the 1,000-result cap sharded under it.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Loop 3: stress — loop sweep + expand for a wall-clock budget
# ---------------------------------------------------------------------------

def _append_log_line(log_path: str, entry: dict) -> None:
    parent = os.path.dirname(log_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def stress_run(ledger: CoverageLedger, minutes: float = 120,
               token: str | None = None, demo: bool = False,
               max_iterations: int | None = None,
               log_path: str | None = None, expand_count: int = 5,
               extra_demo_files=None,
               sleep_fn=time.sleep) -> dict:
    """Loop sweep + expand until the wall-clock budget is spent (or
    max_iterations, when given), then stop cleanly. One JSON line per
    iteration is appended to the stress log; a final summary line closes
    the run. The ledger is saved after every iteration, so a killed run
    resumes from the ledger. Only totals are kept in RAM across iterations
    — per-iteration findings are printed and dropped, never accumulated.

    Rate-limit / network errors are logged and backed off, not fatal. A
    rejected token (401) stops the run with a final summary line."""
    log_path = log_path or DEFAULT_STRESS_LOG
    started = time.monotonic()
    deadline = started + minutes * 60
    totals = {"iterations": 0, "queries_run": 0, "api_calls": 0,
              "files_scanned": 0, "new": 0, "rotated": 0,
              "rate_limit_hits": 0, "errors": 0}
    stopped_reason = "budget"
    consecutive_errors = 0
    while True:
        if max_iterations is not None and totals["iterations"] >= max_iterations:
            stopped_reason = "max_iterations"
            break
        if max_iterations is None and time.monotonic() >= deadline:
            stopped_reason = "budget"
            break
        totals["iterations"] += 1
        t0 = time.monotonic()
        errors: list = []
        counts = {"queries_run": 0, "api_calls": 0, "files_scanned": 0,
                  "new": 0, "rotated": 0, "rate_limit_hits": 0}
        try:
            sw = sweep_ledger(ledger, token, demo, extra_demo_files)
            ex = expand_ledger(ledger, count=expand_count, token=token,
                               demo=demo, extra_demo_files=extra_demo_files)
            for part in (sw, ex):
                for k in counts:
                    counts[k] += part[k]
                errors.extend(part["errors"])
        except TokenRejectedError as e:
            errors.append(f"token rejected (401): {e}")
            stopped_reason = "token_rejected"
            _append_log_line(log_path, {
                "ts_utc": _utcnow(), "kind": "iteration",
                "iteration": totals["iterations"],
                "queries_run": counts["queries_run"],
                "api_calls": counts["api_calls"],
                "files_scanned": counts["files_scanned"],
                "new_findings": counts["new"],
                "rotated": counts["rotated"],
                "rate_limit_hits": counts["rate_limit_hits"],
                "errors": errors,
                "elapsed_seconds": round(time.monotonic() - t0, 2),
            })
            ledger.save()
            break
        except Exception as e:
            # Safety net: an unexpected failure in one iteration (bad
            # response, ledger hiccup) is logged and backed off, never
            # fatal — the run continues with the next iteration.
            errors.append(f"iteration error: {type(e).__name__}: {e}")
        for k in ("queries_run", "api_calls", "files_scanned", "new",
                  "rotated", "rate_limit_hits"):
            totals[k] += counts[k]
        totals["errors"] += len(errors)
        ledger.save()
        _append_log_line(log_path, {
            "ts_utc": _utcnow(), "kind": "iteration",
            "iteration": totals["iterations"],
            "queries_run": counts["queries_run"],
            "api_calls": counts["api_calls"],
            "files_scanned": counts["files_scanned"],
            "new_findings": counts["new"],
            "rotated": counts["rotated"],
            "rate_limit_hits": counts["rate_limit_hits"],
            "errors": errors,
            "elapsed_seconds": round(time.monotonic() - t0, 2),
        })
        if errors:
            consecutive_errors += 1
            if not demo:
                # Back off before the next iteration; grows with repeated
                # failures, capped at 60s. Demo runs never sleep.
                sleep_fn(min(60, 15 * consecutive_errors))
        else:
            consecutive_errors = 0
    elapsed = round(time.monotonic() - started, 2)
    _append_log_line(log_path, {
        "ts_utc": _utcnow(), "kind": "summary",
        "iterations": totals["iterations"],
        "total_queries_run": totals["queries_run"],
        "total_api_calls": totals["api_calls"],
        "total_files_scanned": totals["files_scanned"],
        "total_new": totals["new"],
        "total_rotated": totals["rotated"],
        "total_rate_limit_hits": totals["rate_limit_hits"],
        "total_errors": totals["errors"],
        "elapsed_seconds": elapsed,
        "stopped_reason": stopped_reason,
    })
    totals["elapsed_seconds"] = elapsed
    totals["stopped_reason"] = stopped_reason
    return totals


# ---------------------------------------------------------------------------
# CLI entry points (called from aiscan.py; return exit codes)
# ---------------------------------------------------------------------------

def _resolve_token(args_token, demo: bool) -> str | None:
    if demo:
        return None
    token = args_token or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("error: continuous live mode needs a GitHub token. Set "
              "GITHUB_TOKEN or pass --token (or use --demo for the offline "
              "fake dataset).", file=sys.stderr)
        return None
    return token


def cmd_sweep(args) -> int:
    token = _resolve_token(getattr(args, "token", None),
                           getattr(args, "demo", False))
    if token is None and not getattr(args, "demo", False):
        return 2
    ledger = CoverageLedger(getattr(args, "ledger", None))
    try:
        result = sweep_ledger(ledger, token, getattr(args, "demo", False))
    except TokenRejectedError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    ledger.save()
    print(f"Sweep: {result['queries_run']} queries, "
          f"{result['files_scanned']} files scanned, "
          f"{result['new']} new, {result['rotated']} rotated, "
          f"{result['seen']} already known, "
          f"{result['api_calls']} API calls, "
          f"{result['rate_limit_hits']} rate-limit hits.")
    if result["errors"]:
        for err in result["errors"]:
            print(f"  error: {err}", file=sys.stderr)
    if result["alerts"]:
        print()
        print("NEW / ROTATED detections (masked only):")
        print(table_reporter.render_table(result["alerts"],
                                          "continuous:sweep", False),
              end="")
    else:
        print("No new detections.")
    print(f"Ledger saved to {ledger.path}")
    return 0


def cmd_expand(args) -> int:
    token = _resolve_token(getattr(args, "token", None),
                           getattr(args, "demo", False))
    if token is None and not getattr(args, "demo", False):
        return 2
    ledger = CoverageLedger(getattr(args, "ledger", None))
    try:
        result = expand_ledger(ledger, count=getattr(args, "count", 5),
                               token=token,
                               demo=getattr(args, "demo", False))
    except TokenRejectedError as e:
        print(f"error: {e}", file=sys.stderr)
        ledger.save()
        return 1
    ledger.save()
    print(f"Expand: {result['queries_run']} queries, "
          f"{result['files_scanned']} files scanned, "
          f"{result['new']} new, {result['rotated']} rotated, "
          f"{result['api_calls']} API calls.")
    if result["sharded"]:
        print(f"Sharded over-cap queries: {', '.join(result['sharded'])}")
    if result["errors"]:
        for err in result["errors"]:
            print(f"  error: {err}", file=sys.stderr)
    if result["alerts"]:
        print()
        print("NEW / ROTATED detections (masked only):")
        print(table_reporter.render_table(result["alerts"],
                                          "continuous:expand", False),
              end="")
    t = ledger.totals()
    print(f"Coverage now: {t['queries_covered']}/{t['queries_total']} "
          f"queries covered, {t['queries_remaining']} remaining. "
          f"Ledger saved to {ledger.path}")
    return 0


def cmd_coverage(args) -> int:
    ledger = CoverageLedger(getattr(args, "ledger", None))
    print(render_coverage(ledger))
    return 0


def cmd_stress(args) -> int:
    token = _resolve_token(getattr(args, "token", None),
                           getattr(args, "demo", False))
    if token is None and not getattr(args, "demo", False):
        return 2
    ledger = CoverageLedger(getattr(args, "ledger", None))
    log_path = getattr(args, "log", None) or DEFAULT_STRESS_LOG
    totals = stress_run(
        ledger, minutes=getattr(args, "minutes", 120),
        token=token, demo=getattr(args, "demo", False),
        max_iterations=getattr(args, "max_iterations", None),
        log_path=log_path,
        expand_count=getattr(args, "expand_count", 5))
    print(f"Stress run finished ({totals['stopped_reason']}): "
          f"{totals['iterations']} iteration(s), "
          f"{totals['queries_run']} queries, "
          f"{totals['api_calls']} API calls, "
          f"{totals['files_scanned']} files scanned, "
          f"{totals['new']} new, {totals['rotated']} rotated, "
          f"{totals['errors']} error(s), "
          f"{totals['elapsed_seconds']}s elapsed.")
    print(f"Log: {log_path} | Ledger: {ledger.path}")
    return 0
