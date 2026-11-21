#!/usr/bin/env python3
"""Classify the KeySentry stress-test detections (606 new + 54 rotated).

Phase 1: for every fingerprint in results/coverage_ledger.json, re-fetch
the file from public GitHub (raw.githubusercontent.com, unauthenticated
read-only, main then master — same approach as fresh_liveness_67.py),
re-run the scanner detectors on the live content, match by SHA-256
fingerprint (first 16 hex), and classify per results/DISCOVERY_INTELLIGENCE.md
§1.2 (real / placeholder-or-fixture / borderline).

Hard boundaries (enforced by construction):
- NEVER test any found key against any provider (verification stays OFF).
- NEVER write a full key value anywhere: full values exist only in memory
  during the run; all output uses the first-4 masked form (mask_value).
- Only key lengths are recorded, never values.
- Free-only; no paid APIs; no deploys; production FusionAI keys untouched.

Rotated identification: in the ledger, locations map to fingerprint lists in
discovery order (continuous.py note_finding appends). The FIRST fingerprint
at a location is the "new" one; any later fingerprint at the same location
is a "rotated" one. Cross-check: 606 firsts + 54 later = stress-log totals.

Usage: python3 classify_stress_606.py
Writes: results/STRESS_606_CLASSIFICATION.md + .json
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from collections import Counter, defaultdict
from types import SimpleNamespace

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from common import mask_value, value_hash
from detectors import scan_line
from savings import estimate_savings

LEDGER = "results/coverage_ledger.json"
TRIAL = "results/TRIAL_RUN_3.json"
REAL67 = "results/REAL_67_KEYS_SAVINGS.json"
OUT_MD = "results/STRESS_606_CLASSIFICATION.md"
OUT_JSON = "results/STRESS_606_CLASSIFICATION.json"
CHECKPOINT = "results/.classify_606_checkpoint.json"

UA = {"User-Agent": "aiscan-stress-classification (read-only, public files)"}
MAX_BYTES = 5 * 1024 * 1024  # files bigger than this are recorded too_large
PACE_SECONDS = 0.25

# ---------------------------------------------------------------------------
# Classification rules — DISCOVERY_INTELLIGENCE.md §1.2, applied to the
# re-fetched key (in memory only) + file path.
# ---------------------------------------------------------------------------

# Placeholder words: a real random key essentially never contains one of
# these as a substring (each is 3+ specific chars in sequence).
PLACEHOLDER_WORDS = (
    "fake", "test", "demo", "example", "changeme", "placeholder",
    "sample", "dummy", "your-api-key", "your_api_key", "yourkey",
    "insert", "replace", "todo", "xxx", "not-a-real", "notreal",
    "demofake", "testfake",
)

# A test fixture / example / tutorial file (per §1.2).
FIXTURE_MARKERS = (
    "/fixtures/", "/fixture/", "/tests/", "/test/", "/__tests__/",
    "/testdata", "test-data", ".test.", ".spec.",
    ".env.example", ".env.sample", ".env_sample",
    "semgrep-rules", "held_out", "fake_person_data",
    "/examples/", "/example/", "/tutorial/", "/tutorials/",
    "/demo/", "/demos/", "/sample/", "/samples/", "/mock/", "/mocks/",
)

# EXTENSIONS beyond §1.2 (applied here, documented in the report):
#  "_test." covers Go *_test.go / Python *_test.py test files;
#  "lesson" covers tutorial lesson directories (lesson2/…);
#  basename startswith "demo" covers demo.ipynb / Demo.ipynb notebooks;
#  basename endswith ".spec" covers .env.spec-style spec files.
EXTENSION_FIXTURE_MARKERS = ("_test.", "lesson")

# Documentation files (per §1.2 + the 67-reproduction judgment call on pr.md).
# NOTE: deliberately narrow — the 67 reproduction showed a blanket ".md$"
# rule over-excludes real keys, so only these names / /docs/ count.
DOC_BASENAMES = {"readme.md", "setup.md", "usage.md", "readme", "setup", "usage", "pr.md"}


def _has_sequential_run(s: str) -> bool:
    """True if any 4-char window is a strict ascending/descending run of
    letters or digits, or 4 identical chars (e.g. abcd, wxyz, 7890, aaaa)."""
    for i in range(len(s) - 3):
        w = s[i:i + 4]
        if len(set(w)) == 1:
            return True
        diffs = [ord(w[j + 1]) - ord(w[j]) for j in range(3)]
        if w.isalpha() and (all(d == 1 for d in diffs) or all(d == -1 for d in diffs)):
            return True
        if w.isdigit() and (all(d == 1 for d in diffs) or all(d == -1 for d in diffs)):
            return True
    return False


def placeholder_value_reason(value: str):
    """Check the key value itself (in memory only) for placeholder signs."""
    low = value.lower()
    for w in PLACEHOLDER_WORDS:
        if w in low:
            return f"key contains placeholder word {w!r}"
    if _has_sequential_run(value[-12:]):
        return "key tail has a sequential / repeated run"
    return None


def is_fixture_path(path: str) -> bool:
    low = path.lower()
    if any(m in low for m in FIXTURE_MARKERS):
        return True
    base = low.rsplit("/", 1)[-1]
    return (base.startswith("example") or base.startswith("sample")
            or base.startswith("test_") or base.startswith("fixture"))


def extension_fixture_reason(path: str):
    """Rule-extension fixture check. Returns a reason string or None."""
    low = path.lower()
    for m in EXTENSION_FIXTURE_MARKERS:
        if m in low:
            return f"rule extension: test/lesson file (matched {m!r})"
    base = low.rsplit("/", 1)[-1]
    if base.startswith("demo"):
        return "rule extension: demo file (basename starts with 'demo')"
    if base.endswith(".spec"):
        return "rule extension: spec file (basename ends with '.spec')"
    return None


def is_docs_path(path: str) -> bool:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    return base in DOC_BASENAMES or "/docs/" in low


def classify(value: str, path: str, provider: str = ""):
    """-> (class, reason). Priority: placeholder, then borderline, then real.
    Rule extensions beyond §1.2 (see FIXTURE_MARKERS and the length rule
    below) are flagged in the reason with a 'rule extension:' prefix so
    the split is auditable against the 67's method."""
    reason = placeholder_value_reason(value)
    if reason:
        return "placeholder", reason
    if is_fixture_path(path):
        return "placeholder", "file is a test fixture / example / tutorial"
    if is_docs_path(path):
        return "borderline", "random-looking key inside a documentation file"
    ext = extension_fixture_reason(path)
    if ext:
        return "placeholder", ext
    # EXTENSION: an OpenAI key shorter than 51 chars cannot be a valid key
    # (legacy minimum is 51 chars; project/service-account keys are longer).
    # The 67's OpenAI keys were 51–328 chars; 28–45-char sk-proj- strings
    # are truncated test stubs, not real keys.
    if provider == "OpenAI" and len(value) < 51:
        return "placeholder", ("rule extension: OpenAI key too short to be "
                               "valid (<51 chars; legacy minimum is 51)")
    return "real", "random-looking key in a real code / config / data file"


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def parse_github_location(loc: str):
    """'github:owner/repo/path/to/file' -> (owner, repo, path)."""
    assert loc.startswith("github:"), loc
    rest = loc[len("github:"):]
    owner, repo, path = rest.split("/", 2)
    return owner, repo, path


def fetch_raw(owner: str, repo: str, path: str):
    """Fetch current file via raw.githubusercontent.com. Tries main, then
    master. Path segments are URL-encoded (handles spaces in paths)."""
    encoded = "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/"))
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{encoded}"
        for attempt in (1, 2):
            try:
                req = urllib.request.Request(url, headers=UA)
                with urllib.request.urlopen(req, timeout=25) as resp:
                    data = resp.read(MAX_BYTES + 1)
                    if len(data) > MAX_BYTES:
                        return None, branch, "too_large"
                    return data.decode("utf-8", errors="replace"), branch, None
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    break  # try the next branch
                if attempt == 1:
                    time.sleep(2)
                    continue
                return None, branch, f"HTTP {e.code}"
            except Exception as e:  # network error etc.
                if attempt == 1:
                    time.sleep(2)
                    continue
                return None, branch, f"{type(e).__name__}: {e}"
    return None, None, "404 on main and master (file or repo gone?)"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ledger = json.load(open(LEDGER))
    trial = json.load(open(TRIAL))
    real67 = json.load(open(REAL67))

    # Fingerprints of the 67 (for overlap reporting).
    by_key = {(f["masked"], f["file"]): f for f in trial["findings"]}
    fps67 = set()
    for row in real67["keys"]:
        f = by_key.get((row["masked"], row["file"]))
        if f:
            fps67.add(f["fingerprint_sha256_16"])

    # Build targets: first fingerprint per location = new, later = rotated.
    locations = ledger["locations"]
    targets = []  # (fingerprint, location_key, provider, file, rotated)
    for loc_key, fps in locations.items():
        file_path, provider = loc_key.split("\x1f")
        for i, fp in enumerate(fps):
            targets.append({
                "fingerprint": fp,
                "location_key": loc_key,
                "provider": provider,
                "file": file_path,
                "rotated": i > 0,
            })
    print(f"Targets: {len(targets)} "
          f"({sum(1 for t in targets if not t['rotated'])} new, "
          f"{sum(1 for t in targets if t['rotated'])} rotated)")
    print(f"seen_fingerprints in ledger: {len(ledger['seen_fingerprints'])}")

    by_file = defaultdict(list)
    for t in targets:
        by_file[t["file"]].append(t)
    print(f"Unique files to fetch: {len(by_file)}")

    rows = []
    fetch_stats = Counter()
    for fi, (file_path, file_targets) in enumerate(sorted(by_file.items()), 1):
        owner, repo, path = parse_github_location(file_path)
        content, branch, error = fetch_raw(owner, repo, path)
        if content is None:
            status = "file_gone" if error and error.startswith("404") else (
                "too_large" if error == "too_large" else "fetch_failed")
            fetch_stats[status] += len(file_targets)
            for t in file_targets:
                rows.append({
                    "fingerprint": t["fingerprint"],
                    "provider": t["provider"],
                    "masked": None,
                    "file": file_path,
                    "line": None,
                    "classification": "unresolved",
                    "length": None,
                    "status": status,
                    "detail": error or "",
                    "rotated": t["rotated"],
                    "in_trial_67": t["fingerprint"] in fps67,
                    "exposed_since": None,
                })
        else:
            fetch_stats["fetched"] += 1
            # Re-run the detectors; index matches by fingerprint.
            found = {}  # fp -> (value, provider, line)
            for ln, line in enumerate(content.splitlines(), 1):
                for m in scan_line(line):
                    fp = value_hash(m.value)[:16]
                    if fp not in found:
                        found[fp] = (m.value, m.provider, ln)
            providers_present = {v[1] for v in found.values()}
            for t in file_targets:
                fp = t["fingerprint"]
                if fp in found:
                    value, det_provider, ln = found[fp]
                    cls, reason = classify(value, path, t["provider"])
                    rows.append({
                        "fingerprint": fp,
                        "provider": t["provider"],
                        "masked": mask_value(value),
                        "file": file_path,
                        "line": ln,
                        "classification": cls,
                        "length": len(value),
                        "status": "matched",
                        "detail": reason + (f"; re-detected as {det_provider}"
                                            if det_provider != t["provider"] else ""),
                        "rotated": t["rotated"],
                        "in_trial_67": fp in fps67,
                        "exposed_since": None,
                    })
                elif t["provider"] in providers_present:
                    rows.append({
                        "fingerprint": fp, "provider": t["provider"],
                        "masked": None, "file": file_path, "line": None,
                        "classification": "unresolved", "length": None,
                        "status": "key_gone",
                        "detail": "ledger key no longer in file; a different "
                                  f"same-provider key is present (branch {branch})",
                        "rotated": t["rotated"],
                        "in_trial_67": fp in fps67,
                        "exposed_since": None,
                    })
                else:
                    rows.append({
                        "fingerprint": fp, "provider": t["provider"],
                        "masked": None, "file": file_path, "line": None,
                        "classification": "unresolved", "length": None,
                        "status": "key_removed",
                        "detail": f"no {t['provider']} key in current file (branch {branch})",
                        "rotated": t["rotated"],
                        "in_trial_67": fp in fps67,
                        "exposed_since": None,
                    })
        if fi % 50 == 0:
            print(f"[{fi}/{len(by_file)}] files fetched; rows so far: {len(rows)}")
        time.sleep(PACE_SECONDS)

    print("\nFetch stats:", dict(fetch_stats))
    counts = Counter((r["classification"], r["status"]) for r in rows)
    print("Classification x status:", dict(counts))
    print("Total rows:", len(rows))
    # Checkpoint: the fetch is the slow part (~12 min for 572 files). Save
    # the rows now so a later failure in the summary phase never costs a
    # re-fetch; rows hold masked values only, never full keys.
    json.dump({"rows": rows, "fetch_stats": dict(fetch_stats)},
              open(CHECKPOINT, "w"), indent=1)
    print(f"Checkpoint written: {CHECKPOINT}")

    # ---- summaries ---------------------------------------------------------
    by_class = Counter(r["classification"] for r in rows)
    by_provider_class = defaultdict(Counter)
    for r in rows:
        by_provider_class[r["provider"]][r["classification"]] += 1
    by_status = Counter(r["status"] for r in rows)
    new_rows = [r for r in rows if not r["rotated"]]
    rotated_rows = [r for r in rows if r["rotated"]]
    real_rows = [r for r in rows if r["classification"] == "real"]
    borderline_rows = [r for r in rows if r["classification"] == "borderline"]
    real_new67 = [r for r in real_rows if not r["in_trial_67"]]

    # Length stats (lengths only, never values).
    lengths = [r["length"] for r in real_rows if r["length"]]
    length_by_provider = {}
    for p in sorted({r["provider"] for r in real_rows}):
        ls = [r["length"] for r in real_rows if r["provider"] == p and r["length"]]
        if ls:
            length_by_provider[p] = {"min": min(ls), "max": max(ls),
                                     "median": sorted(ls)[len(ls) // 2], "n": len(ls)}

    # ---- savings (existing model, same rates as the 67 report) -------------
    def _savings(rs):
        # estimate_savings needs .provider and .fingerprint (the
        # owner-verified split matches on fingerprints; with none verified
        # that side stays $0 and the candidate figures are unchanged).
        return estimate_savings([
            SimpleNamespace(provider=r["provider"], fingerprint=r["fingerprint"])
            for r in rs])

    savings_real = _savings(real_rows)
    savings_real_new67 = _savings(real_new67)
    savings_borderline = _savings(borderline_rows)
    borderline_upside_expected = savings_borderline["scenarios"]["expected"]["usage_bill_savings_usd"]

    # Per-key savings by provider (same convention as REAL_67_KEYS_SAVINGS):
    # provider scenario total / provider real-key count.
    per_key = {}
    for scenario in ("conservative", "expected", "worst_case"):
        per_key[scenario] = {}
        for p, total in savings_real["scenarios"][scenario]["by_provider_usd"].items():
            n = savings_real["by_provider"][p]
            per_key[scenario][p] = round(total / n, 2) if n else 0.0
    for r in real_rows:
        r["conservative_usd"] = per_key["conservative"].get(r["provider"], 0.0)
        r["expected_usd"] = per_key["expected"].get(r["provider"], 0.0)
        r["worst_usd"] = per_key["worst_case"].get(r["provider"], 0.0)

    # Real keys sitting in .md files (narrow docs rule) — transparency note.
    md_real = [r for r in real_rows if r["file"].lower().endswith(".md")]
    # Audit note (classification unchanged — rules use the repo-relative
    # path only, as in the 67 report): real keys whose REPO name contains
    # example/tutorial/demo/sample/test/fixture. Such repos are often
    # tutorial or demo code, so a reader can judge whether the narrow
    # fixture rule missed context.
    def _repo_name(file_path):
        parts = file_path[len("github:"):].split("/", 2)
        return parts[1] if len(parts) > 1 else ""
    _audit_words = ("example", "tutorial", "demo", "sample", "test", "fixture")
    repo_audit = [r for r in real_rows
                  if any(w in _repo_name(r["file"]).lower() for w in _audit_words)]
    overlap67 = {
        "trial_67_fingerprints_in_ledger": len(fps67 & set(ledger["seen_fingerprints"])),
        "of_which_classified_real_here": sum(
            1 for r in real_rows if r["in_trial_67"]),
        "of_which_classified_placeholder_here": sum(
            1 for r in rows if r["in_trial_67"] and r["classification"] == "placeholder"),
        "of_which_classified_borderline_here": sum(
            1 for r in rows if r["in_trial_67"] and r["classification"] == "borderline"),
        "of_which_unresolved_here": sum(
            1 for r in rows if r["in_trial_67"] and r["classification"] == "unresolved"),
    }

    ext_rows = [r for r in rows
                if r["detail"].startswith("rule extension:")]
    rules_note = (
        "Placeholder-value check: the key (in memory only) is flagged "
        "if it contains a placeholder word anywhere (fake/test/demo/"
        "example/changeme/placeholder/sample/dummy/your-api-key/xxx/…), "
        "or if its last 12 chars contain a 4-char sequential or "
        "repeated run (abcd/wxyz/7890/aaaa…). Fixture paths: /fixtures/, "
        "/tests/, /test/, .test., .spec., .env.example/.env.sample, "
        "semgrep-rules, held_out, fake_person_data, /examples/, "
        "/tutorial/, /demo/, /sample/, /mock/ and basename starts "
        "with example/sample/test_/fixture. Docs paths (narrow, per the "
        "67 reproduction): README.md, SETUP.md, USAGE.md, pr.md, or "
        "/docs/ — a blanket .md rule was NOT used, because it "
        "over-excluded real keys in the 67 reproduction. "
        "RULE EXTENSIONS beyond §1.2 (reasons flagged 'rule extension:' "
        "in per-key details): (a) _test. files (Go *_test.go / Python "
        "*_test.py) and 'lesson' paths count as fixtures; (b) basenames "
        "starting with 'demo' (demo.ipynb) and ending with '.spec' "
        "(.env.spec) count as fixtures; (c) an OpenAI key shorter than "
        "51 chars counts as placeholder (legacy minimum is 51; the 67's "
        "OpenAI keys were 51–328 chars). "
        f"In this run {len(ext_rows)} keys classify placeholder via a rule "
        f"extension; without the extensions the real count would be "
        f"{len(ext_rows)} higher. "
        "The value-word check is also stricter than the 67's suffix-only "
        "check (whole value, not just the tail), which is why "
        f"{overlap67['of_which_classified_placeholder_here']} key(s) the 67 "
        "counted real classify placeholder here.")

    out = {
        "report": "Classification of the KeySentry stress-test detections "
                  "(606 new + 54 rotated raw candidates)",
        "report_date": time.strftime("%Y-%m-%d", time.gmtime()),
        "run_at_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "source_ledger": LEDGER,
        "source_stress_log": "results/stress_log.jsonl",
        "method": (
            "For each of the 660 fingerprints in the coverage ledger, the "
            "current file was fetched from public GitHub "
            "(raw.githubusercontent.com, unauthenticated read-only, main "
            "then master) and the scanner's own detectors were re-run on "
            "the live content. A fingerprint counted as matched only on an "
            "identical SHA-256 fingerprint (first 16 hex). Matched keys "
            "were classified per results/DISCOVERY_INTELLIGENCE.md §1.2: "
            "real = random-looking key in a real code/config/data file; "
            "placeholder = key tail contains a placeholder word or a "
            "sequential/repeated run, OR the file is a test fixture / "
            "example / tutorial; borderline = random-looking key inside a "
            "documentation file (README/SETUP/USAGE, /docs/, pr.md). "
            "No key was tested against any provider. Full values exist "
            "only in memory during the run; output shows the first-4 "
            "masked form only, and records key lengths only."),
        "classification_rules_note": rules_note,
        "totals": {
            "fingerprints_in_ledger": len(ledger["seen_fingerprints"]),
            "rows": len(rows),
            "new": len(new_rows),
            "rotated": len(rotated_rows),
            "matched": by_status.get("matched", 0),
            "by_classification": dict(by_class),
            "by_status": dict(by_status),
            "new_by_classification": dict(Counter(r["classification"] for r in new_rows)),
            "rotated_by_classification": dict(Counter(r["classification"] for r in rotated_rows)),
        },
        "by_provider": {
            p: dict(by_provider_class[p]) for p in sorted(by_provider_class)
        },
        "lengths_real_keys_only": {
            "overall_min": min(lengths) if lengths else None,
            "overall_max": max(lengths) if lengths else None,
            "by_provider": length_by_provider,
        },
        "real_keys_in_md_files": len(md_real),
        "audit_real_keys_in_example_named_repos": {
            "count": len(repo_audit),
            "note": ("Real-classified keys whose REPO name contains "
                     "example/tutorial/demo/sample/test/fixture. "
                     "Classification is unchanged (rules use the repo-relative "
                     "file path only, as in the 67 report); listed so a reader "
                     "can judge whether tutorial/demo context was missed."),
            "files": sorted({r["file"] for r in repo_audit}),
        },
        "overlap_with_trial_67": overlap67,
        "savings_real_keys": savings_real,
        "savings_real_keys_not_in_trial_67": savings_real_new67,
        "borderline_upside_expected_usd": borderline_upside_expected,
        "per_key_usd_by_provider": per_key,
        "fetch_stats": dict(fetch_stats),
        "keys": rows,
    }
    json.dump(out, open(OUT_JSON, "w"), indent=1)
    print(f"Wrote {OUT_JSON}")

    # ---- Markdown ----------------------------------------------------------
    h = savings_real["headline_range_usd"]
    hn = savings_real_new67["headline_range_usd"]
    lines = []
    lines.append("# Classification — the 606 stress-test detections\n")
    lines.append(f"**Run at (UTC):** {out['run_at_utc']} | "
                 f"**Source:** `{LEDGER}` + `results/stress_log.jsonl`\n")
    lines.append("Method: every one of the 660 fingerprints in the coverage ledger "
                 "was re-checked against the live file on public GitHub "
                 "(raw.githubusercontent.com, unauthenticated read-only) with the "
                 "scanner's own detectors, matched by identical SHA-256 fingerprint "
                 "(first 16 hex), and classified per "
                 "`results/DISCOVERY_INTELLIGENCE.md` §1.2 (real / placeholder / "
                 "borderline). **No key was tested against any provider.** Masked "
                 "form is first 4 chars … rest hidden; only key lengths are recorded.\n")
    lines.append("## Headline\n")
    lines.append(f"| | Count |")
    lines.append(f"|---|---:|")
    lines.append(f"| Fingerprints in ledger | **{len(rows)}** "
                 f"({len(new_rows)} new + {len(rotated_rows)} rotated) |")
    lines.append(f"| Matched in live file | {by_status.get('matched', 0)} |")
    lines.append(f"| **Real-looking** | **{by_class.get('real', 0)}** |")
    lines.append(f"| Placeholder / test fixture | {by_class.get('placeholder', 0)} |")
    lines.append(f"| Borderline (docs context) | {by_class.get('borderline', 0)} |")
    lines.append(f"| Unresolved (gone / removed / fetch failed) | {by_class.get('unresolved', 0)} |")
    lines.append(f"| **Potential savings — {by_class.get('real', 0)} real keys** | "
                 f"**${h['conservative']:,.2f} conservative – "
                 f"${h['expected']:,.2f} expected – "
                 f"${h['worst_case']:,.2f} worst-case** |")
    lines.append(f"| of which: real keys NOT already in the trial 67 "
                 f"({len(real_new67)} keys) | ${hn['conservative']:,.2f} – "
                 f"${hn['expected']:,.2f} – ${hn['worst_case']:,.2f} |")
    lines.append(f"| Borderline upside if real (expected case) | "
                 f"+${borderline_upside_expected:,.2f} |\n")
    lines.append("## By provider × class (matched keys only; unresolved excluded)\n")
    lines.append("| Provider | Real | Placeholder | Borderline | Unresolved | Total |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for p in sorted(by_provider_class):
        c = by_provider_class[p]
        tot = sum(c.values())
        lines.append(f"| {p} | {c.get('real', 0)} | {c.get('placeholder', 0)} | "
                     f"{c.get('borderline', 0)} | {c.get('unresolved', 0)} | {tot} |")
    lines.append(f"| **Total** | **{by_class.get('real', 0)}** | "
                 f"{by_class.get('placeholder', 0)} | {by_class.get('borderline', 0)} | "
                 f"{by_class.get('unresolved', 0)} | **{len(rows)}** |\n")
    lines.append("## New vs rotated\n")
    lines.append("| | Real | Placeholder | Borderline | Unresolved | Total |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for label, subset in (("New (606)", new_rows), ("Rotated (54)", rotated_rows)):
        c = Counter(r["classification"] for r in subset)
        lines.append(f"| {label} | {c.get('real', 0)} | {c.get('placeholder', 0)} | "
                     f"{c.get('borderline', 0)} | {c.get('unresolved', 0)} | {len(subset)} |")
    lines.append("")
    lines.append("Rotated means a new fingerprint appeared at a file+provider "
                 "that already had a key — i.e. the key in that file changed "
                 "between sweeps. A rotated fingerprint is classified on its own "
                 "merits, exactly like a new one.\n")
    lines.append("## Potential savings — real keys only\n")
    lines.append("> ESTIMATE based on public pricing and documented abuse costs — "
                 "not a verified loss. No key was tested against any provider; "
                 "billing status (free tier vs paid) is unknown, and free-tier "
                 "keys would cost far less. Same model and rates as the 67-key "
                 "report (`results/DISCOVERY_INTELLIGENCE.md`).\n")
    lines.append("| Scenario | P(abuse) | Throughput | Window | Usage-bill savings | Per key |")
    lines.append("|---|---|---|---|---|---|")
    for name, label in (("conservative", "Conservative"),
                        ("expected", "Expected"),
                        ("worst_case", "Worst-case")):
        s = savings_real["scenarios"][name]
        lines.append(f"| {label} | {s['p_abuse']:.0%} | "
                     f"{s['throughput_tokens_per_day'] / 1_000_000:.0f}M tok/day | "
                     f"{s['window_days']} days | ${s['usage_bill_savings_usd']:,.2f} | "
                     f"${s['per_key_usd']:,.2f} |")
    lines.append("")
    lines.append("**Expected case, by provider:**")
    lines.append("")
    exp = savings_real["scenarios"]["expected"]["by_provider_usd"]
    for provider, amount in sorted(exp.items(), key=lambda kv: -kv[1]):
        n = savings_real["by_provider"][provider]
        lines.append(f"- {provider} ({n} key{'s' if n != 1 else ''}): ${amount:,.2f}")
    lines.append("")
    lines.append(f"Incident response (assumed $2,500 per abused key, not a sourced "
                 f"figure): ${savings_real['scenarios']['expected']['incident_response_savings_usd']:,.2f} "
                 f"in the expected case. All-in expected (usage + incident "
                 f"response): "
                 f"${savings_real['scenarios']['expected']['usage_bill_savings_usd'] + savings_real['scenarios']['expected']['incident_response_savings_usd']:,.2f}.")
    lines.append("")
    lines.append("**Candidate vs owner-verified:** the figures above are *candidate* "
                 "(potential) savings — the same model as the 67-key report. "
                 "Owner-verified savings are **$0**: none of these keys has been "
                 "confirmed live by its owner (the vault / verified-fingerprints "
                 "flow). Until an owner confirms a key, its savings stay on the "
                 "candidate side only.")
    lines.append("")
    lines.append(f"**Borderline upside:** the {by_class.get('borderline', 0)} borderline "
                 f"keys would add **+${borderline_upside_expected:,.2f}** in the "
                 f"expected case if they are real. The placeholders add $0.\n")
    lines.append("## Overlap with the trial 67\n")
    lines.append(f"**{overlap67['trial_67_fingerprints_in_ledger']} of the 67** "
                 f"re-verified real keys from trial 3 are also in this ledger "
                 f"(the stress sweep re-ran the same seed queries, so it "
                 f"re-found them). Of those, {overlap67['of_which_classified_real_here']} "
                 f"classify real again here, "
                 f"{overlap67['of_which_classified_placeholder_here']} placeholder, "
                 f"{overlap67['of_which_classified_borderline_here']} borderline, "
                 f"{overlap67['of_which_unresolved_here']} unresolved. The headline "
                 f"savings above count every real key in this batch; the "
                 f"“not in the trial 67” line is the incremental figure with no "
                 f"double-counting — use that when adding to the 67-key total.\n")
    lines.append("## Rule extensions vs the 67's method\n")
    lines.append(f"**{len(ext_rows)} keys** classify placeholder via a rule extension "
                 f"beyond `DISCOVERY_INTELLIGENCE.md` §1.2 (their per-key detail "
                 f"starts with “rule extension:”): `_test.` test files, `lesson` "
                 f"paths, `demo.*` basenames, `.spec` files, and OpenAI keys "
                 f"shorter than 51 chars (below the legacy minimum — truncated "
                 f"test stubs). Without the extensions the real count would be "
                 f"{len(ext_rows)} higher. The value-word check is also stricter "
                 f"than the 67's suffix-only check (whole value, not just the "
                 f"tail), which is why "
                 f"{overlap67['of_which_classified_placeholder_here']} key(s) the 67 "
                 f"counted real classify placeholder here.\n")
    lines.append("## Key lengths (real keys only; lengths, never values)\n")
    if lengths:
        lines.append(f"Overall: **{min(lengths)}–{max(lengths)} chars**. By provider:")
        lines.append("")
        for p, s in sorted(length_by_provider.items()):
            lines.append(f"- {p}: {s['min']}–{s['max']} chars (median {s['median']}, n={s['n']})")
        lines.append("")
    lines.append(f"{len(md_real)} real-classified key(s) sit in `.md` files. The docs "
                 f"rule is deliberately narrow (README/SETUP/USAGE, /docs/, pr.md "
                 f"only) because the 67 reproduction showed a blanket `.md` rule "
                 f"over-excludes real keys; those files are listed in the per-key "
                 f"table below so the call can be audited.\n")
    lines.append(f"**Repo-name audit:** {len(repo_audit)} real-classified key(s) sit in "
                 f"repos whose name contains example / tutorial / demo / sample / "
                 f"test / fixture. The classification rules use the repo-relative "
                 f"file path only (as in the 67 report), so these still count as "
                 f"real here — but a tutorial or demo repo is weaker evidence than "
                 f"a production codebase, so the full file list is in the JSON "
                 f"(`audit_real_keys_in_example_named_repos`) for review.\n")
    lines.append("## Unresolved — could not be verified against the live file\n")
    lines.append("| Provider | Masked | File | Status | Detail |")
    lines.append("|---|---|---|---|---|")
    unres = [r for r in rows if r["classification"] == "unresolved"]
    if not unres:
        lines.append("| — | — | none | — | — |")
    for r in unres:
        lines.append(f"| {r['provider']} | `{r['masked'] or '—'}` | {r['file']} | "
                     f"{r['status']} | {r['detail']} |")
    lines.append("")
    lines.append("Unresolved keys are NOT counted as real, placeholder, or borderline, "
                 "and contribute $0 to savings. `key_gone` means the ledger key is "
                 "no longer in the file but a different same-provider key is — the "
                 "key was rotated or the file changed since the stress run. "
                 "`key_removed` means no key of that provider remains in the file. "
                 "`file_gone` means the file (or repo) 404s on main and master. "
                 "`fetch_failed` / `too_large` are fetch problems, not evidence "
                 "about the key.\n")
    lines.append("## Per-key table (masked: first 4 … rest hidden)\n")
    lines.append("| # | Provider | Masked key | File | Class | Length | New / Rotated | Status |")
    lines.append("|---:|---|---|---|---|---:|---|---|---|")
    for i, r in enumerate(sorted(rows, key=lambda x: (x["provider"], x["file"])), 1):
        lines.append(f"| {i} | {r['provider']} | `{r['masked'] or '—'}` | {r['file']} | "
                     f"{r['classification']} | {r['length'] or '—'} | "
                     f"{'rotated' if r['rotated'] else 'new'} | {r['status']} |")
    lines.append("")
    lines.append("## Limits\n")
    lines.append("- “Real-looking” means the string matches the provider's documented "
                 "format and sits in a real file — it does not prove the key is "
                 "active, funded, or unrevoked. Some of the real keys may already "
                 "be dead. Savings are *potential*.")
    lines.append("- Billing status is unknown and unverifiable without testing a key, "
                 "which this exercise never does. Free-tier keys would cost far less.")
    lines.append("- Files were re-fetched hours after the stress run; keys that moved "
                 "or were removed in between show as unresolved, not as classified.")
    lines.append("- The classification rules are deterministic and stated in full in "
                 "the JSON (`method`, `classification_rules_note`) so the split is "
                 "reproducible from the ledger + the live files.")
    lines.append("- Exposed-since dates are not in this phase-1 file; see phase 2 "
                 "below.\n")
    open(OUT_MD, "w").write("\n".join(lines) + "\n")
    print(f"Wrote {OUT_MD}")

    # ---- verification ------------------------------------------------------
    assert len(rows) == len(ledger["seen_fingerprints"]) == 660, (
        f"row count {len(rows)} != ledger fingerprints "
        f"{len(ledger['seen_fingerprints'])}")
    assert len(new_rows) == 606 and len(rotated_rows) == 54, (
        f"new {len(new_rows)} / rotated {len(rotated_rows)} != 606 / 54")
    assert len({r["fingerprint"] for r in rows}) == 660, "duplicate fingerprints in rows"
    print("Phase-1 self-checks passed: 660 rows, 606 new, 54 rotated, "
          "all fingerprints unique.")


if __name__ == "__main__":
    main()
