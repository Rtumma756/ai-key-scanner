#!/usr/bin/env python3
"""Classify the 11 fresh detections from the Nov 19, 2026 10-minute
KeySentry stress run (51 queries, 10 new + 1 rotated).

Same method as classify_stress_606.py, reusing its fetch / detect /
classify functions: for each fresh fingerprint, re-fetch the file from
public GitHub (raw.githubusercontent.com, unauthenticated read-only,
main then master), re-run the scanner detectors on the live content,
match by SHA-256 fingerprint (first 16 hex), and classify per
results/DISCOVERY_INTELLIGENCE.md §1.2 (real / placeholder-or-fixture /
borderline).

Hard boundaries (same as the 606 script):
- NEVER test any found key against any provider.
- NEVER write a full key value anywhere: full values exist only in
  memory during the run; all output uses the first-4 masked form.
- Only key lengths are recorded, never values.

Rotated rule (continuous.py): within a location's fingerprint list
(discovery order), the first fingerprint is "new"; any later one is
"rotated". The goredact specs file holds two fresh fingerprints, so
the second one there is the run's 1 rotated detection.

Usage: python3 classify_10min_11.py
Writes: results/CLASSIFY_10MIN_11.md + .json (masked only)
"""
import json
import sys
import time
from collections import Counter, defaultdict
from types import SimpleNamespace

sys.path.insert(0, "/home/hatch/workspace/ai-key-scanner")

from classify_stress_606 import parse_github_location, fetch_raw, classify
from common import mask_value, value_hash
from detectors import scan_line
from savings import estimate_savings

# (fingerprint, provider, ledger location) — isolated by diffing the
# coverage ledger against all prior reports (see /tmp/diff_fresh.py).
TARGETS = [
    ("094f4e02eb75bfb2", "Groq", "github:Prexzybooster/QUEEN-NYX-BOT/lib/groq.js"),
    ("14f6fa05c9237e84", "Groq", "github:atultiwari997721/kittyai/api/chat.js"),
    ("3419874303eb42c0", "Groq", "github:baum-ai/goredact/internal/rules/specs/ai.json"),
    ("4bb2c3ab0d2f30c6", "Groq", "github:Aless0307/daw_backend/.lh/.env.json"),
    ("6f255757e679a6de", "Groq", "github:Albaraazain/energy-analysis-app/.lh/.env.json"),
    ("937ad583f45d61b5", "OpenAI", "github:ID-Robots/clawbox/src/tests/unit/coding-openai.test.ts"),
    ("b70d9e6f244b719d", "Groq", "github:Stanristics/knowledge-assistant/config.js"),
    ("c2d75f3d4b66de0d", "Groq", "github:Anuj-Sharma01/Waypoint/SETUP.md"),
    ("c2f1fcec95fd90e0", "Groq", "github:Maahira0810/voice-sales-bot/api/chat.js"),
    ("ec2ee1c3f98a7061", "Groq", "github:baum-ai/goredact/internal/rules/specs/ai.json"),
    ("f314867895d9509c", "Groq", "github:NDilanka/envseal/packages/registry/providers/groq.json"),
]

OUT_MD = "results/CLASSIFY_10MIN_11.md"
OUT_JSON = "results/CLASSIFY_10MIN_11.json"
PACE_SECONDS = 0.25


def main():
    ledger = json.load(open("results/coverage_ledger.json"))
    locations = ledger["locations"]
    # rotated = not the first fingerprint at its location (discovery order)
    targets = []
    for fp, provider, loc in TARGETS:
        loc_key = loc + "\x1f" + provider
        idx = locations.get(loc_key, []).index(fp) if fp in locations.get(loc_key, []) else 0
        targets.append({
            "fingerprint": fp, "provider": provider, "file": loc,
            "rotated": idx > 0,
        })
    print(f"Targets: {len(targets)} "
          f"({sum(1 for t in targets if not t['rotated'])} new, "
          f"{sum(1 for t in targets if t['rotated'])} rotated)")

    by_file = defaultdict(list)
    for t in targets:
        by_file[t["file"]].append(t)
    print(f"Unique files to fetch: {len(by_file)}")

    rows = []
    fetch_stats = Counter()
    for file_path, file_targets in sorted(by_file.items()):
        owner, repo, path = parse_github_location(file_path)
        content, branch, error = fetch_raw(owner, repo, path)
        if content is None:
            status = "file_gone" if error and error.startswith("404") else (
                "too_large" if error == "too_large" else "fetch_failed")
            fetch_stats[status] += len(file_targets)
            for t in file_targets:
                rows.append({
                    "fingerprint": t["fingerprint"], "provider": t["provider"],
                    "masked": None, "file": file_path, "line": None,
                    "classification": "unresolved", "length": None,
                    "status": status, "detail": error or "",
                    "rotated": t["rotated"],
                })
        else:
            fetch_stats["fetched"] += 1
            found = {}
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
                        "fingerprint": fp, "provider": t["provider"],
                        "masked": mask_value(value), "file": file_path,
                        "line": ln, "classification": cls,
                        "length": len(value), "status": "matched",
                        "detail": reason + (f"; re-detected as {det_provider}"
                                            if det_provider != t["provider"] else ""),
                        "rotated": t["rotated"],
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
                    })
                else:
                    rows.append({
                        "fingerprint": fp, "provider": t["provider"],
                        "masked": None, "file": file_path, "line": None,
                        "classification": "unresolved", "length": None,
                        "status": "key_removed",
                        "detail": f"no {t['provider']} key in current file (branch {branch})",
                        "rotated": t["rotated"],
                    })
        time.sleep(PACE_SECONDS)

    print("Fetch stats:", dict(fetch_stats))
    by_class = Counter(r["classification"] for r in rows)
    by_status = Counter(r["status"] for r in rows)
    print("Classification:", dict(by_class))
    print("Status:", dict(by_status))

    real_rows = [r for r in rows if r["classification"] == "real"]
    savings_real = estimate_savings([
        SimpleNamespace(provider=r["provider"], fingerprint=r["fingerprint"])
        for r in real_rows])
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
    h = savings_real["headline_range_usd"]
    print(f"Savings on real keys (candidate): "
          f"${h['conservative']:,.2f} / ${h['expected']:,.2f} / ${h['worst_case']:,.2f}")

    out = {
        "report": "Classification of the 11 fresh detections from the Nov 19, 2026 "
                  "10-minute KeySentry stress run (51 queries, 10 new + 1 rotated)",
        "report_date": time.strftime("%Y-%m-%d", time.gmtime()),
        "run_at_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "source_ledger": "results/coverage_ledger.json",
        "source_stress_log": "results/stress_log.jsonl",
        "method": (
            "For each of the 11 fresh fingerprints (isolated by diffing the "
            "coverage ledger against all prior reports), the current file "
            "was fetched from public GitHub (raw.githubusercontent.com, "
            "unauthenticated read-only, main then master) and the scanner's "
            "own detectors were re-run on the live content. A fingerprint "
            "counted as matched only on an identical SHA-256 fingerprint "
            "(first 16 hex). Matched keys were classified per "
            "results/DISCOVERY_INTELLIGENCE.md §1.2: real = random-looking "
            "key in a real code/config/data file; placeholder = key contains "
            "a placeholder word or a sequential/repeated run, OR the file "
            "is a test fixture / example / tutorial; borderline = "
            "random-looking key inside a documentation file. No key was "
            "tested against any provider. Full values exist only in memory "
            "during the run; output shows the first-4 masked form only, and "
            "records key lengths only."),
        "totals": {
            "rows": len(rows),
            "new": sum(1 for r in rows if not r["rotated"]),
            "rotated": sum(1 for r in rows if r["rotated"]),
            "matched": by_status.get("matched", 0),
            "by_classification": dict(by_class),
            "by_status": dict(by_status),
        },
        "by_provider": {
            p: dict(Counter(r["classification"] for r in rows if r["provider"] == p))
            for p in sorted({r["provider"] for r in rows})
        },
        "savings_real_keys_candidate_usd": {
            "conservative": h["conservative"],
            "expected": h["expected"],
            "worst_case": h["worst_case"],
        },
        "rows": rows,
    }
    json.dump(out, open(OUT_JSON, "w"), indent=1)
    print(f"Wrote {OUT_JSON}")

    md = []
    md.append("# Classification — 11 fresh detections (10-minute scan, Nov 19, 2026)\n")
    md.append(f"Run at {out['run_at_utc']}. Method: {out['method']}\n")
    md.append("## Totals\n")
    md.append(f"- Rows: {len(rows)} "
              f"({out['totals']['new']} new, {out['totals']['rotated']} rotated)\n")
    md.append(f"- By classification: {dict(by_class)}\n")
    md.append(f"- By status: {dict(by_status)}\n")
    md.append(f"- By provider: {out['by_provider']}\n")
    md.append("## Savings on real keys (candidate figures, owner-verified $0)\n")
    md.append(f"- Conservative ${h['conservative']:,.2f} / "
              f"Expected ${h['expected']:,.2f} / "
              f"Worst-case ${h['worst_case']:,.2f}\n")
    md.append("## Per-key\n")
    md.append("| Fingerprint | Provider | File | Line | Class | Length | Masked | Detail |")
    md.append("|---|---|---|---|---|---|---|---|")
    for r in rows:
        md.append(f"| {r['fingerprint']} | {r['provider']} | {r['file']} | "
                  f"{r['line'] or '-'} | {r['classification']} | "
                  f"{r['length'] or '-'} | {r['masked'] or '-'} | "
                  f"{r['detail']} |")
    md.append("")
    open(OUT_MD, "w").write("\n".join(md))
    print(f"Wrote {OUT_MD}")


if __name__ == "__main__":
    main()
