#!/usr/bin/env python3
"""Fresh liveness re-check for ALL distinct real-looking keys found to date
(Nov 19, 2026 batches): trial 67 + stress-test 557 + 10-min scan 8 = 580
distinct fingerprints (verified union in the build step below).

Method (same as fresh_liveness_67.py / fresh_liveness_10min_8.py): for each
key, fetch the CURRENT file from public GitHub (raw.githubusercontent.com,
unauthenticated read-only, main then master) and re-run the scanner
detectors on the live content. A key counts as "still exposed" only if a
detected value has the IDENTICAL SHA-256 fingerprint (first 16 hex)
recorded in its classification report. Fetches are cached per file so
keys sharing a file cost one fetch.

No key is ever tested against any provider. Full values exist only in
memory during the check; all output is masked (first 4 ... rest hidden).

Savings: per-key conservative/expected/worst USD from the classification
reports are summed over keys still exposed (candidate estimate only —
owner-verified stays $0; see savings.py).

Usage: python3 fresh_liveness_all.py
Writes: results/FRESH_LIVENESS_ALL.md + .json
"""
import json
import sys
import time
import urllib.request
import urllib.error
from collections import Counter

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from common import value_hash
from detectors import scan_line

OUT_MD = "results/FRESH_LIVENESS_ALL.md"
OUT_JSON = "results/FRESH_LIVENESS_ALL.json"

UA = {"User-Agent": "aiscan-liveness-check (read-only, public files)"}


def parse_github_location(loc: str):
    assert loc.startswith("github:"), loc
    rest = loc[len("github:"):]
    owner, repo, path = rest.split("/", 2)
    return owner, repo, path


def fetch_raw(owner: str, repo: str, path: str):
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        req = urllib.request.Request(url, headers=UA)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.read().decode("utf-8", errors="replace"), branch, None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            return None, branch, f"HTTP {e.code}"
        except Exception as e:
            return None, branch, f"{type(e).__name__}: {e}"
    return None, None, "404 on main and master (file or repo gone?)"


def load_targets():
    """Union of real keys across the three Nov 19 batches, keyed by fingerprint."""
    targets = {}

    # Trial 67: fingerprints from TRIAL_RUN_3.json, savings from REAL_67_KEYS_SAVINGS.json
    t3 = json.load(open("results/TRIAL_RUN_3.json"))["findings"]
    tmap = {(f["masked"], f["file"]): f["fingerprint_sha256_16"] for f in t3}
    r67 = json.load(open("results/REAL_67_KEYS_SAVINGS.json"))
    rows67 = r67.get("rows", r67.get("keys", r67.get("findings", [])))
    for r in rows67:
        fp = tmap.get((r["masked"], r["file"]))
        if not fp:
            print(f"WARN: no trial fingerprint for {r['masked']} {r['file']}", file=sys.stderr)
            continue
        targets[fp] = {
            "fingerprint": fp, "provider": r["provider"], "masked": r["masked"],
            "file": r["file"], "source": "trial_67",
            "conservative_usd": r.get("conservative_usd", 0),
            "expected_usd": r.get("expected_usd", 0),
            "worst_usd": r.get("worst_usd", 0),
        }

    # Stress 606 classification: 557 real
    s = json.load(open("results/STRESS_606_CLASSIFICATION.json"))
    srows = s.get("rows", s.get("keys", s.get("findings", [])))
    for r in srows:
        if r["classification"] != "real":
            continue
        fp = r["fingerprint"]
        if fp not in targets:
            targets[fp] = {
                "fingerprint": fp, "provider": r["provider"], "masked": r["masked"],
                "file": r["file"], "source": "stress_606",
                "conservative_usd": r.get("conservative_usd", 0),
                "expected_usd": r.get("expected_usd", 0),
                "worst_usd": r.get("worst_usd", 0),
            }
        else:
            targets[fp]["source"] += "+stress_606"

    # 10-minute scan: 8 real
    m = json.load(open("results/CLASSIFY_10MIN_11.json"))
    mrows = m.get("rows", m.get("keys", m.get("findings", [])))
    for r in mrows:
        if r["classification"] != "real":
            continue
        fp = r["fingerprint"]
        if fp not in targets:
            targets[fp] = {
                "fingerprint": fp, "provider": r["provider"], "masked": r["masked"],
                "file": r["file"], "source": "scan_10min",
                "conservative_usd": r.get("conservative_usd", 0),
                "expected_usd": r.get("expected_usd", 0),
                "worst_usd": r.get("worst_usd", 0),
            }
        else:
            targets[fp]["source"] += "+scan_10min"

    return list(targets.values())


def main():
    targets = load_targets()
    print(f"Targets: {len(targets)} distinct real keys "
          f"(trial {sum(1 for t in targets if 'trial_67' in t['source'])} + "
          f"stress {sum(1 for t in targets if 'stress_606' in t['source'])} + "
          f"10min {sum(1 for t in targets if 'scan_10min' in t['source'])}, deduped by fingerprint)")

    # Group by file so one fetch serves every key in that file.
    by_file = {}
    for t in targets:
        by_file.setdefault(t["file"], []).append(t)
    print(f"Distinct files to fetch: {len(by_file)}")

    rows = []
    for i, (loc, keys) in enumerate(sorted(by_file.items()), 1):
        owner, repo, path = parse_github_location(loc)
        content, branch, error = fetch_raw(owner, repo, path)
        if content is None:
            status = "file_gone" if error and error.startswith("404") else "fetch_failed"
            for f in keys:
                rows.append({**{k: f[k] for k in ("fingerprint", "provider", "masked", "file", "source",
                                                  "conservative_usd", "expected_usd", "worst_usd")},
                             "status": status, "detail": error or ""})
            print(f"[{i}/{len(by_file)}] {status:14} {loc} ({len(keys)} keys)")
        else:
            found_fps = set()
            found_providers = set()
            for line in content.splitlines():
                for m in scan_line(line):
                    found_fps.add(value_hash(m.value)[:16])
                    found_providers.add(m.provider)
            for f in keys:
                if f["fingerprint"] in found_fps:
                    status, detail = "still_exposed", f"branch {branch}"
                elif f["provider"] in found_providers:
                    status, detail = "rotated", f"same-provider key present, fingerprint differs (branch {branch})"
                else:
                    status, detail = "removed", f"no {f['provider']} key in current file (branch {branch})"
                rows.append({**{k: f[k] for k in ("fingerprint", "provider", "masked", "file", "source",
                                                  "conservative_usd", "expected_usd", "worst_usd")},
                             "status": status, "detail": detail})
            n_live = sum(1 for f in keys if f["fingerprint"] in found_fps)
            print(f"[{i}/{len(by_file)}] fetched {loc}: {n_live}/{len(keys)} still exposed")
        time.sleep(0.2)

    counts = Counter(r["status"] for r in rows)
    print("\nSummary:", dict(counts))

    live = [r for r in rows if r["status"] == "still_exposed"]
    savings = {
        "conservative_usd": round(sum(r["conservative_usd"] for r in live), 2),
        "expected_usd": round(sum(r["expected_usd"] for r in live), 2),
        "worst_usd": round(sum(r["worst_usd"] for r in live), 2),
    }
    print("Savings on still-exposed keys (candidate estimate):", savings)
    by_provider = {}
    for r in live:
        by_provider.setdefault(r["provider"], [0, 0.0, 0.0, 0.0])
        by_provider[r["provider"]][0] += 1
        by_provider[r["provider"]][1] += r["conservative_usd"]
        by_provider[r["provider"]][2] += r["expected_usd"]
        by_provider[r["provider"]][3] += r["worst_usd"]
    for p, v in sorted(by_provider.items(), key=lambda kv: -kv[1][2]):
        print(f"  {p}: {v[0]} keys  cons ${v[1]:,.2f}  exp ${v[2]:,.2f}  worst ${v[3]:,.2f}")

    out = {
        "report": "Fresh liveness re-check — all 580 distinct real keys found Nov 19, 2026",
        "run_at_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "sources": ["results/REAL_67_KEYS_SAVINGS.json (+ TRIAL_RUN_3.json fingerprints)",
                    "results/STRESS_606_CLASSIFICATION.json",
                    "results/CLASSIFY_10MIN_11.json"],
        "method": ("For each key, fetched the CURRENT file from public GitHub "
                   "(raw.githubusercontent.com, unauthenticated read-only, main then "
                   "master) and re-ran the scanner detectors. 'still exposed' = a "
                   "detected value with the identical SHA-256 fingerprint (first 16 hex) "
                   "recorded in the classification report. Fetches cached per file. "
                   "No key was tested against any provider."),
        "note": ("Masked form is first 4 chars ... rest hidden. Savings are the "
                 "candidate estimate from savings.py (aiscan-savings-v1) summed over "
                 "still-exposed keys only; owner-verified savings remain $0 — no "
                 "found key has been confirmed live-and-owned by its owner."),
        "counts": dict(counts),
        "total": len(rows),
        "still_exposed": len(live),
        "savings_still_exposed_candidate_usd": savings,
        "savings_by_provider_still_exposed": {
            p: {"keys": v[0], "conservative_usd": round(v[1], 2),
                "expected_usd": round(v[2], 2), "worst_usd": round(v[3], 2)}
            for p, v in sorted(by_provider.items(), key=lambda kv: -kv[1][2])
        },
        "keys": rows,
    }
    json.dump(out, open(OUT_JSON, "w"), indent=1)

    lines = []
    lines.append("# Fresh liveness re-check — all 580 distinct real keys (Nov 19 batches)\n")
    lines.append(f"**Run at (UTC):** {out['run_at_utc']}\n")
    lines.append("Method: for each key, the current file was fetched from public GitHub "
                 "(raw.githubusercontent.com, unauthenticated read-only) and the scanner "
                 "detectors were re-run on the live content. A key counts as **still exposed** "
                 "only if a detected value has the identical SHA-256 fingerprint recorded in "
                 "its classification report. No key was tested against any provider.\n")
    lines.append("## Summary\n")
    lines.append(f"- Still exposed: **{counts.get('still_exposed', 0)}** / {len(rows)}")
    lines.append(f"- Rotated (different same-provider key in file): {counts.get('rotated', 0)}")
    lines.append(f"- Removed: {counts.get('removed', 0)}")
    lines.append(f"- File gone (404): {counts.get('file_gone', 0)}")
    lines.append(f"- Fetch failed: {counts.get('fetch_failed', 0)}\n")
    lines.append("## Savings on still-exposed keys (candidate estimate)\n")
    lines.append("Candidate estimate only — the savings model from `savings.py` "
                 "(aiscan-savings-v1) summed over still-exposed keys. Owner-verified "
                 "savings remain **$0**: no found key has been confirmed live-and-owned "
                 "by its owner, and no key was tested against any provider.\n")
    lines.append(f"- Conservative: **${savings['conservative_usd']:,.2f}**")
    lines.append(f"- Expected: **${savings['expected_usd']:,.2f}**")
    lines.append(f"- Worst case: **${savings['worst_usd']:,.2f}**\n")
    lines.append("### By provider (still exposed)\n")
    lines.append("| Provider | Keys | Conservative | Expected | Worst case |")
    lines.append("|---|---:|---:|---:|---:|")
    for p, v in sorted(by_provider.items(), key=lambda kv: -kv[1][2]):
        lines.append(f"| {p} | {v[0]} | ${v[1]:,.2f} | ${v[2]:,.2f} | ${v[3]:,.2f} |")
    lines.append("")
    lines.append("## Per-key results (masked: first 4 … rest hidden)\n")
    lines.append("| # | Provider | Masked key | File | Status | Detail |")
    lines.append("|---:|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        lines.append(f"| {i} | {r['provider']} | `{r['masked']}` | {r['file']} | {r['status']} | {r['detail']} |")
    open(OUT_MD, "w").write("\n".join(lines) + "\n")
    print(f"Wrote {OUT_MD} + {OUT_JSON}")


if __name__ == "__main__":
    main()
