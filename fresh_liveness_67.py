#!/usr/bin/env python3
"""Fresh liveness re-check for the 67 re-verified real keys (trial 3).

For each of the 67 keys, fetch the CURRENT file from public GitHub
(raw.githubusercontent.com, unauthenticated read-only, no API rate limit)
and re-run the scanner detectors on the live content. A key counts as
"still exposed" only if a detected value has the IDENTICAL SHA-256
fingerprint (first 16 hex) recorded in TRIAL_RUN_3.json.

No key is ever tested against any provider. Full values exist only in
memory during the check; all output is masked (first 5 ... rest hidden).

Usage: python3 fresh_liveness_67.py
Writes: results/FRESH_LIVENESS_67.md + .json
"""
import json
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from common import value_hash
from detectors import scan_line

TRIAL = "results/TRIAL_RUN_3.json"
REAL67 = "results/REAL_67_KEYS_SAVINGS.json"
OUT_MD = "results/FRESH_LIVENESS_67.md"
OUT_JSON = "results/FRESH_LIVENESS_67.json"

UA = {"User-Agent": "aiscan-liveness-check (read-only, public files)"}


def parse_github_location(loc: str):
    """'github:owner/repo/path/to/file' -> (owner, repo, path)."""
    assert loc.startswith("github:"), loc
    rest = loc[len("github:"):]
    owner, repo, path = rest.split("/", 2)
    return owner, repo, path


def fetch_raw(owner: str, repo: str, path: str):
    """Fetch current file content via raw.githubusercontent.com. Tries main, then master."""
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
        except Exception as e:  # network error etc.
            return None, branch, f"{type(e).__name__}: {e}"
    return None, None, "404 on main and master (file or repo gone?)"


def main():
    trial = json.load(open(TRIAL))
    real67 = json.load(open(REAL67))

    # Join the 67 (masked + file) to trial findings to get fingerprints.
    by_key = {(f["masked"], f["file"]): f for f in trial["findings"]}
    targets = []
    for row in real67["keys"]:
        f = by_key.get((row["masked"], row["file"]))
        if not f:
            print(f"WARNING: no trial finding for {row['masked']} {row['file']}")
            continue
        targets.append(f)
    print(f"Targets: {len(targets)} (of {len(real67['keys'])})")

    rows = []
    for i, f in enumerate(targets, 1):
        owner, repo, path = parse_github_location(f["file"])
        content, branch, error = fetch_raw(owner, repo, path)
        status = None
        detail = ""
        if content is None:
            status = "file_gone" if error and error.startswith("404") else "fetch_failed"
            detail = error or ""
        else:
            found_fps = set()
            found_providers = set()
            for line in content.splitlines():
                for m in scan_line(line):
                    found_fps.add(value_hash(m.value)[:16])
                    found_providers.add(m.provider)
            if f["fingerprint_sha256_16"] in found_fps:
                status = "still_exposed"
                detail = f"branch {branch}"
            elif f["provider"] in found_providers:
                status = "rotated"
                detail = f"same-provider key present, fingerprint differs (branch {branch})"
            else:
                status = "removed"
                detail = f"no {f['provider']} key in current file (branch {branch})"
        rows.append({
            "provider": f["provider"],
            "masked": f["masked"],
            "file": f["file"],
            "status": status,
            "detail": detail,
        })
        print(f"[{i}/{len(targets)}] {status:14} {f['provider']:18} {f['masked']} {f['file']}")
        time.sleep(0.3)  # be polite to raw.githubusercontent.com

    from collections import Counter
    counts = Counter(r["status"] for r in rows)
    print("\nSummary:", dict(counts))

    out = {
        "report": "Fresh liveness re-check — the 67 re-verified real keys (trial 3)",
        "run_at_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "source_trial": TRIAL,
        "method": ("For each key, fetched the current file from public GitHub "
                   "(raw.githubusercontent.com, unauthenticated read-only) and re-ran "
                   "the scanner detectors. 'still exposed' = a detected value with the "
                   "identical SHA-256 fingerprint (first 16 hex) recorded in the trial. "
                   "No key was tested against any provider."),
        "note": "Masked form is first 5 chars ... rest hidden (new masking).",
        "counts": dict(counts),
        "total": len(rows),
        "keys": rows,
    }
    json.dump(out, open(OUT_JSON, "w"), indent=1)

    lines = []
    lines.append("# Fresh liveness re-check — the 67 real keys\n")
    lines.append(f"**Run at (UTC):** {out['run_at_utc']} | **Source trial:** `{TRIAL}`\n")
    lines.append("Method: for each key, the current file was fetched from public GitHub "
                 "(raw.githubusercontent.com, unauthenticated read-only) and the scanner "
                 "detectors were re-run on the live content. A key counts as **still exposed** "
                 "only if a detected value has the identical SHA-256 fingerprint recorded in "
                 "the trial. No key was tested against any provider.\n")
    lines.append("## Summary\n")
    lines.append(f"- Still exposed: **{counts.get('still_exposed', 0)}** / {len(rows)}")
    lines.append(f"- Rotated (different same-provider key in file): {counts.get('rotated', 0)}")
    lines.append(f"- Removed: {counts.get('removed', 0)}")
    lines.append(f"- File gone (404): {counts.get('file_gone', 0)}")
    lines.append(f"- Fetch failed: {counts.get('fetch_failed', 0)}\n")
    lines.append("## Per-key results (masked: first 5 … rest hidden)\n")
    lines.append("| # | Provider | Masked key | File | Status | Detail |")
    lines.append("|---:|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        short_masked = r["masked"][:5] + "..." if "..." in r["masked"] else r["masked"]
        lines.append(f"| {i} | {r['provider']} | `{short_masked}` | {r['file']} | {r['status']} | {r['detail']} |")
    open(OUT_MD, "w").write("\n".join(lines) + "\n")
    print(f"Wrote {OUT_MD} + {OUT_JSON}")


if __name__ == "__main__":
    main()
