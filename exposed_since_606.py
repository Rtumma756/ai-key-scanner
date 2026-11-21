#!/usr/bin/env python3
"""Phase 2 (best-effort): "exposed since" dates for a sample of the real
keys classified in results/STRESS_606_CLASSIFICATION.json.

Method: for each sampled file, GitHub API (unauthenticated, read-only)
  GET /repos/{owner}/{repo}/commits?path={path}&per_page=1
  -> the Link header's rel="last" page number N is the count of commits
     touching the file; then GET the same with page=N and take the last
     item, which is the EARLIEST commit touching the file.
Two API calls per file. Unauthenticated core limit is 60/hour; the script
checks X-RateLimit-Remaining after every call and stops (documenting it)
rather than burning the quota. No key is tested against any provider;
only commit dates/shas are recorded.

IMPORTANT LIMIT: the earliest commit touching the FILE is the earliest
date the key could have been exposed — the key itself may have been added
in a later commit. Treat it as the earliest possible exposure date, not
the confirmed introduction date. Proving introduction would need a
per-commit content search, which is out of scope here.

Usage: python3 exposed_since_606.py [--sample N] [--out JSON]
Default sample: 20 real keys, stratified by provider, preferring keys
NOT already in the trial 67 and distinct repos.
Writes: updates results/STRESS_606_CLASSIFICATION.json (exposed_since on
sampled rows + a phase2 block) and the .md (adds an "Exposed since"
section, replaces the phase-1 placeholder line).
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])

CLS_JSON = "results/STRESS_606_CLASSIFICATION.json"
CLS_MD = "results/STRESS_606_CLASSIFICATION.md"

UA = {"User-Agent": "aiscan-exposed-since (read-only, public GitHub API)"}
PACE_SECONDS = 2.0
MIN_REMAINING = 5  # stop sampling if the API quota falls below this


def parse_github_location(loc: str):
    assert loc.startswith("github:"), loc
    rest = loc[len("github:"):]
    owner, repo, path = rest.split("/", 2)
    return owner, repo, path


def api_get(url: str):
    """GET a GitHub API URL. Returns (parsed_json, headers_dict, error)."""
    req = urllib.request.Request(url, headers={**UA, "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.loads(resp.read().decode("utf-8")), dict(resp.headers), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            body = ""
        return None, dict(e.headers), f"HTTP {e.code}: {body}"
    except Exception as e:
        return None, {}, f"{type(e).__name__}: {e}"


def last_page_from_link(headers: dict):
    """Parse the Link header for rel=\"last\" page number; None if absent."""
    link = headers.get("Link") or headers.get("link") or ""
    for part in link.split(","):
        if 'rel="last"' in part:
            url = part.split(";")[0].strip().strip("<>")
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            try:
                return int(qs["page"][0])
            except (KeyError, ValueError, IndexError):
                return None
    return None


def earliest_commit(owner: str, repo: str, path: str):
    """Return (result_dict, remaining_quota, error). Two API calls max."""
    enc_path = urllib.parse.quote(path, safe="/")
    base = (f"https://api.github.com/repos/{owner}/{repo}/commits"
            f"?path={enc_path}&per_page=1")
    data, headers, err = api_get(base)
    remaining = headers.get("X-RateLimit-Remaining") or headers.get("x-ratelimit-remaining")
    try:
        remaining = int(remaining) if remaining is not None else None
    except ValueError:
        remaining = None
    if err:
        return None, remaining, err
    if not data:
        return None, remaining, "no commits touching this path (empty?)"
    last = last_page_from_link(headers)
    if last is None or last <= 1:
        earliest = data[-1]
        return {
            "date": earliest["commit"]["author"]["date"],
            "sha": earliest["sha"][:7],
            "commits_touching_file": len(data),
            "message": earliest["commit"]["message"].splitlines()[0][:100],
        }, remaining, None
    # Fetch the last page; its last item is the earliest commit.
    time.sleep(PACE_SECONDS)
    data2, headers2, err2 = api_get(base + f"&page={last}")
    remaining2 = headers2.get("X-RateLimit-Remaining") or headers2.get("x-ratelimit-remaining")
    try:
        remaining2 = int(remaining2) if remaining2 is not None else remaining
    except ValueError:
        remaining2 = remaining
    if err2:
        return None, remaining2, err2
    if not data2:
        return None, remaining2, f"last page ({last}) came back empty"
    earliest = data2[-1]
    return {
        "date": earliest["commit"]["author"]["date"],
        "sha": earliest["sha"][:7],
        "commits_touching_file": last,  # per_page=1, so last page == count
        "message": earliest["commit"]["message"].splitlines()[0][:100],
    }, remaining2, None


def pick_sample(real_rows, n: int):
    """Stratified sample: cap per provider, prefer keys NOT in the trial 67
    and distinct repos. Returns a list of rows."""
    # Target shares (cap per provider; total <= n).
    caps = {"Google Gemini": 8, "OpenAI": 4, "Anthropic": 3, "OpenRouter": 2,
            "Groq": 1, "Perplexity": 1, "Hugging Face": 1, "xAI": 1,
            "DeepSeek": 1, "Unknown (generic)": 1}
    by_provider = defaultdict(list)
    for r in real_rows:
        by_provider[r["provider"]].append(r)
    # Within a provider: non-67 first, then spread across repos.
    sample = []
    for provider, rows in by_provider.items():
        rows.sort(key=lambda r: (r["in_trial_67"], r["file"]))
        seen_repos = set()
        picked = []
        for r in rows:
            if len(picked) >= caps.get(provider, 1):
                break
            repo = r["file"].split("/", 2)[1] if r["file"].count("/") >= 1 else r["file"]
            if repo in seen_repos:
                continue
            seen_repos.add(repo)
            picked.append(r)
        sample.extend(picked)
    # If still short of n (small providers), fill from remaining rows.
    if len(sample) < n:
        chosen = {r["fingerprint"] for r in sample}
        rest = [r for r in real_rows if r["fingerprint"] not in chosen]
        rest.sort(key=lambda r: (r["in_trial_67"], r["file"]))
        sample.extend(rest[:n - len(sample)])
    return sample[:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=20)
    args = ap.parse_args()

    data = json.load(open(CLS_JSON))
    rows = data["keys"]
    real_rows = [r for r in rows if r["classification"] == "real"]
    print(f"Real keys: {len(real_rows)}; sampling {args.sample}")
    sample = pick_sample(real_rows, args.sample)
    print(f"Sampled {len(sample)} rows across providers: "
          f"{dict(__import__('collections').Counter(r['provider'] for r in sample))}")

    results = []
    stopped_reason = None
    for i, r in enumerate(sample, 1):
        owner, repo, path = parse_github_location(r["file"])
        res, remaining, err = earliest_commit(owner, repo, path)
        if err:
            results.append({"fingerprint": r["fingerprint"], "provider": r["provider"],
                            "file": r["file"], "exposed_since": None,
                            "error": err, "remaining_quota": remaining})
            print(f"[{i}/{len(sample)}] ERROR {r['provider']:16} {r['file'][:60]}: {err}")
        else:
            results.append({"fingerprint": r["fingerprint"], "provider": r["provider"],
                            "file": r["file"], "exposed_since": res,
                            "error": None, "remaining_quota": remaining})
            print(f"[{i}/{len(sample)}] {res['date'][:10]} {r['provider']:16} "
                  f"{r['file'][:60]} (quota left: {remaining})")
        if remaining is not None and remaining < MIN_REMAINING:
            stopped_reason = (f"stopped early: GitHub API quota down to "
                              f"{remaining} (floor {MIN_REMAINING})")
            print(stopped_reason)
            break
        time.sleep(PACE_SECONDS)

    ok = [x for x in results if x["exposed_since"]]
    by_fp = {x["fingerprint"]: x for x in results}
    for r in rows:
        if r["fingerprint"] in by_fp and by_fp[r["fingerprint"]]["exposed_since"]:
            r["exposed_since"] = by_fp[r["fingerprint"]]["exposed_since"]

    dates = sorted(x["exposed_since"]["date"][:10] for x in ok)
    data["phase2_exposed_since"] = {
        "method": (
            "For each sampled file: GitHub API (unauthenticated, read-only) "
            "GET /repos/{owner}/{repo}/commits?path={path}&per_page=1 — the "
            "Link header's rel=\"last\" page is the number of commits "
            "touching the file; the last item of that page is the earliest "
            "commit touching the file. Two API calls per file at most. "
            "LIMIT: the earliest commit touching the FILE is the earliest "
            "date the key could have been exposed; the key itself may have "
            "been added in a later commit, so treat it as the earliest "
            "possible exposure date, not the confirmed introduction date."),
        "sample_design": (
            f"Stratified sample of {len(sample)} real-classified keys "
            f"(caps: Gemini 8, OpenAI 4, Anthropic 3, OpenRouter 2, 1 each "
            f"for the rest), preferring keys NOT already in the trial 67 "
            f"and distinct repos."),
        "sampled": len(sample),
        "resolved": len(ok),
        "failed": len(results) - len(ok),
        "stopped_reason": stopped_reason,
        "earliest_date_in_sample": dates[0] if dates else None,
        "latest_date_in_sample": dates[-1] if dates else None,
        "dates": dates,
        "results": results,
    }
    json.dump(data, open(CLS_JSON, "w"), indent=1)
    print(f"Updated {CLS_JSON}: {len(ok)}/{len(results)} resolved; "
          f"dates {dates[0] if dates else '—'} .. {dates[-1] if dates else '—'}")

    # ---- Markdown: replace the phase-1 placeholder line, add a section ----
    md = open(CLS_MD).read()
    placeholder = ("- Exposed-since dates are not in this phase-1 file; see phase 2\n"
                   "  below.\n")
    section = ["## Exposed since (phase 2 — sample)\n"]
    section.append(f"Sample of **{len(ok)}** real keys resolved "
                   f"({len(results) - len(ok)} failed"
                   f"{'; ' + stopped_reason if stopped_reason else ''}). "
                   f"Earliest possible exposure in the sample: "
                   f"**{dates[0] if dates else '—'}** to "
                   f"**{dates[-1] if dates else '—'}**. Method: earliest commit "
                   f"touching the file via the GitHub API (unauthenticated, "
                   f"read-only). **Limit: this is the earliest the key *could* "
                   f"have been exposed — the key may have been added in a later "
                   f"commit, so it is an earliest-possible date, not a confirmed "
                   f"introduction date.**\n")
    section.append("| Provider | Masked key | File | Earliest commit touching file |")
    section.append("|---|---|---| --- |")
    for x in sorted(ok, key=lambda z: z["exposed_since"]["date"]):
        row = next(r for r in rows if r["fingerprint"] == x["fingerprint"])
        section.append(f"| {x['provider']} | `{row['masked']}` | {x['file']} | "
                       f"{x['exposed_since']['date'][:10]} "
                       f"(`{x['exposed_since']['sha']}`, "
                       f"{x['exposed_since']['commits_touching_file']} commit(s) touching file) |")
    if len(results) - len(ok):
        section.append("")
        section.append("Unresolved in the sample:")
        section.append("")
        for x in results:
            if not x["exposed_since"]:
                section.append(f"- {x['provider']} — {x['file']}: {x['error']}")
    section.append("")
    section_text = "\n".join(section) + "\n"
    if placeholder in md:
        md = md.replace(placeholder, section_text)
    else:
        md = md.rstrip("\n") + "\n\n" + section_text
    open(CLS_MD, "w").write(md)
    print(f"Updated {CLS_MD}")


if __name__ == "__main__":
    main()
