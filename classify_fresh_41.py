#!/usr/bin/env python3
"""Classify the 41 fresh detections from the Nov 20, 2026 10-minute
KeySentry stress run (53 queries, 40 new + 1 rotated).

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
    ("c826852ab88147ba", "Hugging Face", "github:AIAnytime/Medical-Mixture-of-Experts-LLM/MoE.ipynb"),
    ("16d0acfe45987d00", "Groq", "github:AbdallahOmran629/telegram-ai-bot/.env.txt"),
    ("e92d0779137f325a", "Groq", "github:Arshat-A/shopbot-ai/.env.txt"),
    ("1d9a92a7b2396b90", "Groq", "github:NarutoEmma/FocusFlow_Server/dotenv.env.txt"),
    ("76864be780af2909", "OpenAI", "github:Oridevformeridian/litellm-fork/tests/test_litellm/test_secret_redaction.py"),
    ("0cb8246b5c7e07ea", "Groq", "github:Plutomaster28/seadrive_assistant/AI/hf_config.txt"),
    ("555057d6146d17c5", "Groq", "github:Ritika0510/NagarSetu/.env.example.txt"),
    ("b99e642a4867e095", "OpenAI", "github:S-Sigdel/agent4/.env.example"),
    ("1f5ea10726830026", "Groq", "github:Siva9664/Time_Table_Scheduler/backend/.env.txt"),
    ("c19768ce84b68189", "Hugging Face", "github:Sssssimonk/agent_village/rag.ipynb"),
    ("cf7a6826e0a6f4e0", "Groq", "github:Vipin8171/AI-Powered-Skill-Assessment-Personalised-Learning-Plan-Agent_by-Vipin-Tomer/QUICK_START.txt"),
    ("d7dea907809cef61", "Hugging Face", "github:adrmarabuco/mineracaodenotas/hf.ipynb"),
    ("bc79012c5bc8df91", "Google Gemini", "github:ani77official-lang/Karma-/config.py"),
    ("1b7263508fd77441", "Groq", "github:anushkaSri-04/Predictive-Theft-Modelling-in-PSBs/.env.txt"),
    ("1b983a3e18fa9996", "Hugging Face", "github:bodasadallah/llm-optimized-fintuning/push.ipynb"),
    ("b9f1d19a2ef02e3c", "Groq", "github:captainlinux1337-boop/search-forge/.env.txt"),
    ("99c0326344cd7c21", "Groq", "github:cz040209/RAG-LangChain-Chatbot-Finance-/.env.txt"),
    ("45a97ea9a2382949", "Hugging Face", "github:durgaharish1993/llm-training/gpt.ipynb"),
    ("36be688f93833194", "Hugging Face", "github:hsnam95/class2024Spring/tmp.ipynb"),
    ("94ed75899258e412", "Groq", "github:jayjuk/corvid/common/.env.example.txt"),
    ("fd102f8a9934a71c", "Anthropic", "github:jayjuk/corvid/common/.env.example.txt"),
    ("65741f3ed9f6be3a", "Hugging Face", "github:kcmki/Transformers/LLM.ipynb"),
    ("f17c9bf1bb8b9c26", "Groq", "github:killo431/Ai-LM-LLAMA-STACK/.env.txt"),
    ("bc3b11fc22e1aa7a", "Groq", "github:lemanh06/bot_tele2/render.env.complete.txt"),
    ("290fb8410f355fa5", "Google Gemini", "github:mcowger/plexus/scripts/build-populate.ts"),
    ("a0b6717a23bfb058", "OpenAI", "github:mcowger/plexus/scripts/build-populate.ts"),
    ("4858df682b874d81", "Unknown (generic)", "github:pankilhas2/agente-ia-audio-pank/.env.local.txt"),
    ("11617c1a5bc30338", "Groq", "github:pankilhas2/agenteprodutora/.env.local.txt"),
    ("b21d08882edb3363", "Google Gemini", "github:pankilhas2/agenteprodutora/.env.local.txt"),
    ("b9acebefc4e92cc3", "Google Gemini", "github:pankilhas2/audio_pank/.env.local.txt"),
    ("05217b66deb3f40e", "Google Gemini", "github:pankilhas2/postcard/.env.local.txt"),
    ("be29fa1e486b65c0", "OpenAI", "github:pankilhas2/postcard/.env.local.txt"),
    ("a931ffba21e02986", "Groq", "github:pcosmo69420/pc.com/.env.local.txt"),
    ("1aba053ddc377f9d", "Anthropic", "github:pjherron/hypoc/hypoc/plugins/opencode-model-router/test/unit/scrub.test.ts"),
    ("c3882afd209f87f7", "Groq", "github:swatikotary/reasoning-guardian/.env.txt"),
    ("6e1bef94c97fb2a0", "Groq", "github:udayrastogi0531/LEGALBOT---AI-LAW-ADVISOR-CHATBOT/START_HERE.txt"),
    ("781dcded8bc29efb", "Hugging Face", "github:vardhanam/qdrant_dspy/app.ipynb"),
    ("08a534a5613f8eab", "Unknown (generic)", "github:yashpulsay-code/maihera/backend/.env.txt"),
    ("8d066ebce9ca4aad", "Unknown (generic)", "github:yashpulsay-code/maihera/backend/.env.txt"),
    ("b343ed5ca904510e", "Groq", "github:yashpulsay-code/maihera/backend/.env.txt"),
    ("c47316a2a55cf069", "Hugging Face", "github:yiz142/llm1/logit4.ipynb"),
]

OUT_MD = "results/CLASSIFY_FRESH_41.md"
OUT_JSON = "results/CLASSIFY_FRESH_41.json"
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
        "report": "Classification of the 41 fresh detections from the Nov 20, 2026 "
                  "10-minute KeySentry stress run (53 queries, 40 new + 1 rotated)",
        "report_date": time.strftime("%Y-%m-%d", time.gmtime()),
        "run_at_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "source_ledger": "results/coverage_ledger.json",
        "source_stress_log": "results/stress_log.jsonl",
        "method": (
            "For each of the 41 fresh fingerprints (isolated by diffing the "
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
    md.append("# Classification — 41 fresh detections (10-minute scan, Nov 20, 2026)\n")
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
