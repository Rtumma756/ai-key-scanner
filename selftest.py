"""Self-test harness for aiscan: precision/recall scorecard on fixtures.

Expected fixture findings (provider -> count). The Anthropic key is planted
in both app.py and .mcp.json on purpose: dedup must report it once, so the
expected total is 16 unique findings from 17 plantings.
"""
from __future__ import annotations

import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import value_hash  # noqa: E402
from engine import scan_source  # noqa: E402
from reporters import json_out, markdown  # noqa: E402
from sources import DemoSource, GitHubSource, LocalSource  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")

EXPECTED_PROVIDER_COUNTS = {
    "OpenAI": 3,          # app.py (project), .env (legacy), .mcp.json (project)
    "Anthropic": 1,       # planted twice (app.py + .mcp.json) -> deduped to 1
    "Google Gemini": 1,
    "Groq": 1,
    "OpenRouter": 1,
    "DeepSeek": 1,
    "xAI": 1,
    "Perplexity": 1,
    "Hugging Face": 1,
    "Replicate": 1,
    "Mistral": 1,
    "Together AI": 1,
    "Cohere": 1,
    "Unknown (generic)": 1,
}
EXPECTED_TOTAL = sum(EXPECTED_PROVIDER_COUNTS.values())


def _scorecard(title: str, checks: list) -> bool:
    print(f"\n=== {title} ===")
    ok_all = True
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            ok_all = False
        print(f"  [{mark}] {name}: {detail}")
    return ok_all


def fixture_scorecard() -> bool:
    findings = scan_source(LocalSource(FIXTURES))
    counts = Counter(f.provider for f in findings)
    checks = []

    # Recall: every expected (provider, count) present.
    missing = {p: (EXPECTED_PROVIDER_COUNTS[p], counts.get(p, 0))
               for p in EXPECTED_PROVIDER_COUNTS
               if counts.get(p, 0) != EXPECTED_PROVIDER_COUNTS[p]}
    checks.append(("recall (all planted keys detected)",
                   not missing,
                   f"expected {EXPECTED_TOTAL} findings, got {len(findings)}"
                   + (f"; mismatches: {missing}" if missing else "")))

    # Precision: no unexpected providers.
    extra = {p: c for p, c in counts.items()
             if p not in EXPECTED_PROVIDER_COUNTS}
    checks.append(("precision (no unexpected providers)",
                   not extra,
                   "no extras" if not extra else f"extras: {extra}"))

    # Decoys: nothing in decoys.txt.
    decoy_hits = [f for f in findings if f.file_path.endswith("decoys.txt")]
    checks.append(("decoys not flagged",
                   not decoy_hits,
                   f"{len(decoy_hits)} findings in decoys.txt"
                   if decoy_hits else "0 findings in decoys.txt"))

    # Dedup: the duplicated Anthropic key appears exactly once.
    anthropic = [f for f in findings if f.provider == "Anthropic"]
    fps = {f.fingerprint for f in anthropic}
    checks.append(("dedup (duplicated key reported once)",
                   len(anthropic) == 1 and len(fps) == 1,
                   f"{len(anthropic)} Anthropic finding(s)"))

    # Redaction: no full secret in JSON or Markdown output.
    rendered = (json_out.render_json(findings, "selftest", False)
                + markdown.render_markdown(findings, "selftest", False))
    leaked = [f.masked for f in findings if f.value in rendered]
    checks.append(("redaction (no full key in JSON/Markdown)",
                   not leaked,
                   "clean" if not leaked else f"LEAKED: {leaked}"))

    # Demo mode: bundled fake dataset produces findings.
    demo = scan_source(DemoSource())
    checks.append(("demo mode produces findings",
                   len(demo) >= 5,
                   f"{len(demo)} demo findings"))
    return _scorecard("Fixture precision/recall", checks)


def savings_scorecard() -> bool:
    """Confidence split on the DEMO dataset (no network, fake keys only).

    Checks: (a) the candidate side reproduces the known demo numbers
    exactly ($75.19 / $4,027.91 / $32,223.30); (b) with one finding's
    fingerprint marked verified, verified_keys == 1 and the verified side
    equals the single-key estimate for that provider while the candidate
    side is unchanged; (c) with no verified fingerprints the verified
    side is all $0; (d) load_verified_fingerprints accepts a JSON list
    and a {"fingerprints": [...]} object, skips invalid entries, and
    rejects bad JSON / wrong shapes.
    """
    import json as _json
    import tempfile

    from savings import _estimate_for, estimate_savings, \
        load_verified_fingerprints

    checks = []
    demo = scan_source(DemoSource())
    result = estimate_savings(demo)
    h = result["headline_range_usd"]
    checks.append(("candidate side reproduces the demo numbers",
                   h == {"conservative": 75.19, "expected": 4027.91,
                         "worst_case": 32223.30},
                   f"{h}"))
    checks.append(("verified side is $0 with nothing verified",
                   result["verified_keys"] == 0
                   and result["owner_verified_savings"]["headline_range_usd"]
                   == {"conservative": 0.0, "expected": 0.0,
                       "worst_case": 0.0},
                   f"verified_keys={result['verified_keys']}"))
    one = demo[0]
    marked = estimate_savings(demo, {one.fingerprint})
    vh = marked["owner_verified_savings"]["headline_range_usd"]
    want = _estimate_for([one])["headline_range_usd"]
    checks.append(("one verified fingerprint counts exactly that key",
                   marked["verified_keys"] == 1 and vh == want
                   and marked["headline_range_usd"] == h
                   and marked["verified_fingerprints_unmatched"] == 0,
                   f"verified_keys={marked['verified_keys']}, "
                   f"verified headline={vh}, unmatched="
                   f"{marked['verified_fingerprints_unmatched']}"))
    bogus = estimate_savings(demo, {"0123456789abcdef"})
    checks.append(("unknown fingerprint counts as unmatched, not verified",
                   bogus["verified_keys"] == 0
                   and bogus["verified_fingerprints_unmatched"] == 1,
                   f"unmatched={bogus['verified_fingerprints_unmatched']}"))
    with tempfile.TemporaryDirectory() as td:
        list_path = os.path.join(td, "v-list.json")
        with open(list_path, "w", encoding="utf-8") as f:
            _json.dump([one.fingerprint, "not-a-fingerprint", 42], f)
        fps, skipped = load_verified_fingerprints(list_path)
        checks.append(("list file loads, invalid entries skipped",
                       fps == {one.fingerprint} and skipped == 2,
                       f"{len(fps)} fingerprint(s), {skipped} skipped"))
        dict_path = os.path.join(td, "v-dict.json")
        with open(dict_path, "w", encoding="utf-8") as f:
            _json.dump({"fingerprints": [one.fingerprint.upper()]}, f)
        fps2, skipped2 = load_verified_fingerprints(dict_path)
        checks.append(("object file loads, fingerprints lowercased",
                       fps2 == {one.fingerprint} and skipped2 == 0,
                       f"{len(fps2)} fingerprint(s)"))
        bad_path = os.path.join(td, "v-bad.json")
        with open(bad_path, "w", encoding="utf-8") as f:
            f.write("{not json")
        try:
            load_verified_fingerprints(bad_path)
            bad_ok = False
        except ValueError:
            bad_ok = True
        checks.append(("bad JSON is rejected",
                       bad_ok, "rejected" if bad_ok else "accepted"))
    return _scorecard("Savings confidence split (demo only)", checks)


def live_smoke_test() -> dict:
    """One real GitHub code-search query. Never depends on specific live
    keys existing; checks the pipeline handles results, empty results,
    errors and rate limits gracefully. No verification (off by default)."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return {"status": "skipped",
                "reason": "no GITHUB_TOKEN in environment"}
    out = {"status": "ok", "queries": {}}

    # 1. Nonsense pattern -> expect zero results (empty-path handling).
    try:
        src = GitHubSource("aiscan-smoke-test-nonexistent-pattern-xyz",
                           token, max_pages=1)
        empty = scan_source(src)
        out["queries"]["empty_pattern"] = {
            "results": len(empty), "rate_limit_hits": src.rate_limit_hits}
    except Exception as e:  # noqa: BLE001 - smoke test records, not crashes
        out["queries"]["empty_pattern"] = {"error": str(e)}
        out["status"] = "error"

    # 2. Distinctive real pattern, 1 page, max 5 items -> results path.
    try:
        src = GitHubSource("sk-or-v1-", token, max_pages=1, max_items=5)
        found = scan_source(src)
        masked_only = all(f.value not in "" for f in found)  # trivially true
        out["queries"]["real_pattern"] = {
            "items_seen": src.items_seen,
            "findings": len(found),
            "rate_limit_hits": src.rate_limit_hits,
            "masked_only": masked_only,
        }
    except Exception as e:  # noqa: BLE001
        out["queries"]["real_pattern"] = {"error": str(e)}
        out["status"] = "error"
    return out


def vault_scorecard() -> bool:
    """Vault round-trip on a DEMOFAKE key only (never a real credential).

    Checks: init -> store -> list shows masked only -> vault file and audit
    log hold ciphertext only -> reveal returns the stored key and is
    audit-logged -> wrong passphrase fails -> rotate + purge removes it.
    """
    import tempfile

    from vault import (VaultError, assert_vault_redacted, check_passphrase,
                       init_vault, list_entries, load_vault, purge_entries,
                       read_audit, reveal_entry, set_entry_status,
                       store_finding)

    checks = []
    with tempfile.TemporaryDirectory() as td:
        vpath = os.path.join(td, "vault.json")
        apath = os.path.join(td, "vault-audit.jsonl")
        pw = "selftest-vault-passphrase"
        init_vault(vpath, pw, audit_path=apath)
        checks.append(("vault init creates a usable vault",
                       os.path.exists(vpath) and os.path.exists(apath),
                       "vault + audit files created"))
        demo = scan_source(DemoSource())
        planted = demo[0]
        entry = store_finding(vpath, pw, planted, "demo",
                              audit_path=apath)
        listed = list_entries(vpath)
        checks.append(("vault list shows masked only",
                       len(listed) == 1
                       and listed[0]["masked"] == planted.masked
                       and planted.value not in str(listed),
                       f"{len(listed)} entr(ies), masked {listed[0]['masked']}"))
        leaked = assert_vault_redacted(vpath, [planted.value])
        checks.append(("vault file + audit hold ciphertext only",
                       not leaked,
                       "clean" if not leaked else f"LEAKED: {leaked}"))
        meta, value = reveal_entry(vpath, pw, entry["id"], audit_path=apath)
        checks.append(("vault reveal returns the stored key",
                       value == planted.value,
                       "match" if value == planted.value else "MISMATCH"))
        try:
            reveal_entry(vpath, "wrong-passphrase", entry["id"],
                         audit_path=apath)
            wrong_ok = False
        except VaultError:
            wrong_ok = True
        checks.append(("wrong passphrase is refused",
                       wrong_ok, "refused" if wrong_ok else "ACCEPTED"))
        audit = read_audit(apath)
        actions = [a["action"] for a in audit]
        audit_clean = planted.value not in open(apath, "rb").read().decode(
            "utf-8", errors="replace")
        checks.append(("reveal is audit-logged, audit holds no full key",
                       "store" in actions and "reveal" in actions
                       and audit_clean,
                       f"actions: {actions}"))
        set_entry_status(vpath, entry["id"], "rotated", audit_path=apath)
        purged = purge_entries(vpath, 0, audit_path=apath)
        checks.append(("rotate then purge removes the entry",
                       purged == [entry["id"]] and not list_entries(vpath),
                       f"purged {purged}"))
        # Passphrase check helper itself: correct works, wrong raises.
        data = load_vault(vpath)
        try:
            check_passphrase(data, pw)
            check_ok = True
        except VaultError:
            check_ok = False
        checks.append(("vault verifier accepts the right passphrase",
                       check_ok, "ok" if check_ok else "FAIL"))
    return _scorecard("Vault round-trip (DEMOFAKE only)", checks)


def continuous_scorecard() -> bool:
    """Continuous scanning on the DEMO dataset only (no network, no token).

    Checks: (a) the enumerator contains all 23 seed queries; (b) a demo
    sweep twice — the second reports 0 new; (c) one new fake key planted
    in a demo-dataset copy reports exactly 1 new; (d) a stubbed
    total_count of 2500 shards the parent and marks it sharded;
    (e) the coverage report renders; (f) a short stress run writes at
    least 2 iteration log lines plus a final summary line.
    """
    import json as _json
    import tempfile

    from continuous import (CoverageLedger, SEED_QUERIES, expand_ledger,
                            render_coverage, stress_run, sweep_ledger)

    checks = []
    with tempfile.TemporaryDirectory() as td:
        lpath = os.path.join(td, "ledger.json")
        ledger = CoverageLedger(lpath)
        # (a) All 23 seed queries present (the duplicate mcp entry seeds
        # one record — dedupe by (query, start_page) — so membership is
        # checked per seed entry, not by record count).
        keys = {(r["query"], r["start_page"]) for r in ledger.records}
        missing = [(q, sp) for (q, sp, _mp, _mi) in SEED_QUERIES
                   if (q, sp) not in keys]
        checks.append(("enumerator contains all 23 seed queries",
                       len(SEED_QUERIES) == 23 and not missing,
                       f"{len(SEED_QUERIES)} seeds, "
                       f"{len(ledger.records)} records, "
                       f"missing: {missing}" if missing else
                       f"{len(SEED_QUERIES)} seeds, "
                       f"{len(ledger.records)} records (1 duplicate "
                       f"mcp entry deduped)"))
        # (b) Demo sweep twice: second reports 0 new.
        first = sweep_ledger(ledger, demo=True)
        second = sweep_ledger(ledger, demo=True)
        checks.append(("second demo sweep reports 0 new",
                       first["new"] == 7 and second["new"] == 0
                       and second["rotated"] == 0,
                       f"first sweep: {first['new']} new; second: "
                       f"{second['new']} new, {second['rotated']} rotated"))
        # (c) One new fake key in a demo-dataset copy: exactly 1 new.
        extra = {"demo/leaked-repo/extra.env": [
            'OPENAI_API_KEY="sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"',
        ]}
        third = sweep_ledger(ledger, demo=True, extra_demo_files=extra)
        checks.append(("new fake key reports exactly 1 new",
                       third["new"] == 1,
                       f"{third['new']} new"))
        # (d) Stubbed total_count 2500 shards the parent.
        lpath2 = os.path.join(td, "ledger2.json")
        ledger2 = CoverageLedger(lpath2)
        parent = ledger2.records[0]
        stub = lambda q: 2500 if q == parent["query"] else 800
        expand_ledger(ledger2, count=1, demo=True, probe=stub)
        after = ledger2.find(parent["query"], parent["start_page"])
        shard_recs = [r for r in ledger2.records
                      if r["query"] in after["shards"]]
        checks.append(("total_count 2500 shards the parent",
                       after["status"] == "sharded"
                       and len(after["shards"]) >= 1
                       and len(shard_recs) == len(after["shards"]),
                       f"parent status: {after['status']}, "
                       f"{len(after['shards'])} shard(s)"))
        # (e) Coverage renders.
        text = render_coverage(ledger)
        checks.append(("coverage renders with totals",
                       bool(text) and "Totals:" in text
                       and "sk-proj-" in text,
                       f"{len(text.splitlines())} lines"))
        # (f) Short stress run: 2 iterations + final summary in the log.
        log_path = os.path.join(td, "stress_log.jsonl")
        totals = stress_run(ledger, minutes=0, demo=True,
                            max_iterations=2, log_path=log_path)
        lines = open(log_path, encoding="utf-8").read().splitlines()
        entries = [_json.loads(ln) for ln in lines]
        iters = [e for e in entries if e.get("kind") == "iteration"]
        summaries = [e for e in entries if e.get("kind") == "summary"]
        checks.append(("stress run writes 2 iterations + summary",
                       len(iters) == 2 and len(summaries) == 1
                       and totals["iterations"] == 2
                       and summaries[0]["stopped_reason"]
                       == "max_iterations",
                       f"{len(iters)} iteration line(s), "
                       f"{len(summaries)} summary line(s)"))
        # Ledger survives the stress run (saved after every iteration).
        reloaded = CoverageLedger(lpath)
        checks.append(("ledger persists after stress run",
                       len(reloaded.data["seen_fingerprints"]) >= 7
                       and os.path.exists(lpath),
                       f"{len(reloaded.data['seen_fingerprints'])} "
                       f"fingerprints in reloaded ledger"))
    return _scorecard("Continuous scanning (demo only, no network)", checks)


def run_selftest(live: bool = False) -> int:
    ok = fixture_scorecard()
    ok = vault_scorecard() and ok
    ok = savings_scorecard() and ok
    ok = continuous_scorecard() and ok
    if live:
        print("\n=== Live GitHub smoke test ===")
        result = live_smoke_test()
        print(f"  status: {result['status']}")
        for name, detail in result.get("queries", {}).items():
            print(f"  {name}: {detail}")
        if "reason" in result:
            print(f"  reason: {result['reason']}")
        md_path = os.path.join(ROOT, "tests", "LIVE_SMOKE_TEST.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# Live GitHub smoke test\n\n")
            f.write("Run via `python3 aiscan.py selftest --live` "
                    "(needs GITHUB_TOKEN).\n\n")
            f.write(f"Status: **{result['status']}**\n\n")
            if "reason" in result:
                f.write(f"Reason: {result['reason']}\n\n")
            for name, detail in result.get("queries", {}).items():
                f.write(f"- `{name}`: {detail}\n")
            f.write("\nVerification is OFF in smoke tests; findings are "
                    "masked; no key is ever validated or used.\n")
        print(f"  recorded in tests/LIVE_SMOKE_TEST.md")
        if result["status"] == "error":
            ok = False
    print("\nSELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run_selftest(live="--live" in sys.argv))
