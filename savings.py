"""Potential-savings estimation for aiscan findings.

Estimates the money NOT spent because leaked API keys were found before
they could be abused. This is an ESTIMATE, not a verified loss: no key is
ever tested against a provider, so billing status (free tier vs paid) and
whether a key is still live are unknown.

Model (same as results/DISCOVERY_INTELLIGENCE.md, 2026-11-19):
  savings(provider) = keys x P(abuse) x daily_cost x window_days
  daily_cost = throughput_tokens_per_day x blended_rate
               (+ Perplexity request fees: 5,000 req/day x $8.00/1,000)
  blended_rate  = (3 x input + output) / 4   (3:1 input:output token mix)
  OpenRouter blended rate x 1.055 (its 5.5% credit fee)
  "Unknown (generic)" and any provider without a researched price use the
  mean blended rate of the researched providers ($3.1247/1M tokens).

Scenarios:
  conservative: 10% of keys abused,  5M tokens/day,  7 days undetected
  expected:     25% of keys abused, 25M tokens/day, 30 days undetected
  worst-case:   50% of keys abused, 100M tokens/day, 30 days undetected

Pricing sources (list prices, Nov 2026 — re-check before quoting):
  OpenAI GPT-5 $1.25/$10, Anthropic Sonnet 5.5 $2/$10, Gemini 2.5 Pro
  $1.25/$10, OpenRouter pass-through + 5.5%, Groq GPT-OSS 120B
  $0.15/$0.60, Perplexity Sonar Pro $3/$15 + $6-$14/1k requests,
  Hugging Face Llama 3.3 70B $0.59/$0.79, xAI Grok 4.7 $2/$6.
  Full citations: results/DISCOVERY_INTELLIGENCE.md §2.

Abuse evidence the model is anchored to: Sysdig LLMjacking ($46k+/day
modelled, $100k/day ceiling, one victim ~$30k in 3 hours), Permiso
honeypot ($3,500 in 2 days), Railway breach (~$740k in ~26 hours),
Google Threat Intelligence Group Nov 2026 (>$100k in a single day).
Every modelled pace sits well below those documented paces.

Confidence split (2026-11-19): "real-looking" only proves a key matches
a documented format and sits in real code/config context — it does NOT
prove the key is live or has paid billing, because no found key is ever
tested against a provider. So every estimate is reported twice:

- "Potential (candidate) savings" — the model above, run over ALL
  findings. Unconfirmed candidates; the headline figure.
- "Owner-verified savings" — the SAME model, run only over findings
  whose fingerprint the owner has marked verified (see
  ``load_verified_fingerprints`` / ``aiscan.py verified``). A key lands
  there only after the owner confirms it is live and theirs — e.g. by
  checking their provider console, or by an authorized read-only
  ``--verify`` probe on their own assets. Until any key is verified
  this side is $0, with an honest note saying so.
"""
from __future__ import annotations

import json
import os

MODEL_VERSION = "aiscan-savings-v1"

DISCLAIMER = (
    "ESTIMATE based on public pricing and documented abuse costs — "
    "not a verified loss. No key was tested against any provider; "
    "billing status (free tier vs paid) is unknown, and free-tier keys "
    "would cost far less. See results/DISCOVERY_INTELLIGENCE.md."
)

# provider -> pricing. input/output are $ per 1M tokens for the flagship
# model used in the report. fee_per_1k_requests is $ per 1,000 requests
# (Perplexity only). fee_multiplier applies on top of the blended rate
# (OpenRouter's 5.5% credit fee).
PRICING = {
    "OpenAI": {
        "model": "GPT-5",
        "input_per_1m": 1.25,
        "output_per_1m": 10.00,
        "fee_per_1k_requests": 0.0,
        "source": "https://www.requesty.ai/blog/openai-api-pricing",
    },
    "Anthropic": {
        "model": "Claude Sonnet 5.5",
        "input_per_1m": 2.00,
        "output_per_1m": 10.00,
        "fee_per_1k_requests": 0.0,
        "source": "https://infro.io/blog/claude-api-pricing-2026",
    },
    "Google Gemini": {
        "model": "Gemini 2.5 Pro",
        "input_per_1m": 1.25,
        "output_per_1m": 10.00,
        "fee_per_1k_requests": 0.0,
        "source": "https://infkey.com/gemini-api-pricing-2026-token-costs-5-workload-examples",
    },
    "OpenRouter": {
        "model": "Claude Sonnet 5.5 via OpenRouter",
        "input_per_1m": 2.00,
        "output_per_1m": 10.00,
        "fee_per_1k_requests": 0.0,
        "fee_multiplier": 1.055,
        "source": "https://aionx.co/ai-comparisons/openrouter-ai-aggregator/",
    },
    "Groq": {
        "model": "GPT-OSS 120B",
        "input_per_1m": 0.15,
        "output_per_1m": 0.60,
        "fee_per_1k_requests": 0.0,
        "source": "https://weneedai.net/groq-cloud-pricing/",
    },
    "Perplexity": {
        "model": "Sonar Pro",
        "input_per_1m": 3.00,
        "output_per_1m": 15.00,
        "fee_per_1k_requests": 8.00,
        "source": "https://aibusinessweekly.net/p/perplexity-pricing",
    },
    "Hugging Face": {
        "model": "Llama 3.3 70B (Inference Providers)",
        "input_per_1m": 0.59,
        "output_per_1m": 0.79,
        "fee_per_1k_requests": 0.0,
        "source": "https://computecomparison.com/compare-two-llm-providers/azure-ai-foundry-vs-hugging-face",
    },
    "xAI": {
        "model": "Grok 4.7",
        "input_per_1m": 2.00,
        "output_per_1m": 6.00,
        "fee_per_1k_requests": 0.0,
        "source": "https://flatkey.ai/blog/grok-api-pricing",
    },
}

# Providers the scanner detects but the report did not price-research
# (DeepSeek, Mistral, Cohere, Together AI, Replicate) use the generic
# rate below until researched — same as the report's "Unknown" handling.
GENERIC_BLENDED_PER_1M = 3.1247  # mean of the researched blended rates

SCENARIOS = {
    "conservative": {
        "p_abuse": 0.10,
        "throughput_tokens_per_day": 5_000_000,
        "window_days": 7,
    },
    "expected": {
        "p_abuse": 0.25,
        "throughput_tokens_per_day": 25_000_000,
        "window_days": 30,
    },
    "worst_case": {
        "p_abuse": 0.50,
        "throughput_tokens_per_day": 100_000_000,
        "window_days": 30,
    },
}

# Assumed incident-response cost per abused key (assumption, not sourced):
# a few hours of engineering + security time to investigate, rotate,
# audit usage and dispute charges. Shown separately from usage bills.
INCIDENT_RESPONSE_PER_KEY_USD = 2500

PERPLEXITY_REQUESTS_PER_DAY = 5000

ASSUMPTIONS = {
    "token_mix": "3:1 input:output",
    "billing_caveat": (
        "Model assumes keys have paid billing enabled. Free-tier keys "
        "(e.g. Groq 200k tokens/day cap, Gemini rate-limited free tier, "
        "Hugging Face $0.10/month credit) would cost far less. Billing "
        "status is unverifiable without testing a key, which aiscan never does."
    ),
    "incident_response_usd_per_abused_key": INCIDENT_RESPONSE_PER_KEY_USD,
    "incident_response_note": "Assumption, not a sourced figure.",
    "perplexity_requests_per_day": PERPLEXITY_REQUESTS_PER_DAY,
}

# --- Owner-verified split -------------------------------------------------
# A finding counts as owner-verified only when its SHA-256 fingerprint
# (first 16 hex chars, the same value printed in every report) appears in
# a verified-fingerprints file. Fingerprints are safe to handle: they
# reveal nothing about the key itself. NEVER put a full key in this file.

OWNER_VERIFIED_NOTE = (
    "Owner-verified savings count only keys the owner confirmed live and "
    "theirs (provider console, or an authorized read-only --verify probe "
    "on their own assets) and then marked verified by fingerprint. "
    "Unconfirmed candidates never count here."
)

OWNER_VERIFIED_EMPTY_NOTE = (
    "No keys confirmed live yet. Only keys the owner has checked and "
    "marked verified count as owner-verified savings — see README "
    "'Owner-verified savings'. Until then this side stays $0; the "
    "candidate figures above are unconfirmed estimates, not verified losses."
)


def is_fingerprint(value) -> bool:
    """True for a 16-hex-char SHA-256 fingerprint prefix."""
    return (
        isinstance(value, str)
        and len(value) == 16
        and all(c in "0123456789abcdef" for c in value.lower())
    )


def default_verified_path() -> str:
    """Default verified-fingerprints file (~/.aiscan/verified-fingerprints.json)."""
    return os.path.join(
        os.path.expanduser("~"), ".aiscan", "verified-fingerprints.json")


def load_verified_fingerprints(path: str) -> tuple:
    """Load a verified-fingerprints file.

    Accepts a JSON list of fingerprint strings, or a JSON object with a
    "fingerprints" list. Returns (fingerprints:set, skipped:int) — entries
    that are not 16-hex-char strings are skipped, never fatal. Raises
    OSError / ValueError on an unreadable file or bad JSON.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        raw = data.get("fingerprints", [])
    elif isinstance(data, list):
        raw = data
    else:
        raise ValueError(
            f"{path}: want a JSON list of fingerprints or an object with "
            f"a \"fingerprints\" list, got {type(data).__name__}")
    if not isinstance(raw, list):
        raise ValueError(
            f"{path}: \"fingerprints\" must be a list, got "
            f"{type(raw).__name__}")
    fps, skipped = set(), 0
    for item in raw:
        if is_fingerprint(item):
            fps.add(item.lower())
        else:
            skipped += 1
    return fps, skipped


def blended_rate_per_1m(provider: str) -> float:
    """Blended $/1M tokens at the 3:1 input:output mix."""
    spec = PRICING.get(provider)
    if spec is None:
        return GENERIC_BLENDED_PER_1M
    rate = (3 * spec["input_per_1m"] + spec["output_per_1m"]) / 4
    return rate * spec.get("fee_multiplier", 1.0)


def _per_key_daily_cost(provider: str, throughput_tokens_per_day: int) -> float:
    cost = throughput_tokens_per_day / 1_000_000 * blended_rate_per_1m(provider)
    spec = PRICING.get(provider)
    if spec and spec["fee_per_1k_requests"]:
        cost += (PERPLEXITY_REQUESTS_PER_DAY / 1000) * spec["fee_per_1k_requests"]
    return cost


def _estimate_for(findings) -> dict:
    """The model run over one list of findings (candidate or verified).

    Returns the per-list estimate: total keys, per-provider counts,
    per-scenario usage-bill savings and the headline range. Identical
    arithmetic for both sides of the split — only the input list differs.
    """
    counts: dict = {}
    for f in findings:
        counts[f.provider] = counts.get(f.provider, 0) + 1
    total_keys = len(findings)

    scenarios = {}
    for name, spec in SCENARIOS.items():
        by_provider = {}
        for provider, n in sorted(counts.items()):
            by_provider[provider] = round(
                n * spec["p_abuse"]
                * _per_key_daily_cost(provider, spec["throughput_tokens_per_day"])
                * spec["window_days"],
                2,
            )
        total = round(sum(by_provider.values()), 2)
        expected_abused = round(total_keys * spec["p_abuse"], 1)
        scenarios[name] = {
            "p_abuse": spec["p_abuse"],
            "throughput_tokens_per_day": spec["throughput_tokens_per_day"],
            "window_days": spec["window_days"],
            "usage_bill_savings_usd": total,
            "per_key_usd": round(total / total_keys, 2) if total_keys else 0.0,
            "expected_abused_keys": expected_abused,
            "incident_response_savings_usd": round(
                total_keys * spec["p_abuse"] * INCIDENT_RESPONSE_PER_KEY_USD, 2),
            "by_provider_usd": by_provider,
        }

    return {
        "total_keys": total_keys,
        "by_provider": dict(sorted(counts.items())),
        "scenarios": scenarios,
        "headline_range_usd": {
            name: scenarios[name]["usage_bill_savings_usd"]
            for name in ("conservative", "expected", "worst_case")
        },
    }


def estimate_savings(findings, verified_fingerprints=None) -> dict:
    """Per-provider + total potential-savings ranges for a list of findings.

    The top-level keys are the CANDIDATE estimate (all findings) — the
    same numbers as before this split, byte-for-byte identical. The new
    keys below it are the OWNER-VERIFIED estimate: the same model run
    over only the findings whose fingerprint is in ``verified_fingerprints``
    (a set of 16-hex-char SHA-256 prefixes, as printed in reports).
    With no verified fingerprints the owner-verified side is all $0.

    Returns a JSON-serializable dict with conservative / expected /
    worst-case usage-bill savings, per-key figures, incident-response
    savings, and the assumptions — for both sides.
    """
    candidate = _estimate_for(findings)
    verified_set = {fp.lower() for fp in (verified_fingerprints or ())}
    verified = [f for f in findings if f.fingerprint in verified_set]
    found_fps = {f.fingerprint for f in findings}

    return {
        "model": MODEL_VERSION,
        "disclaimer": DISCLAIMER,
        "assumptions": ASSUMPTIONS,
        "total_keys": candidate["total_keys"],
        "by_provider": candidate["by_provider"],
        "pricing_usd_per_1m_tokens": {
            p: {
                "model": s["model"],
                "blended_per_1m": round(blended_rate_per_1m(p), 4),
            }
            for p, s in PRICING.items()
        },
        "generic_blended_per_1m": GENERIC_BLENDED_PER_1M,
        "scenarios": candidate["scenarios"],
        "headline_range_usd": candidate["headline_range_usd"],
        # Owner-verified split (same model, verified findings only).
        "verified_keys": len(verified),
        "verified_fingerprints_unmatched": len(verified_set - found_fps),
        "owner_verified_savings": _estimate_for(verified),
        "owner_verified_note": OWNER_VERIFIED_NOTE,
    }


def _verified_block(result: dict) -> tuple:
    """Owner-verified side of a savings result, tolerating pre-split dicts.

    Returns (verified_keys, headline_range dict, scenarios dict, unmatched).
    """
    ver = result.get("owner_verified_savings") or {}
    return (
        result.get("verified_keys", 0),
        ver.get("headline_range_usd", {}),
        ver.get("scenarios", {}),
        result.get("verified_fingerprints_unmatched", 0),
    )


def render_savings_lines(result: dict) -> list:
    """Short plain-text block for the terminal scorecard / table report.

    Shows both sides of the split: the candidate estimate (all findings,
    unconfirmed) first, then the owner-verified estimate (confirmed keys
    only — $0 until the owner marks any verified).
    """
    lines = []
    lines.append("Potential (candidate) savings (ESTIMATE — not a verified loss):")
    h = result["headline_range_usd"]
    lines.append(
        f"  ${h['conservative']:,.2f} conservative – "
        f"${h['expected']:,.2f} expected – "
        f"${h['worst_case']:,.2f} worst-case "
        f"({result['total_keys']} key(s) found)")
    exp = result["scenarios"]["expected"]
    lines.append(
        f"  Expected case: {exp['p_abuse']:.0%} of keys abused, "
        f"{exp['throughput_tokens_per_day']/1_000_000:.0f}M tokens/day, "
        f"{exp['window_days']} days undetected → "
        f"${exp['usage_bill_savings_usd']:,.2f} usage bills "
        f"(+ ${exp['incident_response_savings_usd']:,.2f} incident response)")
    lines.append(
        "  Assumes paid billing on the keys; free-tier keys would cost far "
        "less. Public pricing + documented abuse costs; see "
        "results/DISCOVERY_INTELLIGENCE.md.")
    vkeys, vh, vscenarios, unmatched = _verified_block(result)
    lines.append("Owner-verified savings (keys the owner confirmed live):")
    lines.append(
        f"  ${vh.get('conservative', 0.0):,.2f} conservative – "
        f"${vh.get('expected', 0.0):,.2f} expected – "
        f"${vh.get('worst_case', 0.0):,.2f} worst-case "
        f"({vkeys} key(s) verified)")
    if vkeys:
        vexp = vscenarios["expected"]
        lines.append(
            f"  Expected case: {vexp['p_abuse']:.0%} of verified keys abused, "
            f"{vexp['throughput_tokens_per_day']/1_000_000:.0f}M tokens/day, "
            f"{vexp['window_days']} days undetected → "
            f"${vexp['usage_bill_savings_usd']:,.2f} usage bills "
            f"(+ ${vexp['incident_response_savings_usd']:,.2f} incident response)")
    else:
        lines.append(f"  {OWNER_VERIFIED_EMPTY_NOTE}")
    if unmatched:
        lines.append(
            f"  Note: {unmatched} fingerprint(s) in the verified file "
            f"matched no finding in this scan (stale entry or typo?).")
    return lines


def render_savings_markdown(result: dict) -> list:
    """Markdown section for the Markdown report (both sides of the split)."""
    lines = []
    lines.append("## Potential savings — candidates (estimate)")
    lines.append("")
    lines.append(f"> {DISCLAIMER}")
    lines.append("")
    lines.append(
        "These are **candidates**: keys that look real (documented format, "
        "real code/config context) but were never tested against a provider, "
        "so liveness and paid billing are unconfirmed. Treat the figures "
        "as an upper bound on what finding them early might have saved.")
    lines.append("")
    h = result["headline_range_usd"]
    lines.append("| Scenario | P(abuse) | Throughput | Window | Usage-bill savings | Per key |")
    lines.append("|---|---|---|---|---|---|")
    for name, label in (("conservative", "Conservative"),
                        ("expected", "Expected"),
                        ("worst_case", "Worst-case")):
        s = result["scenarios"][name]
        lines.append(
            f"| {label} | {s['p_abuse']:.0%} | "
            f"{s['throughput_tokens_per_day']/1_000_000:.0f}M tok/day | "
            f"{s['window_days']} days | "
            f"${s['usage_bill_savings_usd']:,.2f} | "
            f"${s['per_key_usd']:,.2f} |")
    lines.append("")
    lines.append("**Expected case, by provider:**")
    lines.append("")
    exp = result["scenarios"]["expected"]["by_provider_usd"]
    for provider, amount in sorted(exp.items(), key=lambda kv: -kv[1]):
        n = result["by_provider"][provider]
        lines.append(f"- {provider} ({n} key{'s' if n != 1 else ''}): "
                     f"${amount:,.2f}")
    lines.append("")
    lines.append(
        f"Incident response (assumed ${INCIDENT_RESPONSE_PER_KEY_USD:,} per "
        f"abused key, not a sourced figure): "
        f"${result['scenarios']['expected']['incident_response_savings_usd']:,.2f} "
        f"in the expected case.")
    lines.append("")
    vkeys, vh, vscenarios, unmatched = _verified_block(result)
    lines.append("## Owner-verified savings")
    lines.append("")
    lines.append(f"> {OWNER_VERIFIED_NOTE}")
    lines.append("")
    if vkeys:
        lines.append(
            f"**{vkeys} key(s) confirmed live by the owner.** Same model, "
            f"verified keys only:")
        lines.append("")
        lines.append("| Scenario | P(abuse) | Throughput | Window | Usage-bill savings | Per key |")
        lines.append("|---|---|---|---|---|---|")
        for name, label in (("conservative", "Conservative"),
                            ("expected", "Expected"),
                            ("worst_case", "Worst-case")):
            s = vscenarios[name]
            lines.append(
                f"| {label} | {s['p_abuse']:.0%} | "
                f"{s['throughput_tokens_per_day']/1_000_000:.0f}M tok/day | "
                f"{s['window_days']} days | "
                f"${s['usage_bill_savings_usd']:,.2f} | "
                f"${s['per_key_usd']:,.2f} |")
        lines.append("")
        lines.append(
            f"Incident response in the expected case: "
            f"${vscenarios['expected']['incident_response_savings_usd']:,.2f}.")
        lines.append("")
    else:
        lines.append(
            f"**$0.00 conservative – $0.00 expected – $0.00 worst-case "
            f"(0 keys verified).** {OWNER_VERIFIED_EMPTY_NOTE}")
        lines.append("")
    if unmatched:
        lines.append(
            f"Note: {unmatched} fingerprint(s) in the verified file matched "
            f"no finding in this scan (stale entry or typo?).")
        lines.append("")
    lines.append(
        "**Assumptions:** 3:1 input:output token mix; blended $/1M tokens "
        "from public list prices (Nov 2026); Perplexity request fees at "
        "5,000 requests/day. Providers without a researched price "
        "(DeepSeek, Mistral, Cohere, Together AI, Replicate, Unknown) use "
        f"the generic blended rate of ${GENERIC_BLENDED_PER_1M}/1M tokens. "
        "The model assumes paid billing — free-tier keys would cost far "
        "less, and billing status is unverifiable without testing a key, "
        "which aiscan never does. Full model, sources and sensitivity: "
        "`results/DISCOVERY_INTELLIGENCE.md`.")
    lines.append("")
    return lines
