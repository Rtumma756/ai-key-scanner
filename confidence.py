"""Confidence scoring for aiscan findings: graded 0-100, evidence per finding.

Replaces the binary real/placeholder claim with a defensible score built
only from STATIC signals. This module never makes a network call and never
calls any provider API with any key. It never outputs, logs, or stores a
raw key value: scoring reads the masked form, the key length, the file
path, the (already redacted) snippet, and the finding's metadata. When a
live ``Finding`` object is passed, the raw value is inspected in memory
ONLY for placeholder/denylist checks and is never retained or returned.

Scoring model (weights sum to a 0-100 clamp; see ``score_finding``):

    base                          40   a detected, random-looking candidate
    format strictness        +25 / +12 / -10
        exact provider format (fixed prefix + exact length, e.g. Gemini
        ``AIza`` + 35 chars = 39 total, DeepSeek ``sk-`` + 32 hex = 35,
        OpenAI legacy ``sk-`` + 48 = 51) ............ +25
        provider prefix matches but length is variable (sk-proj-,
        sk-ant-api03-, gsk_, hf_, sk-or-v1-, pplx-, xai-) .. +12
        entropy-only detection (no fixed prefix: Mistral, Cohere,
        Unknown/generic, or detected_via == "entropy") ...... -10
        context-gated 64-hex (Together AI, detected_via == "context") .. +5
    usage context (cap +15)   assignment to an api_key-like variable +5,
        passed to a client constructor +5, Authorization/Bearer nearby +5,
        SDK import of that provider in the same file/repo +5
    file type                 code +10, config/data +5, docs / examples /
        tests / fixtures -15 and the score is capped at 45 there
    liveness duration         exposed_since age: >3y +10, 1-3y +5, <1y +2;
        still live on a later re-check +5
    cross-report corroboration  +5 per additional dated report the same
        fingerprint appears in, cap +10 (e.g. trial-67 + stress-test +
        fresh scan + liveness re-check)
    placeholder / denylist    hard override: score is capped at 5 when the
        value, snippet, path, or the source report's classification says
        placeholder / example / test key (sk_test_ style markers,
        placeholder words, sequential/repeated runs in the key tail)
    source-report caps        classification "borderline" caps at 55,
        "unresolved" caps at 40 (a key the classifier could not place
        cannot score as confident)

Why these weights: format is the strongest single static signal (a
provider's exact format is hard to fake by accident, worth 25), usage
context is the next best proof the value is actually used as a credential
(15), file type separates real app code from documentation (docs cap at
45 because an example key in a README can have a perfect format), and
liveness/corroboration reward keys that keep showing up across independent
dated reports (up to 15 combined). Placeholders are an override, not a
deduction, because a known example key is not a leak however perfect its
format looks.

Fixture marker: the literal string ``TESTFAKE`` (any case) is the repo's
test-fixture marker and is ignored by the placeholder check, so fixture
keys can be scored like real keys. It never appears in a genuine key.

Limitations, stated plainly: corpus rows from results/*.json carry no
snippet, so usage-context signals cannot fire for them and their scores
are a lower bound on what a live scan (which has the snippet) would give.
Format is judged from the masked prefix (first 4 chars) plus the recorded
length, so charset cannot be verified from corpus rows.
"""
from __future__ import annotations

import re
from datetime import date, datetime

# ---------------------------------------------------------------------------
# Placeholder / denylist
# ---------------------------------------------------------------------------

# Words that mark a value as a placeholder when they appear as a *token*
# (delimited by a non-alphanumeric, or at the start/end of the value).
# Substring matching is deliberately NOT used: a random base64-ish key can
# contain "test" by chance, and the fixture marker TESTFAKE contains it.
PLACEHOLDER_TOKENS = (
    "test", "fake", "example", "placeholder", "your", "xxx", "dummy",
    "sample", "replace", "changeme", "todo", "none", "null", "redacted",
    "insert", "demo", "mock", "changethis",
)
_TOKEN_RE = re.compile(
    r"(?i)(?:^|[^a-z0-9])(" + "|".join(PLACEHOLDER_TOKENS) + r")(?:[^a-z0-9]|$)"
)

# Explicit test-key prefixes / markers (checked as prefixes or tokens).
TEST_KEY_MARKERS = ("sk_test_", "pk_test_", "rk_test_", "sk-test-",
                    "test_", "test-", "-test-", "_test_")

# The repo's fixture marker: ignored by every placeholder check so that
# obviously-fake TESTFAKE fixture keys score on format/context alone.
FIXTURE_MARKER = "TESTFAKE"

_SEQUENTIAL_RUNS = ("abcd", "bcde", "cdef", "defg", "efgh", "fghi", "ghij",
                    "hijk", "ijkl", "jklm", "klmn", "lmno", "mnop", "nopq",
                    "opqr", "pqrs", "qrst", "rstu", "stuv", "tuvw", "uvwx",
                    "vwxy", "wxyz", "0123", "1234", "2345", "3456", "4567",
                    "5678", "6789", "7890")


def _strip_fixture_marker(text: str) -> str:
    return re.sub(r"(?i)" + FIXTURE_MARKER, "", text or "")


def _has_placeholder_word(text: str) -> str | None:
    """Return the placeholder token found in ``text``, or None."""
    cleaned = _strip_fixture_marker(text)
    m = _TOKEN_RE.search(cleaned)
    if m:
        return m.group(1).lower()
    lowered = cleaned.lower()
    for marker in TEST_KEY_MARKERS:
        if marker in lowered:
            return marker
    return None


def _has_sequential_or_repeated_tail(value: str) -> str | None:
    """Sequential (abcd/1234) or repeated (aaaa/0000) 4-char run in the tail."""
    tail = _strip_fixture_marker(value)[-12:].lower()
    for run in _SEQUENTIAL_RUNS:
        if run in tail:
            return f"sequential run {run!r} in key tail"
    m = re.search(r"(.)\1{3,}", tail)
    if m:
        return f"repeated run {m.group(0)!r} in key tail"
    return None


# ---------------------------------------------------------------------------
# Provider format table: (masked prefix, exact length or None)
# ---------------------------------------------------------------------------
# exact length None = variable-length provider format (prefix match only).
_EXACT_FORMATS = {
    # provider -> (masked prefix to recognise, exact total length)
    "Google Gemini": ("AIza", 39),
    "DeepSeek": ("sk-", 35),
    "OpenAI": ("sk-", 51),  # legacy sk- + 48; sk-proj-/sk-svcacct- are variable
}
_VARIABLE_PREFIX_FORMATS = {
    "OpenAI": ("sk-p", "sk-s", "sk-"),       # sk-proj-, sk-svcacct-, other sk-
    "Anthropic": ("sk-a",),
    "Groq": ("gsk_",),
    "OpenRouter": ("sk-o",),
    "Hugging Face": ("hf_",),
    "Perplexity": ("pplx",),
    "xAI": ("xai-",),
}
# Providers with no fixed public prefix: only ever entropy/context detected.
ENTROPY_ONLY_PROVIDERS = {"Mistral", "Cohere", "Unknown (generic)", "Unknown"}

# ---------------------------------------------------------------------------
# File-type classification
# ---------------------------------------------------------------------------
_CODE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb",
              ".php", ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt",
              ".scala", ".pl", ".sh", ".ps1"}
_CONFIG_EXTS = {".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
                ".conf", ".xml", ".ipynb", ".txt", ".properties", ".local"}
_DOCS_BASENAMES = {"readme.md", "setup.md", "usage.md", "pr.md",
                   "contributing.md", "changelog.md"}
_EXAMPLE_MARKERS = ("/examples/", "/example/", "/tutorial/", "/demo/",
                    "/sample/", "/mock/", "/fixtures/", "/fixture/",
                    "/test/", "/tests/", ".test.", ".spec.",
                    ".env.example", ".env.sample")
_DOCS_MARKERS = ("/docs/", "/documentation/")


def _file_signal(file_path: str) -> tuple[int, str | None, bool]:
    """Return (points, evidence, is_docs_or_example)."""
    path = (file_path or "").lower()
    if not path:
        return 0, None, False
    base = path.rsplit("/", 1)[-1]
    if (base in _DOCS_BASENAMES or any(m in path for m in _DOCS_MARKERS)
            or base.endswith(".md")):
        return -15, "found in docs file", True
    if (any(m in path for m in _EXAMPLE_MARKERS)
            or base.startswith(("example", "sample", "test_", "fixture"))
            or "example" in base or "fixture" in base):
        return -15, "found in example/test/fixture file", True
    ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
    if ext in _CODE_EXTS:
        return 10, "found in application code", False
    if ext in _CONFIG_EXTS or base.startswith(".env"):
        return 5, "found in config/data file", False
    return 0, None, False


# ---------------------------------------------------------------------------
# Usage-context signals (from snippet / supplied context text)
# ---------------------------------------------------------------------------
_API_KEY_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\b\s*[:=]")
_CLIENT_CTOR_RES = [
    re.compile(r"(?i)\b(openai|anthropic|groq|genai|mistral|cohere|"
               r"huggingface|replicate|together|deepseek|openrouter|"
               r"perplexity|xai)\s*\("),
    re.compile(r"(?i)\b(configure|client\s*=|apiKey\s*:)"),
]
_AUTH_RE = re.compile(r"(?i)\b(authorization|bearer)\b")
_SDK_IMPORT_RES = [
    re.compile(r"(?i)\b(import|from|require|using)\b[^#\n]*\b({kw})\b")
    for kw in ("openai", "anthropic", "google.generativeai", "groq",
               "mistralai", "cohere", "huggingface_hub", "replicate",
               "openrouter", "deepseek", "perplexity", "xai")
]


def _context_signals(text: str, provider: str) -> tuple[int, list[str]]:
    """Score usage context in ``text`` (snippet + optional file text)."""
    points = 0
    evidence: list[str] = []
    if not text:
        return 0, evidence
    if _API_KEY_ASSIGN_RE.search(text):
        points += 5
        evidence.append("assigned to an api_key-like variable")
    if any(rx.search(text) for rx in _CLIENT_CTOR_RES):
        points += 5
        evidence.append("passed to a client constructor / configure call")
    if _AUTH_RE.search(text):
        points += 5
        evidence.append("Authorization/Bearer usage nearby")
    # SDK import of this provider in the same file/repo.
    prov_key = provider.lower().split()[0]
    for rx in _SDK_IMPORT_RES:
        m = rx.search(text)
        if m and (prov_key in m.group(0).lower() or "generativeai" in m.group(0).lower()):
            points += 5
            evidence.append(f"{provider} SDK imported in the same file")
            break
    return min(points, 15), evidence[:4]


# ---------------------------------------------------------------------------
# Liveness / corroboration
# ---------------------------------------------------------------------------
def _parse_date(value) -> date | None:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("date") or value.get("first_seen") or value.get("since")
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()[:10]
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def _liveness_signals(exposed_since, still_live: bool, as_of: date | None
                      ) -> tuple[int, list[str]]:
    points = 0
    evidence: list[str] = []
    since = _parse_date(exposed_since)
    if since is not None:
        ref = as_of or date.today()
        age_days = max(0, (ref - since).days)
        if age_days >= 3 * 365:
            points += 10
            evidence.append(f"exposed since {since.isoformat()} "
                            f"({age_days // 365}y+ in the open)")
        elif age_days >= 365:
            points += 5
            evidence.append(f"exposed since {since.isoformat()} "
                            f"({age_days // 365}y in the open)")
        elif age_days >= 0:
            points += 2
            evidence.append(f"exposed since {since.isoformat()}")
    if still_live:
        points += 5
        evidence.append("still exposed on a later re-check")
    return points, evidence


# ---------------------------------------------------------------------------
# Normalisation: Finding object or plain dict -> flat field dict
# ---------------------------------------------------------------------------
def _normalise(finding, context: dict | None) -> dict:
    ctx = dict(context or {})
    if hasattr(finding, "provider"):  # a Finding object
        raw_value = getattr(finding, "value", "") or ""
        d = {
            "provider": finding.provider,
            "masked": getattr(finding, "masked", "") or "",
            "length": len(raw_value) if raw_value else None,
            "file": getattr(finding, "file_path", "") or "",
            "line": getattr(finding, "line_number", 0) or 0,
            "snippet": getattr(finding, "snippet", "") or "",
            "detected_via": getattr(finding, "detected_via", "") or "",
            "classification": "",
            "status": getattr(finding, "verification", "") or "",
            "exposed_since": None,
            "in_trial_67": False,
            "rotated": False,
            "_raw_value": raw_value,  # in-memory only; never returned
        }
    elif isinstance(finding, dict):
        fp = finding.get("fingerprint") or finding.get("fingerprint_sha256_16")
        d = {
            "provider": finding.get("provider", "") or "",
            "masked": finding.get("masked") or "",
            "length": finding.get("length"),
            "file": finding.get("file") or finding.get("file_path") or "",
            "line": finding.get("line") or finding.get("line_number") or 0,
            "snippet": finding.get("snippet") or "",
            "detected_via": finding.get("detected_via") or "",
            "classification": finding.get("classification") or "",
            "status": finding.get("status") or "",
            "exposed_since": finding.get("exposed_since"),
            "in_trial_67": bool(finding.get("in_trial_67")),
            "rotated": bool(finding.get("rotated")),
            "fingerprint": fp,
            "_raw_value": finding.get("value") or "",
        }
    else:
        raise TypeError(f"cannot score finding of type {type(finding)!r}")
    # Context overrides / additions (never contains a raw key).
    if ctx.get("exposed_since") is not None and d["exposed_since"] is None:
        d["exposed_since"] = ctx["exposed_since"]
    d["_context"] = ctx
    return d


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def score_finding(finding, context: dict | None = None
                  ) -> tuple[int, list[str]]:
    """Score one finding 0-100 with short human-readable evidence.

    ``finding`` is a ``Finding`` object or a dict (corpus rows from
    results/*.json work: provider, masked, length, file, classification,
    exposed_since, in_trial_67, detected_via, snippet when present).
    ``context`` is an optional dict of static extras, all safe to pass:
    ``snippet``/``file_text`` (extra surrounding text), ``sdk_imports``
    (provider names imported in the file/repo), ``as_of`` ("YYYY-MM-DD"
    reference date for exposure age), ``still_live`` (bool), ``report_count``
    (how many dated reports this fingerprint appears in),
    ``live_fingerprints`` (set of fingerprints confirmed still exposed).
    Never put a raw key value in ``context``. Returns (score, evidence).
    """
    try:
        return _score_finding_inner(finding, context)
    except Exception as exc:  # scoring must never break a report
        return 0, [f"confidence scoring failed: {exc}"]


def _score_finding_inner(finding, context) -> tuple[int, list[str]]:
    d = _normalise(finding, context)
    ctx = d["_context"]
    provider = d["provider"]
    masked = d["masked"] or ""
    length = d["length"]
    evidence: list[str] = []

    # --- placeholder / denylist: hard override, checked first ----------
    raw_value = d.get("_raw_value") or ""
    placeholder_hit = None
    if raw_value:
        placeholder_hit = _has_placeholder_word(raw_value)
        if not placeholder_hit:
            placeholder_hit = _has_sequential_or_repeated_tail(raw_value)
    if not placeholder_hit and d["snippet"]:
        placeholder_hit = _has_placeholder_word(d["snippet"])
    if not placeholder_hit and d["file"]:
        placeholder_hit = _has_placeholder_word(d["file"])
    if not placeholder_hit and d["classification"] == "placeholder":
        placeholder_hit = "classified placeholder in source report"
    if placeholder_hit:
        score = 5 if isinstance(placeholder_hit, str) and \
            placeholder_hit.startswith(("sequential", "repeated")) else 0
        return score, [f"known placeholder / example key ({placeholder_hit})"]

    # --- format strictness ---------------------------------------------
    score = 40
    via = (d["detected_via"] or "").lower()
    if via == "entropy" or provider in ENTROPY_ONLY_PROVIDERS:
        score -= 10
        evidence.append("entropy-only detection, no fixed prefix")
    elif via == "context":
        score += 5
        evidence.append("context-gated match (provider keyword in line)")
    elif provider in _EXACT_FORMATS:
        prefix, exact_len = _EXACT_FORMATS[provider]
        if masked.startswith(prefix) and length == exact_len:
            score += 25
            evidence.append(f"exact {provider} format "
                            f"({prefix} + {exact_len - len(prefix)} chars)")
        elif masked.startswith(prefix):
            score += 12
            evidence.append(f"{provider} prefix present, length "
                            f"{length} (variable-length format)")
        else:
            score -= 10
            evidence.append(f"{provider} key without its usual prefix")
    elif provider in _VARIABLE_PREFIX_FORMATS:
        prefixes = _VARIABLE_PREFIX_FORMATS[provider]
        if any(masked.startswith(p) for p in prefixes):
            score += 12
            evidence.append(f"{provider} prefix present "
                            f"(variable-length format)")
        else:
            score -= 10
            evidence.append(f"{provider} key without its usual prefix")
    else:
        score -= 10
        evidence.append("unknown provider, no verifiable format")

    # --- usage context (snippet + supplied context text) ---------------
    text_parts = [d["snippet"], ctx.get("snippet") or "",
                  ctx.get("file_text") or ""]
    ctx_points, ctx_evidence = _context_signals("\n".join(text_parts),
                                                provider)
    score += ctx_points
    evidence.extend(ctx_evidence)
    if ctx.get("sdk_imports"):
        imports = [s.lower() for s in ctx["sdk_imports"]]
        if provider.lower().split()[0] in " ".join(imports):
            if ctx_points < 15:
                score += 5
                evidence.append(f"{provider} SDK imported in the repo")

    # --- file type ------------------------------------------------------
    file_points, file_evidence, is_docs = _file_signal(d["file"])
    score += file_points
    if file_evidence:
        evidence.append(file_evidence)

    # --- liveness duration ----------------------------------------------
    still_live = bool(ctx.get("still_live"))
    if d["status"] == "still_exposed":
        still_live = True
    if ctx.get("live_fingerprints") and d.get("fingerprint"):
        still_live = d["fingerprint"] in ctx["live_fingerprints"]
    as_of = _parse_date(ctx.get("as_of"))
    live_points, live_evidence = _liveness_signals(
        d["exposed_since"], still_live, as_of)
    score += live_points
    evidence.extend(live_evidence)

    # --- cross-report corroboration --------------------------------------
    report_count = int(ctx.get("report_count") or 1)
    if d["in_trial_67"]:
        report_count = max(report_count, 2)
    if ctx.get("live_fingerprints") and d.get("fingerprint") \
            and d["fingerprint"] in ctx["live_fingerprints"]:
        report_count = max(report_count, 2)
    extra_reports = max(0, report_count - 1)
    if extra_reports:
        corroboration = min(10, 5 * extra_reports)
        score += corroboration
        evidence.append(f"same fingerprint in {report_count} dated reports")

    # --- source-report caps ----------------------------------------------
    if d["classification"] == "borderline":
        score = min(score, 55)
        evidence.append("classifier marked borderline (docs file)")
    elif d["classification"] == "unresolved":
        score = min(score, 40)
        evidence.append("classifier could not resolve this key")
    if is_docs:
        score = min(score, 45)
        evidence.append("docs/example/test file caps confidence at 45")

    score = max(0, min(100, score))
    if not evidence:
        evidence.append("detected key, no further static signals")
    return score, evidence


# ---------------------------------------------------------------------------
# Corpus helpers: build shared context from dated report files
# ---------------------------------------------------------------------------
def build_corpus_context(reports: list[dict]) -> dict:
    """Build scorer context from loaded results/*.json report dicts.

    ``reports`` is a list of report dicts (each with a ``keys`` or ``rows``
    list carrying ``fingerprint``). Returns a context dict with
    ``live_fingerprints`` (fingerprints whose status is still_exposed) and
    a per-fingerprint ``report_count`` map under the private key
    ``_report_counts`` (score_results.py turns it into per-row context).
    """
    live: set[str] = set()
    counts: dict[str, int] = {}
    for report in reports:
        rows = report.get("keys") or report.get("rows") or []
        seen_here: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            fp = row.get("fingerprint") or row.get("fingerprint_sha256_16")
            if not fp:
                continue
            if row.get("status") == "still_exposed":
                live.add(fp)
            if fp not in seen_here:
                counts[fp] = counts.get(fp, 0) + 1
                seen_here.add(fp)
    return {"live_fingerprints": live, "_report_counts": counts}


def context_for_fingerprint(corpus_context: dict, fingerprint: str | None,
                            as_of: str | None = None) -> dict:
    """Per-finding context dict derived from a corpus context."""
    ctx: dict = {}
    if as_of:
        ctx["as_of"] = as_of
    if fingerprint:
        counts = corpus_context.get("_report_counts") or {}
        ctx["report_count"] = counts.get(fingerprint, 1)
        if fingerprint in (corpus_context.get("live_fingerprints") or set()):
            ctx["still_live"] = True
    return ctx
