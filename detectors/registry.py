"""Detector registry: provider regex patterns + entropy fallback.

Each detector carries a provider name, credential type, regex, the provider
console URL (for remediation), and the key used to look up its read-only
verifier (None when no verifier is implemented).

Design notes:
- Patterns are ordered so more specific prefixes win. Overlap resolution
  keeps the longest match at a given start position.
- DeepSeek keys (``sk-`` + 32 lowercase hex) and legacy OpenAI keys
  (``sk-`` + 48 alphanumerics) share a prefix, so DeepSeek's pattern uses a
  negative lookahead for a 33rd alphanumeric character, and the OpenAI
  legacy pattern excludes the other providers' prefixes.
- Mistral, Cohere and Together AI have no fixed public prefix, so they are
  caught by the entropy fallback (secret-looking assignment + provider
  keyword in the line) or, for Together, by a context-gated 64-hex pattern.
- The generic entropy fallback only runs on lines with NO regex match, and
  only for values that clear the entropy threshold and do not look like
  placeholders. This is what keeps UUIDs, hashes and ``your-api-key-here``
  out of the results.
- Example / test keys: ``scan_line`` drops values that are marked as
  examples (see ``is_example_key``) by default, so a repo's docs, tests
  and fixtures do not fail a CI gate with fake keys. This is a *reporting*
  filter, not a detection change: the regexes still match the value, and
  ``scan_line(line, allow_examples=True)`` returns it — the self-test uses
  that mode to prove detection still works. The bundled demo source
  (``sources/demo.py``, in-memory synthetic data) sets ``allow_examples``
  so demo mode still demonstrates the full flow; every real scan path
  (local, git history, repo, internet) filters examples.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .entropy import shannon_entropy

ENTROPY_THRESHOLD = 4.5
MIN_GENERIC_LENGTH = 16

# Values containing any of these words are treated as placeholders, never
# as real secrets (entropy fallback only; regex matches are always kept).
PLACEHOLDER_WORDS = (
    "test", "fake", "example", "placeholder", "your-", "xxx", "dummy",
    "sample", "replace", "changeme", "todo", "none", "null", "redacted",
    "insert", "here", "demo",
)

# ---------------------------------------------------------------------------
# Example / test-key filter (is_example_key)
# ---------------------------------------------------------------------------
# A value carrying one of these markers is an example key, not a real
# credential. Matching is deliberately conservative, because a false
# negative here means a real leak is silently dropped:
# - Compound markers are matched as substrings. "TESTFAKE", "DEMOFAKE"
#   and "DEADBEEF" never occur in a genuine random key (a specific
#   8-char string in a 32-char hex key has P ~ 6e-9; the compound
#   TESTFAKE/DEMOFAKE strings are longer still).
# - Long words (>= 5 chars: example, changeme, placeholder, redacted,
#   sample, dummy, changethis) are matched as substrings. A specific
#   5+-char string in a 20+-char random key has P <= ~1e-8 per key.
# - Short words (test, fake, demo, mock, xxx, none, null, todo, insert,
#   replace, your, here) are matched ONLY as delimited tokens (bounded
#   by a non-alphanumeric or the value boundary). A random base62 key
#   can contain "test" or "fake" by chance (P ~ 1e-6 per key), so
#   substring matching them would eventually suppress a real key.
#   A human writing an example delimits the word ("sk_test_...",
#   "FAKE_KEY", "demo-key"), so token matching catches the realistic
#   cases. Bare "FAKE" glued to random characters (e.g. "sk-proj-FAKEa1b2...")
#   is NOT filtered — that is the documented trade-off; use TESTFAKE.
# - Test-key prefixes (Stripe-style sk_test_ / pk_test_ / rk_test_) are
#   structural: a real production key never starts with them.
EXAMPLE_MARKER_SUBSTRINGS = (
    "testfake", "demofake", "deadbeef",
    "example", "changeme", "placeholder", "redacted", "sample", "dummy",
    "changethis",
)
EXAMPLE_WORD_TOKENS = (
    "test", "fake", "demo", "mock", "xxx", "none", "null", "todo",
    "insert", "replace", "your", "here",
)
EXAMPLE_TEST_KEY_PREFIXES = (
    "sk_test_", "pk_test_", "rk_test_", "sk-test-", "-test-", "_test_",
)
_EXAMPLE_WORD_RE = re.compile(
    r"(?i)(?:^|[^a-z0-9])(" + "|".join(EXAMPLE_WORD_TOKENS) + r")(?:[^a-z0-9]|$)"
)


def is_example_key(value: str) -> bool:
    """True when ``value`` is marked as an example / test key.

    Only the matched value is inspected — never the file path. A real key
    committed in a test file or fixture is still a real leak, so paths
    (tests/, fixtures/, docs/, demo/) are deliberately NOT a signal here.
    """
    if not value:
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in EXAMPLE_MARKER_SUBSTRINGS):
        return True
    if any(prefix in lowered for prefix in EXAMPLE_TEST_KEY_PREFIXES):
        return True
    return bool(_EXAMPLE_WORD_RE.search(value))


@dataclass
class Detector:
    provider: str
    cred_type: str
    pattern: str | None  # None = entropy/context only, no fixed format
    console_url: str
    verify_key: str | None = None
    severity: str = "high"
    requires_context: str | None = None  # substring that must appear in line


# fmt: off
DETECTORS = [
    Detector("OpenAI", "API key (project)", r"sk-proj-[A-Za-z0-9_\-]{20,}",
             "https://platform.openai.com/api-keys", "openai"),
    Detector("OpenAI", "API key (service account)", r"sk-svcacct-[A-Za-z0-9_\-]{20,}",
             "https://platform.openai.com/api-keys", "openai"),
    Detector("OpenAI", "API key (legacy)", r"sk-(?!proj-|svcacct-|or-v1-|ant-)[A-Za-z0-9]{48}",
             "https://platform.openai.com/api-keys", "openai"),
    Detector("Anthropic", "API key", r"sk-ant-api03-[A-Za-z0-9_\-]{20,}",
             "https://console.anthropic.com/settings/keys", None),
    Detector("Google Gemini", "API key", r"AIza[0-9A-Za-z\-_]{35}",
             "https://aistudio.google.com/api-keys", "google"),
    Detector("Groq", "API key", r"gsk_[A-Za-z0-9]{20,}",
             "https://console.groq.com/keys", "groq"),
    Detector("OpenRouter", "API key", r"sk-or-v1-[A-Za-z0-9]{32,}",
             "https://openrouter.ai/keys", "openrouter"),
    Detector("DeepSeek", "API key", r"sk-[a-f0-9]{32}(?![A-Za-z0-9])",
             "https://platform.deepseek.com/api_keys", None),
    Detector("xAI", "API key", r"xai-[A-Za-z0-9]{20,}",
             "https://console.x.ai/", None),
    Detector("Perplexity", "API key", r"pplx-[A-Za-z0-9]{20,}",
             "https://www.perplexity.ai/settings/api", None),
    Detector("Hugging Face", "API token", r"hf_[A-Za-z0-9]{20,}",
             "https://huggingface.co/settings/tokens", None),
    Detector("Replicate", "API token", r"r8_[A-Za-z0-9]{20,}",
             "https://replicate.com/account/api-tokens", None),
    # No fixed prefix: caught only when the provider name is in the line.
    Detector("Together AI", "API key", r"(?<![A-Za-z0-9])[a-f0-9]{64}(?![A-Za-z0-9])",
             "https://api.together.ai/settings/api-keys", None,
             severity="medium", requires_context="together"),
    # Entropy-only providers (no regex): handled by the fallback classifier.
    Detector("Mistral", "API key (entropy-detected)", None,
             "https://console.mistral.ai/api-keys", None, severity="medium"),
    Detector("Cohere", "API key (entropy-detected)", None,
             "https://dashboard.cohere.com/api-keys", None, severity="medium"),
]
# fmt: on

# Provider keywords used to classify entropy-fallback findings.
CONTEXT_PROVIDERS = [
    ("mistral", "Mistral", "API key (entropy-detected)", "https://console.mistral.ai/api-keys"),
    ("cohere", "Cohere", "API key (entropy-detected)", "https://dashboard.cohere.com/api-keys"),
    ("together", "Together AI", "API key (entropy-detected)", "https://api.together.ai/settings/api-keys"),
    ("openai", "OpenAI", "API key (entropy-detected)", "https://platform.openai.com/api-keys"),
    ("anthropic", "Anthropic", "API key (entropy-detected)", "https://console.anthropic.com/settings/keys"),
    ("gemini", "Google Gemini", "API key (entropy-detected)", "https://aistudio.google.com/api-keys"),
    ("google", "Google Gemini", "API key (entropy-detected)", "https://aistudio.google.com/api-keys"),
    ("groq", "Groq", "API key (entropy-detected)", "https://console.groq.com/keys"),
    ("openrouter", "OpenRouter", "API key (entropy-detected)", "https://openrouter.ai/keys"),
    ("deepseek", "DeepSeek", "API key (entropy-detected)", "https://platform.deepseek.com/api_keys"),
    ("xai", "xAI", "API key (entropy-detected)", "https://console.x.ai/"),
    ("perplexity", "Perplexity", "API key (entropy-detected)", "https://www.perplexity.ai/settings/api"),
    ("hugging", "Hugging Face", "API token (entropy-detected)", "https://huggingface.co/settings/tokens"),
    ("replicate", "Replicate", "API token (entropy-detected)", "https://replicate.com/account/api-tokens"),
]

_FALLBACK_RE = re.compile(
    r"(?i)(api[_-]?key|apikey|access[_-]?token|secret|password|passwd|"
    r"auth[_-]?token|private[_-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})[\"']?"
)


@dataclass
class RawMatch:
    provider: str
    cred_type: str
    value: str
    start: int
    end: int
    console_url: str
    verify_key: str | None
    severity: str
    via: str  # regex | context | entropy


def _resolve_overlaps(matches: list) -> list:
    """Keep the longest match at each start position; drop overlaps."""
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
    kept: list = []
    for m in ordered:
        if any(not (m.end <= k.start or m.start >= k.end) for k in kept):
            continue
        kept.append(m)
    return kept


def _entropy_fallback(line: str, allow_examples: bool = False):
    """Generic secret-looking assignment, gated by entropy + placeholders.

    ``allow_examples`` bypasses the example-key checks (both the new
    ``is_example_key`` filter and the older PLACEHOLDER_WORDS check) —
    used by the self-test to prove detection still works on marked
    fixture values. Real scan paths never set it.
    """
    for m in _FALLBACK_RE.finditer(line):
        value = m.group(2).strip("\"' ")
        if len(value) < MIN_GENERIC_LENGTH:
            continue
        if not allow_examples and is_example_key(value):
            continue
        lowered = value.lower()
        if not allow_examples and any(word in lowered
                                      for word in PLACEHOLDER_WORDS):
            continue
        if shannon_entropy(value) < ENTROPY_THRESHOLD:
            continue
        provider, cred_type, console = _classify_context(line)
        return RawMatch(provider, cred_type, value, m.start(2), m.end(2),
                        console, None, "medium", "entropy")
    return None


def _classify_context(line: str):
    low = line.lower()
    for keyword, provider, cred_type, console in CONTEXT_PROVIDERS:
        if keyword in low:
            return provider, cred_type, console
    return "Unknown (generic)", "Generic API key/token", ""


def scan_line(line: str, allow_examples: bool = False) -> list:
    """Return all credential candidates found in one line of text.

    Values marked as example / test keys (see ``is_example_key``) are
    dropped unless ``allow_examples`` is True. Detection itself is
    unchanged: the regexes still match the value, so
    ``scan_line(line, allow_examples=True)`` proves a marked value is
    still detectable. When every regex match on the line is an example,
    the entropy fallback still runs — and it applies the same filter.
    """
    matches: list = []
    low = line.lower()
    for det in DETECTORS:
        if det.pattern is None:
            continue
        if det.requires_context and det.requires_context not in low:
            continue
        for m in re.finditer(det.pattern, line):
            value = m.group(1) if m.lastindex else m.group(0)
            if not allow_examples and is_example_key(value):
                continue
            via = "context" if det.requires_context else "regex"
            matches.append(RawMatch(det.provider, det.cred_type, value,
                                    m.start(), m.end(), det.console_url,
                                    det.verify_key, det.severity, via))
    matches = _resolve_overlaps(matches)
    if not matches:
        fallback = _entropy_fallback(line, allow_examples=allow_examples)
        if fallback is not None:
            matches.append(fallback)
    return matches


def provider_names() -> list:
    seen = []
    for det in DETECTORS:
        if det.provider not in seen:
            seen.append(det.provider)
    return seen
