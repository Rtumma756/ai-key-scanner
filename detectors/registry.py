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


def _entropy_fallback(line: str):
    """Generic secret-looking assignment, gated by entropy + placeholders."""
    for m in _FALLBACK_RE.finditer(line):
        value = m.group(2).strip("\"' ")
        if len(value) < MIN_GENERIC_LENGTH:
            continue
        lowered = value.lower()
        if any(word in lowered for word in PLACEHOLDER_WORDS):
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


def scan_line(line: str) -> list:
    """Return all credential candidates found in one line of text."""
    matches: list = []
    low = line.lower()
    for det in DETECTORS:
        if det.pattern is None:
            continue
        if det.requires_context and det.requires_context not in low:
            continue
        for m in re.finditer(det.pattern, line):
            value = m.group(1) if m.lastindex else m.group(0)
            via = "context" if det.requires_context else "regex"
            matches.append(RawMatch(det.provider, det.cred_type, value,
                                    m.start(), m.end(), det.console_url,
                                    det.verify_key, det.severity, via))
    matches = _resolve_overlaps(matches)
    if not matches:
        fallback = _entropy_fallback(line)
        if fallback is not None:
            matches.append(fallback)
    return matches


def provider_names() -> list:
    seen = []
    for det in DETECTORS:
        if det.provider not in seen:
            seen.append(det.provider)
    return seen
