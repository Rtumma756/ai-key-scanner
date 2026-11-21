"""Read-only verifiers: probe a provider's model-list / balance endpoint.

These calls NEVER generate anything and never spend credits — they only ask
the provider whether the credential is accepted. HTTP semantics:
  200  -> live (key accepted)
  401/403 -> dead (revoked or invalid)
  429  -> valid but quota exhausted
  anything else / network error -> unknown

Verification must only ever run on keys the user owns or is authorized to
test. It is OFF by default everywhere in aiscan.
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

# provider key -> (endpoint, auth mode). "query" puts the key in ?key= (the
# only auth method the Gemini REST API offers for key auth).
VERIFIERS = {
    "openai": ("https://api.openai.com/v1/models", "bearer"),
    "groq": ("https://api.groq.com/openai/v1/models", "bearer"),
    "openrouter": ("https://openrouter.ai/api/v1/models", "bearer"),
    "google": ("https://generativelanguage.googleapis.com/v1beta/models", "query"),
}


def verify_key(provider_key: str, value: str, timeout: int = 10):
    """Return (status, detail). Status: live | no_quota | dead | unknown."""
    if provider_key not in VERIFIERS:
        return ("unsupported", "no read-only verifier for this provider")
    url, mode = VERIFIERS[provider_key]
    try:
        if mode == "bearer":
            req = urllib.request.Request(
                url, headers={"Authorization": f"Bearer {value}"})
        else:
            req = urllib.request.Request(
                url + "?key=" + urllib.parse.quote(value))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return ("live", f"HTTP {resp.status} — key accepted")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return ("dead", f"HTTP {e.code} — revoked or invalid")
        if e.code == 429:
            return ("no_quota", "HTTP 429 — key valid, quota exhausted")
        return ("unknown", f"HTTP {e.code}")
    except Exception as e:  # network error, timeout, DNS, ...
        return ("unknown", f"request failed: {e}")
