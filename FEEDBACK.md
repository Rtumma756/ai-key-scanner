# Feedback — what helps most

aiscan is a prototype. The most useful feedback is concrete: a real
detection it missed, a false positive it raised, a provider whose keys
it does not recognise, or a source worth adding. Every issue type has a
template in `.github/ISSUE_TEMPLATE/` — use it, it asks for exactly
what is needed and nothing more.

## What to send

### 1. Missed detections (highest value)
A key the scanner did not flag. Include:
- Provider (e.g. OpenAI, Groq, Together AI)
- File type it was in (`.env`, `.mcp.json`, `.py`, notebook, Docker
  image layer, npm package…)
- The key **masked only**: first 4 characters `...` rest hidden
  (e.g. `sk-proj-...a9b0`). **Never paste a full key.** If the key is
  real and still live, revoke it first, then report it.
- What the line looked like (with the secret masked the same way)

### 2. False positives
Something flagged that is not a secret. Include:
- What was flagged (masked the same way) and what it actually is
  (UUID, hash, test fixture, placeholder, minified bundle…)
- The file type and the surrounding line (masked)

### 3. New providers / key formats
A provider whose keys aiscan does not detect. Include:
- Provider name and docs link for the key format (if public)
- The key's shape: prefix, length, character set — with a clearly
  fake example, never a real key
- The provider's key-management console URL (for remediation links)

### 4. New sources
A public source worth scanning. Include:
- What it is and why keys leak there
- Whether it has a free API / public feed (aiscan is free-tiers only —
  a source that needs a paid key will be documented in
  `sources/roadmap.md`, not implemented)

### 5. Bugs
The command you ran, the error (full traceback if any), Python version
(`python3 --version`), and OS.

## What NOT to send

- **Never a full API key, token, or password** — yours or anyone
  else's. Masked samples only. If you paste a real key by accident,
  revoke it immediately and tell us so the issue can be scrubbed.
- **No live keys to "test".** Verification (`--verify`) is only for
  keys you own or are authorized to test, and it is read-only.

## Privacy

aiscan runs locally and uploads nothing. The only network calls it ever
makes are the ones you explicitly trigger:
- A source fetch you asked for (GitHub code search, Docker Hub, gists,
  npm, PyPI, Pastebin, Stack Overflow, Common Crawl).
- A read-only verification probe, only with `--verify` (off by default),
  only for keys you own or are authorized to test.

Findings are written only where you tell the tool to write them
(`--output`, `--metrics-file`). Nothing is phoned home.
