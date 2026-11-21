"""MCP / agent config scanner: structured agent identity inventory.

Parses:
  * ``.mcp.json`` (and any ``*mcp.json``) — one agent per server entry
    under ``mcpServers`` (plus a file-level entry when there are none).
  * Claude Code settings — ``.claude.json``, ``.claude/settings.json``,
    ``.claude/settings.local.json``.
  * Cursor — ``.cursor/mcp.json``, ``.cursorrules``, ``.cursor/rules/*``.
  * Generic agent config files — any other ``*.json`` / ``*.jsonc`` that
    mentions ``mcpServers`` or an ``env`` block holding credential-like
    names.

Credential extraction, per value:
  * A string value matching a detector pattern (``detectors.scan_line``)
    is a credential: provider + fingerprint (SHA-256 first 16 hex) +
    prefix4 masked form. The raw value is discarded immediately and
    never appears in the output.
  * A value marked as an example / test key (``is_example_key``) is
    skipped — never reported as a credential.
  * An env-var reference (``${VAR}`` / ``$VAR``) or an env-dict key whose
    name looks credential-like (``*_API_KEY``, ``*_TOKEN``, ``*_SECRET``,
    provider names) is recorded as a reference with provider inferred
    from the name and no fingerprint — the value itself is not present
    in the config, so there is nothing to fingerprint.
  * Plain env-dict keys that are not credential-like are ignored.

Output shapes (JSON-safe, fingerprint/masked only):
  inventory: {"path", "agents": [Agent], "summary": {...}}
  mapping:   inventory + {"repo", "owner"} per agent, plus
             "exposed_count" per agent (fingerprints also seen in local
             scan results under <path>/results or the CLI results dir).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from common import mask_value, value_hash
from detectors import is_example_key, scan_line

# Env-var names that look like credentials. Matched case-insensitively
# as a substring; deliberately narrow so ordinary config keys
# (e.g. "timeout", "model") are not reported as credentials.
CREDENTIAL_NAME_HINTS = (
    "api_key", "apikey", "api-key", "access_token", "auth_token",
    "token", "secret", "password", "private_key", "client_secret",
)
PROVIDER_KEYWORDS = (
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic"),
    ("gemini", "Google Gemini"),
    ("google", "Google Gemini"),
    ("groq", "Groq"),
    ("openrouter", "OpenRouter"),
    ("deepseek", "DeepSeek"),
    ("xai", "xAI"),
    ("perplexity", "Perplexity"),
    ("hugging", "Hugging Face"),
    ("hf_", "Hugging Face"),
    ("replicate", "Replicate"),
    ("mistral", "Mistral"),
    ("cohere", "Cohere"),
    ("together", "Together AI"),
)

_ENV_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_JSONC_COMMENT_RE = re.compile(r"(?m)^\s*//.*$")


def _provider_for_name(name: str) -> str:
    lowered = name.lower()
    for keyword, provider in PROVIDER_KEYWORDS:
        if keyword in lowered:
            return provider
    return "Unknown"


def _looks_credential_name(name: str) -> bool:
    lowered = name.lower()
    if any(hint in lowered for hint in CREDENTIAL_NAME_HINTS):
        return True
    return any(keyword in lowered for keyword, _ in PROVIDER_KEYWORDS
               if keyword in ("openai", "anthropic", "groq", "deepseek",
                              "gemini", "openrouter", "mistral", "cohere",
                              "perplexity", "replicate", "hugging"))


def _credential_from_value(value: str, source: str, env_var: str = "") -> dict | None:
    """Fingerprint one string value in-memory; return the public record
    (provider + fingerprint + masked only) or None when it is not a
    reportable credential. The raw value never leaves this function."""
    if not isinstance(value, str) or not value:
        return None
    if is_example_key(value):
        return None
    matches = scan_line(value)
    if not matches:
        return None
    match = matches[0]
    return {
        "provider": match.provider,
        "credential_type": match.cred_type,
        "fingerprint": value_hash(value)[:16],
        "masked": mask_value(value),
        "source": source,
        "env_var": env_var,
    }


def _env_ref_credential(name: str, source: str) -> dict:
    """A reference to a credential held elsewhere (env var): provider
    inferred from the name, no fingerprint — there is no value here."""
    return {
        "provider": _provider_for_name(name),
        "credential_type": "env var reference",
        "fingerprint": "",
        "masked": "",
        "source": source,
        "env_var": name,
    }


def _walk_value(node, source: str, out: list[dict], seen: set[str]) -> None:
    """Recursively extract credentials from a parsed JSON value."""
    if isinstance(node, dict):
        for key, val in node.items():
            key_str = str(key)
            if isinstance(val, str):
                # Env-var reference: "$VAR" / "${VAR}" — no value present.
                refs = _ENV_REF_RE.findall(val)
                if refs and _looks_credential_name(key_str):
                    for ref in refs:
                        name = ref[0] or ref[1]
                        if _looks_credential_name(name):
                            rec = _env_ref_credential(name, source)
                            dedup = (rec["provider"], rec["env_var"], "")
                            if dedup not in seen:
                                seen.add(dedup)
                                out.append(rec)
                    continue
                if _looks_credential_name(key_str):
                    rec = _credential_from_value(val, source, env_var=key_str)
                    if rec is not None:
                        dedup = (rec["provider"], "", rec["fingerprint"])
                        if dedup not in seen:
                            seen.add(dedup)
                            out.append(rec)
                    elif val and not _ENV_REF_RE.search(val):
                        # Credential-named key whose value did not match a
                        # detector (e.g. an env-var name as the value, or
                        # a short/rotated value): record as a reference
                        # only when the value itself looks like a var name.
                        if re.fullmatch(r"[A-Z][A-Z0-9_]*", val.strip()):
                            rec = _env_ref_credential(val.strip(), source)
                            dedup = (rec["provider"], rec["env_var"], "")
                            if dedup not in seen:
                                seen.add(dedup)
                                out.append(rec)
                    continue
                # Any other string value: still check for an embedded key.
                rec = _credential_from_value(val, source)
                if rec is not None:
                    dedup = (rec["provider"], "", rec["fingerprint"])
                    if dedup not in seen:
                        seen.add(dedup)
                        out.append(rec)
            else:
                _walk_value(val, source, out, seen)
    elif isinstance(node, list):
        for item in node:
            _walk_value(item, source, out, seen)
    elif isinstance(node, str):
        rec = _credential_from_value(node, source)
        if rec is not None:
            dedup = (rec["provider"], "", rec["fingerprint"])
            if dedup not in seen:
                seen.add(dedup)
                out.append(rec)


def _load_json_lenient(path: Path):
    """Parse JSON, tolerating // comments and trailing commas (JSONC)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        cleaned = _JSONC_COMMENT_RE.sub("", text)
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        return json.loads(cleaned)


def classify_config(path: Path) -> str | None:
    """Agent type for a config file, or None when it is not one."""
    name = path.name
    parts = path.parts
    if name in (".mcp.json",) or name.endswith("mcp.json"):
        return "mcp-server"
    if name in (".claude.json", "settings.json", "settings.local.json") and (
        ".claude" in parts or name == ".claude.json"
    ):
        return "claude-code"
    if name == ".claude.json":
        return "claude-code"
    if ".cursor" in parts:
        return "cursor"
    if name == ".cursorrules":
        return "cursor"
    return None


def find_agent_configs(root: Path) -> list[Path]:
    """All agent config files under ``root`` (file or directory)."""
    if root.is_file():
        return [root] if classify_config(root) or _is_generic_agent_config(root) else []
    found: list[Path] = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in filenames:
            candidate = Path(dirpath) / filename
            if classify_config(candidate) or _is_generic_agent_config(candidate):
                found.append(candidate)
    return sorted(found)


def _is_generic_agent_config(path: Path) -> bool:
    """A JSON/JSONC file (not already classified) that mentions
    mcpServers or holds a credential-named env block."""
    if path.suffix.lower() not in (".json", ".jsonc"):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "mcpServers" in text or "mcp_servers" in text


def scan_config_file(path: Path) -> list[dict]:
    """Public credential records for one config file.

    One dict per agent entry in the file: {"name", "type",
    "config_path", "credentials": [...]}. For ``.mcp.json`` each server
    under ``mcpServers`` is its own agent; other files yield one agent.
    Returns [] when the file is not an agent config or is unparseable.
    """
    path = Path(path)
    agent_type = classify_config(path)
    is_generic = agent_type is None and _is_generic_agent_config(path)
    if agent_type is None and not is_generic:
        return []
    if agent_type is None:
        agent_type = "mcp-server"
    rel = str(path)

    # Cursor rules are Markdown/text: scan line by line for keys / refs.
    if agent_type == "cursor" and path.suffix.lower() not in (".json", ".jsonc"):
        creds: list[dict] = []
        seen: set[str] = set()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for line in lines:
            for ref in _ENV_REF_RE.findall(line):
                name = ref[0] or ref[1]
                if _looks_credential_name(name):
                    rec = _env_ref_credential(name, "cursor-rules")
                    dedup = (rec["provider"], rec["env_var"], "")
                    if dedup not in seen:
                        seen.add(dedup)
                        creds.append(rec)
            for match in scan_line(line):
                value = line[match.start:match.end]
                # The example marker may sit outside the matched
                # substring (e.g. "TESTFAKE-gsk_..."): check the whole
                # token containing the match, not just the match itself.
                tok_start = match.start
                while tok_start > 0 and line[tok_start - 1] not in " \t\"'":
                    tok_start -= 1
                tok_end = match.end
                while tok_end < len(line) and line[tok_end] not in " \t\"'":
                    tok_end += 1
                if is_example_key(line[tok_start:tok_end]):
                    continue
                rec = {
                    "provider": match.provider,
                    "credential_type": match.cred_type,
                    "fingerprint": value_hash(value)[:16],
                    "masked": mask_value(value),
                    "source": "cursor-rules",
                    "env_var": "",
                }
                dedup = (rec["provider"], "", rec["fingerprint"])
                if dedup not in seen:
                    seen.add(dedup)
                    creds.append(rec)
        name = "cursor" if path.name == ".cursorrules" else path.stem
        return [{"name": name, "type": "cursor", "config_path": rel,
                 "credentials": creds}]

    try:
        data = _load_json_lenient(path)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    servers = data.get("mcpServers") or data.get("mcp_servers")
    if isinstance(servers, dict) and servers:
        agents = []
        for server_name, server_cfg in servers.items():
            creds: list[dict] = []
            _walk_value(server_cfg, "mcp-server-env", creds, set())
            agents.append({
                "name": str(server_name),
                "type": "mcp-server",
                "config_path": rel,
                "credentials": creds,
            })
        return agents

    creds = []
    _walk_value(data, "agent-config", creds, set())
    if agent_type == "claude-code":
        agent_name = "claude-code"
    elif agent_type == "cursor":
        agent_name = "cursor"
    else:
        agent_name = path.stem
    return [{"name": agent_name, "type": agent_type, "config_path": rel,
             "credentials": creds}]


def load_result_fingerprints(search_roots: list[Path]) -> dict[str, dict]:
    """Fingerprint -> row info from local scan results JSON files.

    Reads ``results/*.json`` under each search root (rows may be a
    top-level list or a dict with a ``rows`` list). Only fingerprint /
    provider / file / line are kept — never key material.
    """
    found: dict[str, dict] = {}
    for root in search_roots:
        results_dir = Path(root) / "results"
        if not results_dir.is_dir():
            continue
        for json_file in sorted(results_dir.glob("*.json")):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            rows = data if isinstance(data, list) else (
                data.get("rows") if isinstance(data, dict) else None)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                fp = row.get("fingerprint_sha256_16") or row.get("fingerprint")
                if isinstance(fp, str) and len(fp) == 16:
                    found[fp.lower()] = {
                        "provider": str(row.get("provider", "") or ""),
                        "file": str(row.get("file", "") or ""),
                        "line": row.get("line", 0),
                        "masked": str(row.get("masked", "") or ""),
                    }
    return found


def build_inventory(root: str | Path) -> dict:
    """Structured inventory for ``root`` (file or directory)."""
    root_path = Path(root)
    agents: list[dict] = []
    for config in find_agent_configs(root_path):
        agents.extend(scan_config_file(config))
    total_creds = sum(len(a["credentials"]) for a in agents)
    with_fp = sum(1 for a in agents for c in a["credentials"] if c["fingerprint"])
    return {
        "path": str(root_path),
        "agents": agents,
        "summary": {
            "agent_count": len(agents),
            "credential_count": total_creds,
            "with_fingerprint": with_fp,
            "env_var_references": total_creds - with_fp,
        },
    }


def _infer_owner_repo(root: Path) -> tuple[str, str]:
    """(repo, owner) from git config: remote origin owner/repo, else
    git user.name, else ("", "unknown"). Never raises."""
    repo = ""
    owner = "unknown"
    try:
        remote = subprocess.run(
            ["git", "-C", str(root), "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if remote:
            m = re.search(r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?$", remote)
            if m:
                owner, repo = m.group(1), f"{m.group(1)}/{m.group(2)}"
            else:
                repo = remote
    except Exception:
        pass
    if owner == "unknown":
        try:
            user = subprocess.run(
                ["git", "-C", str(root), "config", "--get", "user.name"],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()
            if user:
                owner = user
        except Exception:
            pass
    return repo, owner


def build_mapping(root: str | Path, results_roots: list[str | Path] | None = None) -> dict:
    """Agent -> credential -> repo -> owner mapping, with exposed counts.

    ``exposed_count`` per agent = credentials whose fingerprint also
    appears in local scan results (``results/*.json`` under the scanned
    path and the CLI repo dir).
    """
    root_path = Path(root)
    inventory = build_inventory(root_path)
    cli_dir = Path(__file__).resolve().parent.parent
    search_roots = [root_path, cli_dir]
    if results_roots:
        search_roots.extend(Path(r) for r in results_roots)
    exposed = load_result_fingerprints(search_roots)
    repo, owner = _infer_owner_repo(root_path if root_path.is_dir() else root_path.parent)
    for agent in inventory["agents"]:
        agent["repo"] = repo
        agent["owner"] = owner
        agent["exposed_count"] = sum(
            1 for c in agent["credentials"]
            if c["fingerprint"] and c["fingerprint"] in exposed
        )
        agent["exposed"] = [
            {"fingerprint": c["fingerprint"], "provider": c["provider"]}
            for c in agent["credentials"]
            if c["fingerprint"] and c["fingerprint"] in exposed
        ]
    inventory["repo"] = repo
    inventory["owner"] = owner
    return inventory
