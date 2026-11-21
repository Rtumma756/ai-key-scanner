"""Encrypted vault for aiscan findings — admin-only unmask.

Design
-------
The vault stores the UNMASKED key, encrypted at rest. Every other surface
(terminal, JSON/Markdown reports, metrics, logs) shows MASKED keys only.

* Encryption: AES-256-GCM (``cryptography`` package). The vault key is
  derived from an admin passphrase with PBKDF2-HMAC-SHA256 (600,000
  iterations) and a per-vault random salt. The passphrase is NEVER stored;
  only the salt and an encrypted verifier are kept, so a wrong passphrase
  fails loudly at reveal time.
* Vault file (default ``~/.aiscan/vault.json``, overridable with
  ``--vault-file`` / ``AISCAN_VAULT_FILE``): JSON with the KDF header and
  one entry per stored finding. Each entry holds metadata in plaintext
  (provider, masked value, fingerprint, source, status) and exactly two
  secret fields — a random 12-byte nonce and the AES-GCM sealed value
  (ciphertext + tag, base64). The file is written atomically with mode 0600.
* Listing needs NO passphrase (metadata is masked). Revealing needs the
  passphrase and is a separate explicit action.
* Audit log (default ``~/.aiscan/vault-audit.jsonl``): append-only JSON
  lines, one per store / reveal / rotate / expire / purge action, with a
  timestamp, entry id and fingerprint. Full keys are NEVER written to it.

Scope boundary (enforced by the CLI, not just documented)
----------------------------------------------------------
The vault only accepts keys from scans the operator owns or is authorized
to handle — ``scan local`` (your own code) and ``scan internet --demo``
(planted fake data). Live internet findings belong to other people and are
REFUSED for vaulting (``aiscan.py`` errors out). Never vault trial
findings from results/TRIAL_RUN_3.json or any other public-internet run.
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import secrets
import stat
import tempfile
import uuid
from datetime import datetime, timezone

VAULT_VERSION = 1
KDF_ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
VERIFIER_PLAINTEXT = b"aiscan-vault-verifier-v1"

DEFAULT_VAULT_DIR = os.path.join(os.path.expanduser("~"), ".aiscan")
DEFAULT_VAULT_FILE = os.path.join(DEFAULT_VAULT_DIR, "vault.json")
DEFAULT_AUDIT_FILE = os.path.join(DEFAULT_VAULT_DIR, "vault-audit.jsonl")


class VaultError(Exception):
    """Any vault failure: missing file, bad passphrase, bad input."""


class VaultNotInitialized(VaultError):
    """The vault file does not exist yet — run `vault init` first."""


def _require_cryptography():
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: F401
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # noqa: F401
    except ImportError as e:
        raise VaultError(
            "The vault needs the 'cryptography' package, which is not "
            "installed. Install it with:\n"
            "  pip install cryptography\n"
            "Refusing to store anything weakly instead."
        ) from e


def default_vault_path() -> str:
    return os.environ.get("AISCAN_VAULT_FILE", DEFAULT_VAULT_FILE)


def default_audit_path() -> str:
    return os.environ.get("AISCAN_VAULT_AUDIT_FILE", DEFAULT_AUDIT_FILE)


def get_passphrase(prompt: str = "Vault passphrase: ",
                   confirm: bool = False) -> str:
    """Passphrase from env (scripted use) or an interactive prompt (no echo).

    Env var AISCAN_VAULT_PASS exists for automation only; prefer the prompt.
    """
    env = os.environ.get("AISCAN_VAULT_PASS")
    if env:
        return env
    first = getpass.getpass(prompt)
    if confirm:
        second = getpass.getpass("Confirm vault passphrase: ")
        if first != second:
            raise VaultError("Passphrases do not match.")
    if not first:
        raise VaultError("Empty passphrase — refusing to create/use a vault.")
    return first


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=KDF_ITERATIONS)
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt(key: bytes, plaintext: bytes) -> tuple[str, str]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, plaintext, None)
    return (base64.b64encode(nonce).decode("ascii"),
            base64.b64encode(sealed).decode("ascii"))


def _decrypt(key: bytes, nonce_b64: str, sealed_b64: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = base64.b64decode(nonce_b64)
    sealed = base64.b64decode(sealed_b64)
    return AESGCM(key).decrypt(nonce, sealed, None)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)


def _atomic_write_json(path: str, data: dict) -> None:
    _ensure_parent(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)),
                               prefix=".vault-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _append_audit(audit_path: str, action: str, entry_id: str | None,
                  fingerprint: str | None, actor: str = "local-admin",
                  detail: str = "") -> None:
    _ensure_parent(audit_path)
    record = {
        "ts_utc": _now_iso(),
        "action": action,          # init|store|reveal|rotate|expire|purge|list
        "entry_id": entry_id,
        "fingerprint_sha256_16": fingerprint,
        "actor": actor,
        "detail": detail,
    }
    # The audit log never holds a full key: only ids and fingerprints.
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    os.chmod(audit_path, stat.S_IRUSR | stat.S_IWUSR)


def init_vault(vault_path: str, passphrase: str,
               audit_path: str | None = None) -> dict:
    """Create a new vault. Refuses if one already exists at the path."""
    _require_cryptography()
    if os.path.exists(vault_path):
        raise VaultError(
            f"Vault already exists at {vault_path}. Delete it explicitly "
            "if you really want a fresh one (that destroys stored keys).")
    salt = secrets.token_bytes(SALT_BYTES)
    key = _derive_key(passphrase, salt)
    nonce_b64, sealed_b64 = _encrypt(key, VERIFIER_PLAINTEXT)
    data = {
        "version": VAULT_VERSION,
        "kdf": {
            "algorithm": "pbkdf2-sha256",
            "iterations": KDF_ITERATIONS,
            "salt_b64": base64.b64encode(salt).decode("ascii"),
        },
        "verifier": {"nonce_b64": nonce_b64, "sealed_b64": sealed_b64},
        "entries": [],
    }
    _atomic_write_json(vault_path, data)
    _append_audit(audit_path or default_audit_path(), "init", None, None,
                  detail=f"vault created at {vault_path}")
    return data


def load_vault(vault_path: str) -> dict:
    if not os.path.exists(vault_path):
        raise VaultNotInitialized(
            f"No vault at {vault_path}. Run `aiscan.py vault init` first.")
    with open(vault_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("version") != VAULT_VERSION:
        raise VaultError(
            f"Unsupported vault version {data.get('version')} (expected "
            f"{VAULT_VERSION}).")
    return data


def check_passphrase(data: dict, passphrase: str) -> bytes:
    """Verify the passphrase against the stored verifier; return the key."""
    _require_cryptography()
    salt = base64.b64decode(data["kdf"]["salt_b64"])
    key = _derive_key(passphrase, salt)
    try:
        plain = _decrypt(key, data["verifier"]["nonce_b64"],
                         data["verifier"]["sealed_b64"])
    except Exception as e:  # noqa: BLE001 - any AEAD failure = bad passphrase
        raise VaultError("Wrong vault passphrase.") from e
    if plain != VERIFIER_PLAINTEXT:
        raise VaultError("Wrong vault passphrase.")
    return key


def store_finding(vault_path: str, passphrase: str, finding,
                  source_label: str,
                  audit_path: str | None = None) -> dict:
    """Encrypt one finding's full key into the vault. Returns the entry
    metadata (masked only). The same key twice is one entry (dedup by
    fingerprint); the second store just refreshes the source label."""
    _require_cryptography()
    if not getattr(finding, "value", None):
        raise VaultError("Finding has no secret value to store.")
    data = load_vault(vault_path)
    key = check_passphrase(data, passphrase)
    entry_id = f"vlt_{uuid.uuid4().hex[:12]}"
    nonce_b64, sealed_b64 = _encrypt(key, finding.value.encode("utf-8"))
    entry = {
        "id": entry_id,
        "provider": finding.provider,
        "credential_type": getattr(finding, "credential_type", "API key"),
        "masked": finding.masked,
        "fingerprint_sha256_16": finding.fingerprint,
        "source": source_label,
        "file": finding.file_path,
        "line": finding.line_number,
        "severity": finding.severity,
        "status": "active",
        "stored_at_utc": _now_iso(),
        "rotated_at_utc": None,
        "nonce_b64": nonce_b64,
        "sealed_b64": sealed_b64,
    }
    for existing in data["entries"]:
        if existing["fingerprint_sha256_16"] == entry["fingerprint_sha256_16"]:
            # Already vaulted: keep the original entry, refresh its source.
            existing["source"] = source_label
            _atomic_write_json(vault_path, data)
            _append_audit(audit_path or default_audit_path(), "store",
                          existing["id"], existing["fingerprint_sha256_16"],
                          detail="duplicate — entry already vaulted")
            return _public_entry(existing)
    data["entries"].append(entry)
    _atomic_write_json(vault_path, data)
    _append_audit(audit_path or default_audit_path(), "store", entry_id,
                  entry["fingerprint_sha256_16"],
                  detail=f"{finding.provider} key from {source_label}")
    return _public_entry(entry)


def _public_entry(entry: dict) -> dict:
    """The only form of an entry that leaves the vault module: masked."""
    return {
        "id": entry["id"],
        "provider": entry["provider"],
        "credential_type": entry["credential_type"],
        "masked": entry["masked"],
        "fingerprint_sha256_16": entry["fingerprint_sha256_16"],
        "source": entry["source"],
        "file": entry["file"],
        "line": entry["line"],
        "severity": entry["severity"],
        "status": entry["status"],
        "stored_at_utc": entry["stored_at_utc"],
        "rotated_at_utc": entry["rotated_at_utc"],
    }


def list_entries(vault_path: str) -> list:
    """Masked-only list. Needs no passphrase — metadata is not secret."""
    data = load_vault(vault_path)
    return [_public_entry(e) for e in data["entries"]]


def reveal_entry(vault_path: str, passphrase: str, entry_id: str,
                 audit_path: str | None = None) -> tuple[dict, str]:
    """Decrypt one entry. Returns (public metadata, full key). The reveal
    is audit-logged; the full key is returned to the caller ONLY — the
    caller must print it once and never log it."""
    _require_cryptography()
    data = load_vault(vault_path)
    key = check_passphrase(data, passphrase)
    entry = next((e for e in data["entries"] if e["id"] == entry_id), None)
    if entry is None:
        raise VaultError(f"No vault entry with id {entry_id}.")
    try:
        value = _decrypt(key, entry["nonce_b64"],
                         entry["sealed_b64"]).decode("utf-8")
    except Exception as e:  # noqa: BLE001 - AEAD failure = corrupt entry
        raise VaultError(f"Entry {entry_id} failed to decrypt (corrupt?).") from e
    _append_audit(audit_path or default_audit_path(), "reveal", entry_id,
                  entry["fingerprint_sha256_16"],
                  detail=f"{entry['provider']} key revealed by admin")
    return _public_entry(entry), value


def set_entry_status(vault_path: str, entry_id: str, status: str,
                     audit_path: str | None = None) -> dict:
    """Mark an entry rotated or expired. Rotated/expired entries stay in
    the vault (ciphertext intact) until `purge_entries` removes them."""
    if status not in ("rotated", "expired"):
        raise VaultError("status must be 'rotated' or 'expired'.")
    data = load_vault(vault_path)
    entry = next((e for e in data["entries"] if e["id"] == entry_id), None)
    if entry is None:
        raise VaultError(f"No vault entry with id {entry_id}.")
    entry["status"] = status
    entry["rotated_at_utc"] = _now_iso()
    _atomic_write_json(vault_path, data)
    _append_audit(audit_path or default_audit_path(), status, entry_id,
                  entry["fingerprint_sha256_16"],
                  detail=f"entry marked {status}")
    return _public_entry(entry)


def purge_entries(vault_path: str, days: int = 30,
                  audit_path: str | None = None) -> list:
    """Delete rotated/expired entries older than `days` (default 30).
    Returns the purged entry ids (masked metadata only)."""
    from datetime import timedelta
    data = load_vault(vault_path)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    kept, purged = [], []
    for entry in data["entries"]:
        if entry["status"] in ("rotated", "expired") and entry.get("rotated_at_utc"):
            when = datetime.fromisoformat(entry["rotated_at_utc"])
            if when <= cutoff:
                purged.append(entry)
                continue
        kept.append(entry)
    data["entries"] = kept
    _atomic_write_json(vault_path, data)
    for entry in purged:
        _append_audit(audit_path or default_audit_path(), "purge",
                      entry["id"], entry["fingerprint_sha256_16"],
                      detail=f"purged {entry['status']} entry")
    return [e["id"] for e in purged]


def read_audit(audit_path: str) -> list:
    """Read the append-only audit log (never contains full keys)."""
    if not os.path.exists(audit_path):
        return []
    out = []
    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def assert_vault_redacted(vault_path: str, values: list) -> list:
    """Test helper: return any full secret value found as plaintext in the
    vault file or audit log. Empty list = clean."""
    leaked = []
    paths = [vault_path, default_audit_path()]
    for path in paths:
        if not os.path.exists(path):
            continue
        raw = open(path, "rb").read()
        for value in values:
            if value and value.encode("utf-8") in raw:
                leaked.append((path, value[:8] + "..."))
    return leaked
