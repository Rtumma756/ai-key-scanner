#!/usr/bin/env python3
"""verify_own.py — owner-authorized read-only verification of YOUR OWN keys.

This verifies ONLY keys the user explicitly provides and owns, with an
explicit consent flag. It NEVER verifies keys found in internet scans —
those belong to strangers, and probing them is forbidden.

Inputs (exactly one):
  * a key read from STDIN (never argv — argv is visible in process
    listings), with ``--provider`` naming the provider; or
  * a vault entry selected by fingerprint (``--vault-fingerprint``),
    decrypted with the vault passphrase — the key never leaves the
    process except to the provider's own read-only endpoint.

REQUIRED: ``--i-own-these-keys``. Without it the script refuses to run.
That flag is the operator's explicit statement that the key is theirs
(or they are authorized to test it) and that they accept the read-only
probe hitting the provider.

GUARDS (all enforced before any network call):
  1. No consent flag -> refuse (exit 2).
  2. Any scan-results / findings input -> refuse. That means: a file
     path passed on the command line (there is no --file option at all),
     stdin that parses as JSON containing findings (``"findings"``,
     ``"fingerprint_sha256_16"`` or ``"masked"`` keys), or more than one
     key on stdin. Internet-scan findings are strangers' keys.
  3. A key passed via argv (positional argument) -> refuse; stdin only.
  4. Provider with no read-only verifier in ``verifiers/registry.py``
     -> report ``"unsupported"`` and make NO network call.

The probe itself is ``verifiers.registry.verify_key`` only: a model-list
endpoint, read-only (200 = live, 401/403 = dead, 429 = no_quota). It
never generates text and never spends credits.

Output: one JSON object on stdout — provider, fingerprint, masked,
status (live / no_quota / dead / unknown / unsupported), detail.
The raw key is NEVER printed, logged, or written anywhere.

Optional: ``--mark-verified`` — on a ``live`` result, append the key's
fingerprint to the owner-verified fingerprints file used by
``savings.py`` (``~/.aiscan/verified-fingerprints.json`` by default, or
``--verified-file``). Fingerprints are safe to store; they reveal
nothing about the key. This is the clean hook into owner-verified
savings — no vault crypto is touched.

OPEN FOLLOW-UP (not wired here): ``vault.py`` has no "verified" entry
status — ``set_entry_status`` only accepts ``"rotated"`` / ``"expired"``.
So a live result for a vault entry is reported here (and can be marked
in the verified-fingerprints file with ``--mark-verified``), but the
vault entry itself is NOT updated. Wiring that needs a small vault.py
change (accept a ``"verified"`` status + ``verified_at_utc``) — left
for the vault owner, deliberately not hacked in from this script.

Usage:
  # verify a key you own (type/paste it on stdin; it is never echoed back)
  printf '%s' 'YOUR_KEY_HERE' | python3 verify_own.py \\
      --provider groq --i-own-these-keys

  # verify a key already in your vault, by fingerprint
  python3 verify_own.py --vault-fingerprint ab12cd34ef56ab78 \\
      --i-own-these-keys --mark-verified
  # (passphrase via AISCAN_VAULT_PASS env or an interactive prompt)

  # TESTFAKE keys only in tests — never a real-looking key in a fixture.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import mask_value, value_hash  # noqa: E402
from savings import default_verified_path, is_fingerprint  # noqa: E402
from verifiers import VERIFIERS, verify_key  # noqa: E402

# User-facing aliases for the registry's provider keys.
PROVIDER_ALIASES = {
    "gemini": "google",
    "google-gemini": "google",
    "google gemini": "google",
    "open-ai": "openai",
}

# JSON shapes that mean "this is a scan-results / findings file", not a key.
FINDINGS_JSON_MARKERS = ("findings", "fingerprint_sha256_16", "masked",
                         "potential_savings_estimate")


class Refusal(Exception):
    """A guard fired: refuse before any verification. exit code 2."""


def _looks_like_findings_json(text: str) -> bool:
    """True if stdin parses as JSON shaped like scan results/findings."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return False
    if isinstance(data, dict):
        return any(k in data for k in FINDINGS_JSON_MARKERS)
    if isinstance(data, list):
        return any(isinstance(item, dict)
                   and any(k in item for k in FINDINGS_JSON_MARKERS)
                   for item in data)
    return False


def _read_key_from_stdin(stdin_text: str | None) -> str:
    """Read exactly one key from stdin. Refuses findings JSON / multiples."""
    text = stdin_text if stdin_text is not None else sys.stdin.read()
    stripped = text.strip()
    if not stripped:
        raise Refusal(
            "No key on stdin. Pipe exactly one key, e.g.:\n"
            "  printf '%s' 'YOUR_KEY' | python3 verify_own.py "
            "--provider groq --i-own-these-keys")
    if _looks_like_findings_json(stripped):
        raise Refusal(
            "Refused: stdin looks like a scan-results / findings JSON file. "
            "Those findings are strangers' keys — verification of "
            "internet-scan findings is forbidden. verify_own.py only "
            "verifies keys you explicitly provide and own.")
    lines = [ln for ln in stripped.splitlines() if ln.strip()]
    if len(lines) > 1:
        raise Refusal(
            "Refused: more than one line on stdin. Verify one key at a "
            "time, from stdin only.")
    return lines[0].strip()


def _normalize_provider(name: str) -> str:
    return PROVIDER_ALIASES.get(name.strip().lower(), name.strip().lower())


def _mark_verified(fingerprint: str, path: str) -> bool:
    """Append a fingerprint to the owner-verified file. Returns True if
    it was newly added (False if already present). Fingerprints only —
    never a key."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    existing: list = []
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                existing = data.get("fingerprints", [])
            elif isinstance(data, list):
                existing = data
        except (ValueError, OSError):
            existing = []
    fps = [fp for fp in existing if is_fingerprint(fp)]
    if fingerprint in fps:
        return False
    fps.append(fingerprint)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"fingerprints": sorted(fps)}, f, indent=2)
        f.write("\n")
    os.chmod(path, 0o600)
    return True


def _verify_vault_entry(fingerprint: str, vault_path: str | None,
                        passphrase: str | None) -> tuple[str, str, str]:
    """Decrypt a vault entry by fingerprint. Returns (provider, value,
    entry_id). The value is returned to the caller ONLY — never printed."""
    import vault as vault_mod

    path = vault_path or vault_mod.default_vault_path()
    if passphrase is None:
        passphrase = os.environ.get("AISCAN_VAULT_PASS") or getpass.getpass(
            "Vault passphrase: ")
    if not passphrase:
        raise Refusal("Empty vault passphrase — refusing to open the vault.")
    try:
        entries = vault_mod.list_entries(path)
    except vault_mod.VaultError as e:
        raise Refusal(f"Cannot open vault at {path}: {e}") from None
    entry = next((e for e in entries
                  if e["fingerprint_sha256_16"] == fingerprint.lower()), None)
    if entry is None:
        raise Refusal(
            f"No vault entry with fingerprint {fingerprint}. "
            "List vault entries (masked) with: python3 aiscan.py vault list")
    try:
        _, value = vault_mod.reveal_entry(path, passphrase, entry["id"])
    except vault_mod.VaultError as e:
        raise Refusal(f"Cannot reveal vault entry: {e}") from None
    return entry["provider"], value, entry["id"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="verify_own.py",
        description=(
            "Read-only verification of YOUR OWN API keys. Requires "
            "--i-own-these-keys. Refuses scan-results/findings inputs and "
            "providers with no read-only verifier."),
        epilog=(
            "Never verify a key found in an internet scan — those belong "
            "to strangers. This tool only probes keys you explicitly "
            "provide and own."))
    p.add_argument("--i-own-these-keys", action="store_true",
                   help="REQUIRED consent flag: the key(s) being verified "
                        "are mine / I am authorized to test them")
    p.add_argument("--provider",
                   help="provider key for stdin mode: "
                        + ", ".join(sorted(VERIFIERS)))
    p.add_argument("--vault-fingerprint", metavar="FINGERPRINT",
                   help="verify a vault entry by its 16-hex fingerprint "
                        "instead of stdin (provider comes from the entry)")
    p.add_argument("--vault-file", metavar="FILE",
                   help="vault file (default: ~/.aiscan/vault.json)")
    p.add_argument("--mark-verified", action="store_true",
                   help="on a 'live' result, append the fingerprint to the "
                        "owner-verified fingerprints file (savings.py hook)")
    p.add_argument("--verified-file", metavar="FILE",
                   help="verified-fingerprints file for --mark-verified "
                        "(default: ~/.aiscan/verified-fingerprints.json)")
    return p


def main(argv=None, stdin_text: str | None = None) -> int:
    args, unknown = build_parser().parse_known_args(argv)
    # Guard: there is no file/positional input mode at all. Anything
    # extra on the command line is either a mistake or an attempt to pass
    # a results file / a raw key via argv — refuse either way.
    if unknown:
        print("error: unexpected argument(s): " + " ".join(unknown), file=sys.stderr)
        print("Refused: verify_own.py takes no positional arguments and no "
              "--file option. Keys come from stdin only (or from your vault "
              "by fingerprint). Scan-results files are never accepted.",
              file=sys.stderr)
        return 2
    if not args.i_own_these_keys:
        print("error: --i-own-these-keys is required.", file=sys.stderr)
        print("Refused: verification runs only on keys you own or are "
              "authorized to test, with your explicit consent. Re-run with "
              "--i-own-these-keys to confirm the key being verified is yours.",
              file=sys.stderr)
        return 2

    try:
        if args.vault_fingerprint:
            if not is_fingerprint(args.vault_fingerprint):
                print("error: --vault-fingerprint wants a 16-hex-char "
                      "fingerprint (as shown by `vault list`).",
                      file=sys.stderr)
                return 2
            provider, value, entry_id = _verify_vault_entry(
                args.vault_fingerprint, args.vault_file,
                os.environ.get("AISCAN_VAULT_PASS"))
            source = "vault"
            provider_key = _normalize_provider(provider)
        else:
            if not args.provider:
                print("error: --provider is required in stdin mode "
                      "(or use --vault-fingerprint).", file=sys.stderr)
                return 2
            value = _read_key_from_stdin(stdin_text)
            provider_key = _normalize_provider(args.provider)
            entry_id = None
            source = "stdin"
    except Refusal as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    fingerprint = value_hash(value)[:16]
    result = {
        "provider": provider_key,
        "fingerprint": fingerprint,
        "masked": mask_value(value),
        "status": None,
        "detail": "",
        "source": source,
    }
    if entry_id:
        result["entry_id"] = entry_id

    if provider_key not in VERIFIERS:
        # Unsupported: report it, make NO network call.
        result["status"] = "unsupported"
        result["detail"] = (
            f"no read-only verifier for provider {provider_key!r} "
            f"(supported: {', '.join(sorted(VERIFIERS))})")
        print(json.dumps(result, indent=2))
        return 0

    # The only network call in this tool, and only for an owned key.
    status, detail = verify_key(provider_key, value)
    result["status"] = status
    result["detail"] = detail

    if status == "live" and args.mark_verified:
        path = args.verified_file or default_verified_path()
        added = _mark_verified(fingerprint, path)
        result["marked_verified"] = True
        result["verified_file"] = path
        result["verified_new_entry"] = added

    # Safety: the JSON must never contain the raw key (masked + fp only).
    out = json.dumps(result, indent=2)
    if value and value in out:
        print("error: REDACTION FAILURE — refusing to emit output "
              "containing the raw key.", file=sys.stderr)
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
