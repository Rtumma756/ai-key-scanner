# KeySentry — Security Policy

KeySentry scans for leaked AI API keys. This policy states what we store,
what we never store, and how we handle secrets. It applies to the CLI
(`~/workspace/ai-key-scanner/`), the web app
(https://key-sentry-inky.vercel.app), and the business (pilot) service.

## The one rule

A raw API key is never stored, logged, emailed, or shown — except inside the
owner's own encrypted vault, as described below. Everything else that leaves
a scan is a masked value and a fingerprint.

## What is stored

- **Masked value.** The first 4 characters of a key, then `...`
  (for example, `sk-p...`). This is the default display everywhere.
- **Fingerprint.** The first 16 hex characters of the SHA-256 hash of the
  full key value (`hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]`).
  A fingerprint identifies a key without revealing it. Two copies of the
  same key have the same fingerprint, so findings are deduplicated on it.
- **Finding metadata.** Provider, credential type, file path, line number,
  a redacted snippet, severity, source, and verification status. The
  snippet is redacted by the scanner before it is stored. The only
  serialized form of a finding (`public_dict`) never includes the secret.
- **Owner's vault (own keys only).** When a business customer stores its
  own findings with `--vault`, the vault holds the masked value, the
  fingerprint, and the key sealed as ciphertext with AES-256-GCM
  (12-byte random nonce, passphrase-derived key). Revealing a vault entry
  needs the admin passphrase and is written to an append-only audit log.
  Listing the vault needs no passphrase, because listings show masked
  values only.
- **Audit log.** Append-only lines for vault actions (init, store, reveal,
  rotate, expire, purge). The log holds entry IDs and fingerprints only —
  never a full key.

## What is NEVER stored

- Raw API keys or tokens, in any file, database, report, log, or email —
  except as AES-256-GCM ciphertext inside the owner's own vault (above).
- Full keys belonging to anyone other than the customer. Live internet
  findings are never vaulted: the CLI refuses `--vault` on live internet
  scans, because those keys belong to other people.
- Passphrases. The vault passphrase is held in memory only while a vault
  command runs.
- Unmasked ("ends") views of strangers' keys. See masking below.

## How masking works

- **Default: `prefix4`.** First 4 characters shown, the rest replaced
  with `...`. This is the default in every report, screen, and email.
- **`ends` mode: own keys only.** Showing the ends of a key is allowed
  only for the customer's own keys, in their own vault, with the admin
  passphrase. It is never used for keys found in public code.
- A key value exists in full only in memory during a scan. It is never
  written to disk, a report, or a log in plain text.

## Strangers' keys are never tested

A key found in public code is never sent to any provider to check whether
it works. Liveness of internet findings is checked only by an
unauthenticated raw re-fetch of the public file — that confirms the key is
still exposed, not that it is live. A key counts as "live" only when its
owner confirms it.

## Fingerprint monitoring

A customer can register fingerprints of its own keys (SHA-256, first
16 hex). The scanner then watches public sources for those fingerprints
and alerts when one appears. The fingerprint alone cannot reconstruct the
key, and registering it does not disclose the key to KeySentry.

## Data retention

- **CLI vault:** an entry marked `rotated` or `expired` stays in the vault
  until purged. `vault purge` deletes rotated/expired entries older than
  30 days (default). Purged entries are gone; the audit log keeps only the
  entry ID and fingerprint.
- **Scan reports:** local scan reports live on the customer's machine and
  are theirs to delete. KeySentry does not keep a copy.
- **Web app (Neon Postgres, free tier):** the vault is empty by default and
  holds only entries a customer stores deliberately. No retention period
  for web-app data has been set yet — see the gap note at the end of this
  file.

## Infrastructure

- Free-only infrastructure: Vercel Hobby (web app) and Neon free Postgres
  (vault database). No paid services hold customer data.
- The scanner is an add-on to a customer's existing CI scanners, not a
  replacement. It catches what slips past: AI-specific keys and leaks
  outside the pipeline (contractor repos, gists, repos made public after
  the fact).

## Reporting a vulnerability

If you find a security problem in KeySentry, do not open a public issue.

- **How to report:** email the maintainer. No dedicated security contact
  address has been published yet — see the gap note below.
- **What to include:** what you found, where, and how to reproduce it.
  Do not include a real API key in your report. Use a masked value and a
  fingerprint.
- **What happens next:** we confirm receipt, fix the issue, and tell you
  when the fix is live. We do not publish details of a vulnerability
  before a fix is available.

## Gaps in this policy (not yet decided)

- **No security contact address yet.** No `security@` address or reporting
  form exists. One must be published before the pilot starts.
- **No web-app retention period yet.** The 30-day purge rule above covers
  the CLI vault only. A retention period for web-app vault data and for
  pilot accounts has not been set.
- **No incident-response owner named yet.** Who is paged, and in what
  order, if a vault is suspected compromised, is not yet written down.
