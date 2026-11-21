# KeySentry — Responsible Disclosure

When KeySentry finds an AI API key in public code, the key belongs to
someone else. This document states how we tell them, what we send, and
what happens next. The raw key is never part of any notification.

## What we send the owner

A notification contains only:

- The **masked key** (first 4 characters + `...`).
- The **fingerprint** (SHA-256, first 16 hex) so the owner can match it
  against their own keys without us ever showing the key.
- The **file location** (repository, file path, line number) where the key
  was found, and the date it was first seen.
- **Remediation steps:** rotate the key now, revoke the old one, remove
  the key from the code and from git history, check provider usage and
  billing for unexpected activity, move the secret to environment
  variables or a secret manager, and enable push protection.
- A way to reply: confirm the key is rotated, tell us it is not a live
  key, or ask us to delete our record of the finding.

A notification never contains the raw key, the full key, or the ends of
the key.

## How owners are contacted

- **If the owner is identifiable** (for example, the repository owner or a
  contact listed in the repository), we contact them directly through the
  channel they publish — repository contact, security policy, or public
  email. We send one notification, not repeated reminders.
- **If the owner cannot be identified**, we do not guess. The finding
  stays in our masked-only records, and no notification is sent.
- **If the owner is a KeySentry customer** (their fingerprint is
  registered for monitoring), they get an alert through their chosen
  channel instead — email in the pilot, Slack on the Team tier.
- We do not contact a provider (OpenAI, Anthropic, and so on) about an
  individual key. Rotation is the owner's decision.

## What happens when the owner replies

- **"Rotated."** We mark the finding `rotated`, stop including it in
  counts of exposed keys, and keep only the masked value and fingerprint
  for the audit trail. The entry becomes eligible for purge under the
  30-day rule (see `SECURITY.md`).
- **"Not a live key" / "Not ours."** We mark the finding accordingly. If
  it was a false positive, we record the pattern so the detector can be
  improved, and we do not re-notify about the same fingerprint at the
  same location.
- **"Delete your record."** We delete the finding record. The audit trail
  keeps only the fingerprint and the fact of deletion — no key material.
- **No reply.** We do not chase. The finding stays marked as exposed in
  our records, and we re-check it only by unauthenticated raw re-fetch
  of the public file. We never test the key against a provider.

## The audit trail

Every notification and every owner reply is logged with: date, masked
value, fingerprint, file location, channel used, and outcome
(rotated / not-live / deleted / no reply). The log never holds a raw key.
This trail is what turns a "candidate" saving into an owner-verified one:
a key counts as verified only when its owner confirms it.

## Honest limits

- **We cannot prove a key is live.** Our re-check confirms the key is
  still exposed in public code. Only the owner can confirm it still
  works. All savings figures built on internet findings are candidate
  estimates until owners confirm them. Owner-verified savings to date:
  **$0**.
- **We cannot force rotation.** We can notify and advise. The owner
  decides.
- **We cannot reach every owner.** Some repositories have no usable
  contact. Those findings are recorded masked-only and never disclosed
  further.
- **We do not publish findings.** Masked findings appear only in
  aggregate, anonymized reports (counts by provider, candidate savings).
  Individual keys — even masked — are never published with enough detail
  to identify the owner.
