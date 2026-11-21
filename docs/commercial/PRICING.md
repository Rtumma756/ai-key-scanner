# KeySentry — Pricing

Three paid tiers for business use. The internet scanner, the CLI, and the
web scanner are free. Prices are not set yet — see the note at the end.

## What is free

- **Internet mode (CLI):** sweep public GitHub code search for exposed
  keys, including the demo dataset (no token, no network) and presets for
  `.mcp.json` files and notebooks.
- **Local scans (CLI):** scan your own repos and git history, with
  Markdown remediation reports.
- **Web scanner:** https://key-sentry-inky.vercel.app — same masked-only
  rules as the CLI.
- **Vault (CLI):** encrypted storage for your own findings, admin-only
  reveal, audit log.

Free use is for your own keys and your own code. Keys found in public code
belong to other people: they are never vaulted, never unmasked, and never
tested against a provider.

## The tiers

| Feature | Starter | Team | Business |
|---|---|---|---|
| Organizations | 1 | 1 | Multiple |
| Repos scanned | Up to 5 | Unlimited | Unlimited |
| Fingerprint monitoring | Yes | Yes | Yes |
| Email alerts | Yes | Yes | Yes |
| Slack alerts | No | Yes | Yes |
| Remediation workflow | No | Yes | Yes |
| Owner verification | No | Yes | Yes |
| SSO | No | No | Yes |
| Audit logs | No | No | Yes |
| Policy controls | No | No | Yes |
| Reporting | No | Basic | Full |
| SLA | No | No | Yes |
| Private deployment | No | No | Yes |

- **Starter** — one org, up to 5 repos, fingerprint monitoring, email
  alerts. For a small team that wants to know when its own keys leak.
- **Team** — unlimited repos, Slack alerts, remediation workflow, owner
  verification. For a team that fixes leaks as part of its normal work.
- **Business** — SSO, audit logs, policy controls, reporting, SLA,
  private deployment. For organizations with compliance and uptime
  requirements.

## What is explicitly NOT promised

- **No guarantee a key is live.** A finding means the key is still
  exposed in public code. Only the owner can confirm it still works.
  Owner-verified savings to date: **$0**.
- **Savings figures are candidate estimates.** The figures quoted for
  internet findings — $7,103.07 / $376,955.44 / $3,010,248.90
  (conservative / expected / worst-case, across 612 distinct real-looking
  keys) — are estimates of what those keys could cost if abused. They are
  not money saved, and they are not a promise about any customer's keys.
- **No replacement for existing scanners.** KeySentry is an add-on to a
  customer's existing CI scanners. It catches AI-specific keys and leaks
  outside the pipeline. It does not replace general secret scanning.
- **No detection guarantee.** No scanner catches every leak. Missed
  detections are a known limit, and we track them openly (see the
  missed-detection issue template).
- **No uptime promise on free tiers.** The free web scanner runs on
  Vercel Hobby and Neon free Postgres. The SLA exists only on the
  Business tier.

## Prices — not set yet

No dollar prices have been set for Starter, Team, or Business. The pilot
is free, and pricing will be set from what the pilot teams say the
fingerprint monitoring is worth to them. This file will be updated when
prices exist. Until then, any price quoted anywhere else should be treated
as a placeholder, not a commitment.
