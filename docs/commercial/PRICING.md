# KeySentry — Pricing

Eight tiers, Free to Enterprise. The internet scanner, the CLI, and the
web scanner are free; the paid tiers add monitoring, alerts, workflow,
and compliance. Prices below are **proposals to be validated by pilots**
— see the note at the end.

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

| Feature | Free | Maker | Starter | Premium | Team | Premium Plus | Business | Enterprise |
|---|---|---|---|---|---|---|---|---|
| Price | $0 | $19/mo | $49/mo | $99/mo | $149/mo | $299/mo | $499/mo | Custom |
| Repos scanned | 1 | 5 apps | 5 | 15 | Unlimited | Unlimited | Unlimited | Unlimited |
| Fingerprints | 5 | 5 | 25 | 75 | Unlimited | Unlimited | Unlimited | Unlimited |
| Scans & audits | 2/day each | Unlimited scans, 2 audits/day | Unlimited | Unlimited | Unlimited | Unlimited | Unlimited | Unlimited |
| MCP queries | 100/day | Unlimited | Unlimited | 5,000/day | Unlimited | Unlimited | Unlimited | Unlimited |
| Audit history | 7 days | 30 days | 30 days | 60 days | 90 days | 180 days | 7 years | Custom |
| Seats | 1 | 1 | 1 | 5 | 5 | 25 | Unlimited | Custom |
| Fingerprint monitoring | No | No | Yes | Yes | Yes | Yes | Yes | Yes |
| Email alerts | No | No | Yes | Yes | Yes | Yes | Yes | Yes |
| Vibe-code monitoring | No | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Fix PRs | No | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Slack alerts | No | No | No | Yes | Yes | Yes | Yes | Yes |
| Remediation workflow | No | No | No | Yes | Yes | Yes | Yes | Yes |
| Owner verification | No | No | No | No | Yes | Yes | Yes | Yes |
| API access | No | No | No | No | No | Yes | Yes | Yes |
| Priority support | No | No | No | No | No | Yes | Yes | Yes |
| Audit logs | No | No | No | No | No | No | Yes | Yes |
| Compliance export | No | No | No | No | No | No | Yes | Yes |
| Policy controls | No | No | No | No | No | No | Yes | Yes |
| SLA | No | No | No | No | No | No | Yes | Yes |
| SSO | No | No | No | No | No | No | No | Yes |
| Private deployment | No | No | No | No | No | No | No | Yes |

- **Free** — scanner, one-repo audits (identity + vibe), one-agent
  timeline (last 7 days), 5 fingerprints. Daily caps: 2 scans, 2 audits,
  100 MCP queries, 2 dashboard saves — all reset at midnight UTC.
- **Maker** — 5 apps, unlimited vibe-code scans, vibe monitoring, fix PRs,
  30-day history. For a vibe coder who wants to know when their own keys
  leak.
- **Starter** — one org, up to 5 repos, fingerprint monitoring, email
  alerts. For a small team that wants to know when its own keys leak.
- **Premium** — 15 repos, 75 fingerprints, Slack alerts, remediation
  workflow, 60-day history. For the team that outgrew Starter but isn't
  ready for Team pricing.
- **Team** — unlimited repos, Slack alerts, remediation workflow, owner
  verification. For a team that fixes leaks as part of its normal work.
- **Premium Plus** — everything in Team, plus API access, 180-day history,
  priority support. For the team that needs API and longer history but not
  the full compliance package.
- **Business** — audit logs, policy controls, reporting, SLA. For
  organizations with compliance and uptime requirements.
- **Enterprise** — SSO, team accounts/roles, private deployment,
  retention controls. For organizations that need the product inside
  their own boundary.

> Note (Nov 21, 2026): SSO and private deployment moved from Business
> to Enterprise to match `GO-TO-MARKET.md` (Business is the compliance
> tier; SSO/private deployment are the enterprise boundary). The layer
> model's `plans.json` already follows this split.

## What is explicitly NOT promised

- **No guarantee a key is live.** A finding means the key is still
  exposed in public code. Only the owner can confirm it still works.
  Owner-verified savings to date: **$0**.
- **Savings figures are candidate estimates.** The figures quoted for
  internet findings — $7,006.83 / $371,799.20 / $2,968,998.90
  (conservative / expected / worst-case, across 604 distinct real-looking
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

## Prices — proposed, to be validated by pilots

Proposed: Free $0, Maker $19/mo, Starter $49/mo, Premium $99/mo,
Team $149/mo, Premium Plus $299/mo, Business $499/mo, Enterprise custom.
The pilot is free, and these numbers will be set from what the pilot
teams say the monitoring, alerts, and workflow are worth to them. If a
tier does not convert, kill it — do not discount the tier above it. This
file will be updated when prices are confirmed. Until then, any price
quoted anywhere should be treated as a proposal, not a commitment.
