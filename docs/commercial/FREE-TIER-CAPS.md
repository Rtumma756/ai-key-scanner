# KeySentry — Free Tier Caps (exact)

Written 2026-11-21 by Rakesh's call. The model is the PDF editor: 2 free
edits a day. Generous enough to love, tight enough that a real user hits
the wall within their first 2–3 days — right when they want a little
more. The wall is daily and soft (come back tomorrow, it works again),
so users keep returning and hitting it until paying is the easier option.

## The principle

- **Caps are daily and replenish.** A monthly cap is waited out once and
  forgotten. A daily cap creates a habit and a repeated upgrade prompt.
  Reset at midnight UTC.
- **The cap bites at the natural "want more" moment.** The re-scan after
  a fix. The second app. The event from last week. The second repo.
  Never in the first hour (too stingy to love), never after a month
  (too generous to sell).
- **Show the counter.** "1 of 2 free scans used today" in the UI and
  the CLI output. Visible scarcity is the conversion engine. Hitting
  the cap shows exactly what the next tier unlocks — never a dead end.
- **Free is never taken away.** Upgrading adds capabilities; it never
  removes what the free tier already had.

## Free tier — exact caps

| Feature | Free cap | What happens at the cap |
|---|---|---|
| Web repo scan (vibe-code) | 2 / day | 3rd scan → upgrade prompt ("Maker: unlimited scans") |
| Agent Identity Audit | 2 / day | 3rd audit → upgrade prompt ("Starter: unlimited audits") |
| Fingerprints | 5 total, each checkable 1× / day, manual only | 6th fingerprint, or auto-monitoring → upgrade prompt |
| Audit timeline | 1 agent, last 7 days of events | 2nd agent, or older events → upgrade prompt |
| MCP server read-only queries | 100 / day | 101st query → upgrade prompt |
| CLI local scans | Unlimited (runs on the user's machine) | Saving results to the dashboard: 2 / day |
| Shareable reports | Latest 2 per type, permanent links | 3rd report replaces the oldest in the free list (links stay live) |
| GitHub Action | Unlimited runs on public repos | Dashboard history: latest run only |
| Email / Slack alerts | None | Any alert → upgrade prompt |
| Team seats | 1 user | 2nd seat → upgrade prompt |

Anonymous (no account) users get the same 2/day web caps, tracked by IP.
Creating a free account keeps the same caps but saves history and the
badge — the account is the lead capture, not a bigger free tier.

## Why these numbers

- **2 scans/day, not 1:** one scan is a demo, not a tool. Two lets a
  vibe coder scan, fix, and re-scan — the full loop, once. The third
  scan is the second app, or the second fix — that is the paying moment.
- **5 fingerprints:** enough to protect one small project for real, not
  enough for a team or a second project.
- **7 days of audit history:** enough to debug yesterday, not enough to
  answer "what happened last week" — and last week is exactly what an
  auditor asks about.
- **100 MCP queries/day:** generous for one dev's agents, tight for a
  fleet. A fleet hits it by lunch.
- **CLI unlimited:** the CLI is distribution and trust. Capping it would
  push devs to a fork. The paid value is what the CLI can't do alone:
  monitoring, alerts, history, proof.

## Paid tiers — what the cap lifts to

Full ladder (all prices proposed, to be validated by pilots):

| Tier | Price | Repos / apps | Fingerprints | Scans & audits | MCP queries | History | Seats | Unlocks |
|---|---|---|---|---|---|---|---|---|
| Free | $0 | 1 | 5 | 2/day each | 100/day | 7 days, 1 agent | 1 | Scans, reports, timeline |
| Maker | $19/mo | 5 apps | 25 | Unlimited | 1,000/day | 30 days | 1 | Monitoring, fix PRs |
| Starter | $49/mo | 5 repos | 25 | Unlimited | 1,000/day | 30 days | 3 | Email alerts, monitoring |
| Premium | $99/mo | 15 repos | 75 | Unlimited | 5,000/day | 60 days | 5 | Slack alerts, remediation workflow |
| Team | $149/mo | Unlimited | Unlimited | Unlimited | Unlimited | 90 days | 10 | Exports, owner verification |
| Premium Plus | $299/mo | Unlimited | Unlimited | Unlimited | Unlimited | 180 days | 25 | API access, priority support |
| Business | $499/mo | Unlimited | Unlimited | Unlimited | Unlimited | 7 years | Unlimited | Audit logs, compliance export, detections, policy controls, SLA |
| Enterprise | Custom | Unlimited | Unlimited | Unlimited | Unlimited | Custom | Custom | SSO, team accounts/roles, private deployment |

Maker is the vibe-coder tier; Starter is the dev-team tier; Premium and
Premium Plus are the bridges — Premium for the team that outgrew Starter but
isn't ready for Team pricing, Premium Plus for the team that needs API and
longer history but not the full compliance package. All are proposals
to be validated by pilots — if a tier doesn't convert, kill it, don't
discount the tier above it.

## Tuning — these are starting values, not scripture

Watch **time to first cap hit**: a real user should hit a cap within
their first 2–3 days. If they hit it in the first hour, the cap is too
tight and the product feels like a demo. If nobody hits a cap in a
month, it's too loose and nobody will ever pay. Adjust one cap at a
time, and only on data — never on a hunch, never for one loud user.

Also watch: cap-hit → upgrade conversion rate, and the failure mode
(thousands of free users, ~0% conversion). If conversion is ~0%, the
paid value is wrong — fix the paid layer, don't loosen the caps.
