# KeySentry — Comprehensive Platform Plan (Pillars 1, 2, 7)

Decided 2026-11-21 by Rakesh. Recruiting-area products are OUT — agencies run on
thin margins. KeySentry becomes one comprehensive platform with three
pillars, all sharing the same spine (detectors, fingerprints, confidence
scoring, dashboard):

- **Pillar 1 — Agent identity security** (idea #1): who owns which credential.
- **Pillar 2 — Vibe-code security scanner** (idea #2): is the AI-built app safe.
- **Pillar 3 — Agent audit trail** (idea #7): what did each agent do, and can
  you prove it.

**#6 PMO copilot is PARKED** — Rakesh redirected to KeySentry 1, 2, 7 on
Nov 21. The competitive check stands (see bottom): the wedge is real but
narrow, weakest of the three for $50M. Revisit only if the free wedge is
validated cheaply later.

## The platform in one paragraph

One question runs through all three pillars: *an AI agent did something —
which agent, with which credential, and can you prove it?* Pillar 1
answers which agent holds which key. Pillar 2 answers whether the code
the agent wrote is safe. Pillar 3 answers what the agent did with its
access, in a record an auditor will accept. The free tools are the funnel
for all three; the paid product is the workflow that fixes and proves.

## The market, in one paragraph

Machine identities outnumber humans 45 to 1 (up to 144 to 1 in cloud-native
shops) and 82% of organizations already use AI agents. The M&A wave proved
the exit: CyberArk to Palo Alto $25B, Astrix to Cisco ~$400M, Entro to
SailPoint ~$200M, Oasis to Cyera ~$1B. For the audit pillar specifically:
the EU AI Act's Article 12 logging requirements reached full enforcement
Aug 2, 2026; NIST SP 800-53 AU-10 demands irrefutable evidence that a
process acting for a person performed an action; the IETF WIMSE draft
makes a verifiable trace a MUST. And the ecosystem gives you none of it
for free: OpenTelemetry's GenAI conventions define 73 attributes, zero
stable and zero carrying identity or authorization; MCP deprecated its
own logging feature in the 2026-07-28 spec. A 2026 analysis of ~7,000
public MCP servers found 41% had no authentication at all. Enterprise
players (Nightfall, Strac, Palo Alto Prisma AIRS) sell to the top of the
market; the dev/SMB layer has no audit trail at all. That is the lane.

## Phase 0 — Close the commercial gaps (this week)

The product is built and deployed; it is not yet sellable. In order:

1. **Stripe billing** — connect Stripe, create the tier products below.
   Biggest gap; without it this is a free tool, not a subscription.
2. **Email alerts** — Resend API key (or SMTP) + the alert email address.
   Code is built (`lib/email.ts`); nothing can send until credentials exist.
3. **Score policy decision** — ≥80 = confirmed leak (467 rows), 50–79 =
   needs review, <50 = excluded from headlines. Needed before the launch
   post goes out, because the post headlines the 467.
4. **Launch post** — draft ready at `docs/commercial/LAUNCH-POST.md`
   (604 keys, 467 high-confidence, ~$372K modelled expected exposure).
   Decision: Show HN + LinkedIn + X, or a subset. Post it; it is the
   top of the funnel.
5. **PyPI publish** (`aiscan`) + **GitHub Marketplace listing** — needs a
   PyPI token. Distribution, not revenue.
6. **Fix stale figures in `PRICING.md`** — it still quotes the pre-review
   612 keys / $376,955. Correct: 604 keys / $371,799.20 expected.
7. **Small code gaps** — rate limiting on `/api/matches/assign`,
   `/api/matches/export`, `/api/posture`, `/api/vault/*`; vault
   `--mark-verified` status update; CLI email one-liner.

## Pillar 1 — Agent identity inventory (weeks 2–4)

What exists today: key scanning (15 detectors, 13 providers + entropy),
fingerprint monitoring (hashes only), confidence scoring, team workflow,
dashboard, nightly sweeps, vault. What does NOT exist: any notion of an
*agent* owning a credential.

Build order:

1. **MCP config scanner** — parse `.mcp.json`, Claude Code settings,
   Cursor rules, agent config files; inventory which agents exist in a
   repo and which credentials each one holds. The CLI already has a
   `--preset mcp` query (`filename:.mcp.json "sk-"`); this turns that
   preset into a structured inventory.
2. **Agent → credential → repo → owner mapping** — the inventory view.
   This is the product: "here are your 14 agents, here are the 31
   credentials they hold, here are the 3 that are exposed."
3. **Fingerprint monitoring for agent credentials** — the existing
   monitoring, extended so a fingerprint is tagged with its agent.
4. **Free wedge: the Agent Identity Audit** — point the web scanner at a
   repo, get a one-page report: agents found, credentials per agent,
   exposed keys, confidence scores. Shareable link. This is the hook
   that gets passed around.
5. **KeySentry MCP server** — the agent-era hook. Let an AI agent ask
   KeySentry "are my keys exposed?" and "what do I own?" Agents that
   use the tool become distribution. (This server is also the audit
   source for Pillar 3.)

## Pillar 2 — Vibe-code security scanner (weeks 4–6, rides Pillar 1)

Reuses detectors, confidence scoring, the GitHub Action, and the report
pattern. Build order:

1. Web repo-URL scan — paste a repo link, get a security report
   (OWASP flaws + secrets + exposed databases). No install.
2. Shareable report page — the viral loop: "my app has 3 critical issues."
3. Fix suggestions in plain language, for non-developers.
4. Continuous monitoring + one-click fix pull requests (paid).
5. Team policy gates (paid).

Audience: Lovable / Bolt / v0 / Replit users — millions of new builders
who ship apps and have never thought about security. Snyk and Sonar don't
speak their language; that is the opening. Start this only after the
Pillar 1 wedge is live — it rides the same distribution, it does not need
its own.

## Pillar 3 — Agent audit trail (weeks 6–10, builds on Pillar 1)

An audit log has to answer one question a trace cannot: *who authorized
this action, and can you prove it later to someone who does not trust
you?* A transcript is not an audit log — it shows what the model said,
not what your systems allowed. Build order:

1. **Canonical event schema** — one structured JSON event per agent tool
   call: who asked (human principal), which agent (agent ID, version,
   model), what it tried (stable tool label), on what (resource + argument
   key names only), what was decided (allow/deny + policy + reason),
   what happened (outcome), when (server timestamps), as part of what
   (run/task correlation ID). Six-tuple pivot in every event:
   `principal_id`, `parent_agent_id`, `session_id`, `policy_id`,
   `ticket_of_record`, `model_run_id`. Log attempts, not only successes —
   a denial is often the most important record.
2. **Redaction before write** — never log tokens, secrets, or raw
   arguments. Argument key names + redacted errors only. This rule is
   load-bearing: the audit trail must never become a second leak.
3. **Hash-chained, append-only log** — each event's SHA-256 covers the
   previous event's hash; a `verify` command recomputes the chain and
   reports per-event pass/fail. Tamper-evident, not just append-only.
   CLI + web app both write to it.
4. **Timeline view** — per agent, per run, in the dashboard: what each
   agent did, in order, with the decision attached. This is the free
   wedge for the pillar: one agent's timeline, free.
5. **Five first detections** — tool-set drift, cost spike,
   confidence-floor breach, cross-tenant access, sub-agent fan-out
   anomaly. Alerts, not just logs.
6. **Compliance export** — SOC 2 / ISO 27001 control mapping, EU AI Act
   Article 12 report, SIEM export. The report a CTO hands an auditor.
   Retention: hot 30 days, warm 90 days, cold 7 years (pilot: 90 days).
7. **MCP server as audit source** — the Pillar 1 MCP server records its
   own calls through the same schema, so agents using KeySentry generate
   audit events by default.

## How the pillars connect (the shared spine)

- Detectors + confidence scoring feed Pillars 1 and 2.
- Fingerprints are the identity key: a fingerprint tagged with its agent
  (Pillar 1) is the same fingerprint an audit event references when that
  agent acts (Pillar 3).
- Discovery events from Pillar 2 scans (a leaked key found in a vibe-coded
  app) land in the audit timeline as findings, not just in a report.
- One dashboard, one passphrase-admin model for the pilot, one pricing
  ladder. Three free wedges, one paid workflow.

## Remediation (the paid feature, across pillars)

Detection is free; fixing and proving are what people pay for.

1. Guided rotation playbooks per provider (where to revoke, what to
   re-issue, what breaks if you don't).
2. Re-scan to confirm the leak is gone — the "fixed" proof, which is
   what a team shows its manager.
3. Auto-revoke/rotate where the provider API allows it (opt-in, own keys
   only, explicit confirmation each time).
4. Audit events for every remediation step, so the fix itself is provable.

## Free wedge — exact scope

Free forever, no account needed:

- Internet scanner (CLI) + web scanner + local repo scans with git history
- Agent Identity Audit for one repo at a time (shareable report)
- Vibe-code report for one repo at a time (shareable report)
- Audit timeline for one agent (shareable view)
- Fingerprint check: up to 5 fingerprints, 1 repo, manual checks only
- GitHub Action + pre-commit hook

Paid starts where the workflow starts: monitoring, alerts, team workflow,
remediation, audit trail, compliance export.

## Layer model — free to integrate, pay to scale

This is the product shape, not just a billing switch. Two layers, built
into the code:

**Free layer — integrate and use, no account, no card.** Install the CLI,
Action, or hook; run the scanners; get the shareable reports. This layer
is the distribution: it has to work end to end without ever talking to
us. Per pillar (exact caps in `docs/commercial/FREE-TIER-CAPS.md`):
- Pillar 1: Agent Identity Audit 2/day, 5 fingerprint checks, MCP
  server read-only queries 100/day.
- Pillar 2: repo-URL scan 2/day, plain-language fixes, shareable report.
- Pillar 3: one-agent audit timeline, last 7 days of events.

**Commercial layer — the capabilities that unlock when you pay.** Same
product, more of it, plus the workflow: monitoring, alerts, team
workflow, remediation, full audit trail, compliance export, API.
Per pillar:
- Pillar 1: unlimited repos, fingerprint monitoring, agent-level posture.
- Pillar 2: continuous monitoring, fix PRs, team policy gates.
- Pillar 3: full audit log, the five detections, compliance export, SIEM
  export, retention controls.

**How the layers are built:**
- Plan definitions live in code (Free / Starter / Team / Business) — one
  source of truth for limits and feature gates, shared by CLI and web.
- Limits enforced server-side, not just hidden in the UI. Hitting a
  limit shows an upgrade prompt in the CLI and the dashboard, with what
  the next tier unlocks — never a dead end.
- Billing is a stub until Stripe connects: checkout and webhook code
  with env placeholders, plan state stored per workspace. Once Stripe
  is connected, the pay layer starts charging; the free layer keeps
  working exactly as before.
- Free users are never locked out of what they already had. Upgrading
  adds capabilities; it never takes the free layer away.

## Pricing — proposed, to be validated by pilots

| Tier | Price | What unlocks |
|---|---|---|
| Free | $0 | Scanner, one-repo audits (identity + vibe), one-agent timeline, 5 fingerprints, Action/hook |
| Maker | $19/mo | 5 apps, unlimited scans, monitoring, fix PRs, 30-day history |
| Starter | $49/mo | 5 repos, 25 fingerprints, email alerts, monitoring, 30-day history |
| Premium | $99/mo | 15 repos, 75 fingerprints, Slack alerts, remediation workflow, 60-day history |
| Team | $149/mo | Unlimited repos, Slack alerts, remediation workflow, owner verification, exports, 90-day history |
| Premium Plus | $299/mo | Everything in Team, plus API access, 180-day history, priority support |
| Business | $499/mo | Audit logs + compliance export, posture reports, policy controls, API, detections, SLA, 7-year retention |
| Enterprise | Custom | SSO, team accounts/roles, private deployment, retention controls |

Pricing rule for later: price per protected identity/repo, not per seat.
The pilot (free, 4 weeks) is what validates these numbers — if pilot
teams say fingerprint monitoring is worth more, prices go up, not down.

## First 10 customers — founder-led, no paid ads

Pilot terms (from `PILOT-GUIDE.md`): free, 4 weeks, 5 repos, 25
fingerprints, 10 scans/day, 2–3 devs, email alerts only. Success = one
team asks to keep fingerprint monitoring afterwards.

1. **Sravan (Sravan08@gmail.com)** — pilot #1, already named. Invite
   drafted, HELD on Rakesh's call Nov 21. Send only when he re-raises it.
2–3. **Two more devs from Rakesh's own network** who build with AI
   agents or MCP servers — the people he already talks to about this.
   Ask them directly; a personal ask beats any landing page.
4–10. **From the launch funnel, in order:**
   - Show HN post (the launch draft) — the 604-key / 467 high-confidence
     report is the hook.
   - LinkedIn + X with the same numbers.
   - GitHub Action users — everyone who installs the Action is a lead;
     the Action's output links to the fingerprint check.
   - MCP community — r/mcp, MCP server directories, Claude Code users.
     The MCP config scanner is the conversation starter. (41% of public
     MCP servers have no auth — that stat is the audit pillar's hook.)
   - Vibe-coding communities — Lovable / Bolt / v0 / Replit users.
   - Teams under compliance pressure — the audit trail is the wedge for
     anyone who has to answer an auditor about agents.

Do not buy ads. Do not do enterprise outreach. The first 10 come from
the free tool and the report, or the wedge is wrong and we learn that
cheaply.

## Sequencing (why this order)

1. Pillar 1 first — it is half-built, and the audit trail needs identity
   before it can attribute anything.
2. Pillar 2 rides Pillar 1's distribution — same detectors, same report
   pattern, different audience.
3. Pillar 3 last — it needs Pillar 1's identity mapping, and it is the
   enterprise wedge, so it pays only after the dev/SMB wedge proves
   people care.
4. Enterprise (SSO, real accounts, API, private deployment) only on
   demand, month 5+.

## What NOT to do

- No recruiting-area products (thin margins — Rakesh's call).
- #6 PMO copilot parked (see below).
- No paid ads before 10 pilots.
- No SOC 2 before a customer demands it.
- No enterprise sales motion before the first paying team.
- No raw keys, ever — fingerprints only, strangers' keys never vaulted,
  never tested against a provider. Audit events never carry tokens,
  secrets, or raw arguments. These rules are the business's trust
  foundation, not features.

## $50M math (recap)

~2,000 mid-market teams at ~$2,000/mo blended, or a mix with enterprise
contracts. Three pillars change the mix, not the total: identity is the
volume wedge, vibe-code is the viral wedge, audit is the enterprise
wedge (compliance budgets are the biggest per-customer dollars). The
volume path (~35,000 teams at $120/mo) is the wrong shape — NHI sells to
teams with real agent fleets, at real prices. The acquisition wave says
the exit is real if the product gets there first in the dev/SMB layer.

## Product #6 — PMO copilot: competitive check (Nov 21, 2026) — PARKED

Rakesh asked whether PMO products already exist in market. Yes — two
layers of incumbents, verified Nov 21:

- **Portfolio suites (PPM):** Planview, Broadcom (Clarity), Smartsheet,
  ServiceNow SPM, Microsoft Project, Oracle Primavera, SAP, Atlassian
  (Jira Align), Asana, monday.com. Market $9.79B in 2026 → $17.75B by
  2031 (12.6% CAGR); AI portfolio analytics is the fastest-growing
  segment. These own governance — but they all require manual status
  entry. Nothing in them turns a meeting into portfolio truth.
- **Meeting AI:** Otter ($100M+ ARR, 35M users), Fireflies ($1B
  valuation), Fathom (acquired by Superhuman, Sept 2026), Granola
  ($1.5B valuation), Gong ($500M+ ARR), plus Notion AI Meeting Notes.
  ~$740M market, 30+ competitors — transcription and basic summaries
  are commoditized.

**The gap that remains:** the last mile between the two layers. No
incumbent automatically turns meetings into PMO artifacts — RAID log,
RAG status, decision log, exec pack. The notetakers produce generic
summaries; the suites wait for a human to type the status in.

**Honest verdict:** #6 is the weakest of the three picks for $50M. The
wedge is real but narrow, and the giants can close it — Microsoft
Copilot + Teams and ServiceNow adding AI are the obvious closers. The
moat would be PMO-workflow depth plus Rakesh's own credibility, not
technology. Realistic shape is a solid smaller business ($1–5M ARR)
rather than a $50M one. #1, #2 and #7 stay the stronger bets. Parked
Nov 21 when Rakesh redirected to KeySentry 1, 2, 7.
