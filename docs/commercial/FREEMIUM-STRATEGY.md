# KeySentry — Freemium Strategy: Vibe Coders + AI Agent Managers

Written 2026-11-21 by Rakesh's call. One freemium motion, two audiences.
The free layer is the marketing; the paid layer is the workflow. The
funnel is the same shape for both, but the hook, the fear, and the
conversion trigger are different — so they are designed separately.

## The idea in one line

Give each audience a free answer to the one question that scares them,
in a report they can share. The report is the ad. The limit they hit
next is the sale.

## Audience 1 — Vibe coders (Pillar 2)

**Who they are:** people shipping apps with Lovable, Bolt, v0, Replit.
Mostly non-developers or junior devs. They have never thought about
security and would not know a leaked key if they saw one. They deploy
to Vercel/Netlify, use Supabase/Firebase, and share their apps publicly.

**What they fear:** not compliance — they fear their app breaking, their
Supabase keys stolen, someone draining their API credits, their app
getting hacked the week they show it off. Speak to that, never to
"posture" or "governance."

**Free hook — the repo-URL scan.** Paste a repo link, no install, no
account. Thirty seconds later: "Your app has 3 critical issues" — in
plain language, with what each issue means in their terms ("anyone can
read your database" beats "exposed Supabase anon key"). One repo free.

**Free value:**
- One-repo scan + shareable report page (the viral loop — they post it).
- Plain-language fix for each finding ("change this setting, paste the
  new key here").
- A security score + badge for their project page ("Scanned by
  KeySentry — 0 critical issues"). The badge is the ad that lives on
  their app.

**Conversion trigger:** they build a second app, or they want to know
the moment a new app leaks — monitoring. Or they want the fix applied
for them instead of reading instructions — the one-click fix PR.

**Paid unlock (commercial layer):**
- Continuous monitoring across all their apps.
- One-click fix pull requests.
- Team policy gates (for the ones who start building with friends).

**Channels:** Lovable / Bolt / v0 / Replit communities and Discords,
X, YouTube creators who teach vibe coding, Product Hunt. One good
"my app had 3 critical issues" post from a creator is worth more than
any ad.

**Price sensitivity:** HIGH. A hobby vibe coder will not pay $49/mo.
Proposed addition to the ladder, to be validated: a **Maker tier at
$19/mo** — 5 apps, monitoring, fix PRs. Starter $49 stays the team
tier. If Maker converts, it is the volume engine; if it doesn't, kill
it — do not discount Starter to chase it.

## Audience 2 — AI agent managers (Pillars 1 + 3)

**Who they are:** dev leads, platform engineers, CTOs of small teams
running agent fleets — Claude Code, Cursor, MCP servers. They own the
credentials the agents use, and they are the ones who answer when
something goes wrong.

**What they fear:** an agent leaking a key, an agent doing something
nobody authorized, and an auditor (or their own CTO) asking "who did
what, and can you prove it." They fear the incident and the question
after it.

**Free hook — the Agent Identity Audit.** Point it at a repo, get a
one-page report: "14 agents, 31 credentials, 3 exposed." One repo free,
shareable link. The report is the thing that gets forwarded to the team
lead — that forward is the sale starting.

**Free value:**
- One-repo identity audit (shareable report).
- 5 fingerprint checks, manual.
- One-agent audit timeline — what that agent did, in order.
- KeySentry MCP server, read-only — agents ask "are my keys exposed?"
  and the tool spreads agent-to-agent.

**Conversion trigger:** they add a second repo, or they want monitoring
and alerts, or they need the full audit trail for compliance, or — most
commonly — a leak happens somewhere and monitoring suddenly becomes
urgent. The free audit creates the awareness; the incident creates the
budget.

**Paid unlock (commercial layer):**
- Fingerprint monitoring + email/Slack alerts.
- Remediation workflow (rotation playbooks, fix proof).
- Full audit log, the five detections, compliance export, SIEM export.
- Team workflow: assign, exports, owner verification.

**Channels:** Show HN (the 604-key report is the hook), MCP community
(r/mcp, MCP directories, Claude Code users), GitHub Action users (every
install is a lead), LinkedIn + X with the same numbers. The stat to
lead with: 41% of public MCP servers have no authentication at all.

**Price sensitivity:** LOW-MEDIUM. These buyers have budgets and a
compliance reason to spend. Starter $49 / Team $149 / Business $499
fits. Do not discount to win them — discounting a security tool reads
as "not serious."

## The shared funnel

Same shape for both audiences:

1. **Free tool, no account** — scan or audit, get the report.
2. **Shareable report** — the viral loop. Each report is an ad with the
   product's name on it.
3. **Free account** — to save reports, monitor one repo/agent, get the
   badge. Account creation is the lead capture; it costs the user
   nothing and gives us the email.
4. **Limit hit** — second repo, second app, more fingerprints. The
   upgrade prompt names exactly what the next tier unlocks. Never a
   dead end, never a silent block.
5. **Pay** — monthly, or founder annual (see sequencing).

Land-and-expand is built in: one dev uses it free, shares the report,
the team lead sees it, the team upgrades. The free user is the
salesperson.

## Sequencing (from the funding decision)

Paid pilots FIRST, then open the free tier wide. Get 3–5 teams paying
(Sravan + 2 from Rakesh's network, founder annual ~$490/yr Starter)
before scaling free. That proves someone will pay before free users
arrive in volume. If nobody pays, the lesson is free; if they do, the
free tier scales on proven conversion.

## Guardrails (so free users can't sink the business)

- Hard caps on free: 1 repo, 1 app, 5 fingerprints, 10 scans/day, 1
  agent timeline. Enforced server-side.
- Heavy compute stays on the user's machine (CLI, Action). The server
  only serves reports and fingerprints.
- Rate limits + per-IP quotas on the web scanner. Abuse gets throttled,
  not billed.
- Free users are never locked out of what they already had. Upgrading
  adds capabilities; it never takes the free layer away.

## Metrics — what good looks like

- Free tool uses → free accounts: aim 10–20%.
- Free accounts → paid: dev tools convert at 1–3% on a good day; aim
  for 2%+ in the first 6 months, higher for agent managers than vibe
  coders.
- Viral coefficient: reports shared per user. Above 1.0, the free tier
  grows itself.
- Time to first limit hit: the shorter, the better — it means the free
  tier is being used hard enough to sell.
- Watch the failure mode: thousands of free users, ~0% conversion. If
  that appears, the paid value is wrong (probably monitoring isn't
  urgent enough) — fix the paid layer, don't buy ads for the free one.

## What NOT to do

- No paid ads before 10 pilots. The free tool is the ad.
- No discounting Starter to win vibe coders — that is what the Maker
  tier is for.
- No compliance language to vibe coders, no "easy and fun" language to
  agent managers. Each audience gets its own words.
- No gating the first scan behind an account. The first report must be
  free and instant, or the loop never starts.
