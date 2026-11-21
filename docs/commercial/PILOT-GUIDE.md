# KeySentry — Pilot Guide

A pilot for 2–3 developers at one company. Free. Short. The point is to
learn whether fingerprint monitoring is worth paying for — not to sell
anything.

## What the pilot team gets

- The CLI and the web scanner, free, with no account needed.
- Fingerprint monitoring for their own keys (item 1 of the commercial
  build — in progress; see `COMMERCIAL-STATUS.md`. If it is not live on
  day one, the pilot starts with local scans and the web scanner, and
  fingerprint monitoring is the first thing we deliver).
- Email alerts when a monitored fingerprint appears in public code.
- Help from us setting up the first scan and the first fingerprint.
- A direct channel to report false positives and missed detections.

## What we ask the pilot team to do

1. **Run it on their own repos.** At least one local scan with
   `--git-history` per repo they care about, plus one web-scanner run.
2. **Register fingerprints** for the AI API keys they actually use
   (OpenAI, Anthropic, Gemini, Groq, and the rest — 13 providers are
   covered). Registering a fingerprint never shares the key itself.
3. **Report false positives.** Every finding that is not a real key:
   what it was, and the file it was in. Use the false-positive issue
   template (`.github/ISSUE_TEMPLATE/false_positive.md`).
4. **Report missed detections.** Any real AI key in their repos that the
   scanner did not flag. Use the missed-detection template
   (`.github/ISSUE_TEMPLATE/missed_detection.md`).
5. **Answer the feedback questions below** at the end of the pilot.

## Feedback questions

1. Did the scanner find a real leaked key you did not know about?
2. How many false positives did you see, and what were they?
3. Did any real key slip past the scanner?
4. Was the remediation report clear enough to act on without asking us?
5. Would fingerprint monitoring (alerts when your key shows up in public
   code) save you time? How much?
6. What would you change before you paid for this?

## Success criteria

The pilot succeeds if **one team asks for fingerprint monitoring** after
trying it — that is, they want to keep it running on their keys. That is
the only pass/fail measure.

Secondary signals (useful, not pass/fail):

- At least one real leaked key found and rotated during the pilot.
- False-positive rate low enough that the team keeps using it.
- At least one missed detection reported and fixed.

## Pilot limits (proposed)

These caps are proposed, not yet enforced in code. They keep the free
pilot small and the paid tiers meaningful.

| Limit | Pilot cap |
|---|---|
| Repos scanned | Up to 5 |
| Fingerprints monitored | Up to 25 |
| Scans per day | Up to 10 |
| Team size | 2–3 developers |
| Alert channel | Email only (Slack is a paid Team feature) |
| Duration | 4 weeks, then we decide together whether to continue |

## What the pilot does not include

- No SSO, audit logs, or policy controls (Business tier).
- No Slack alerts or remediation workflow (Team tier).
- No scheduled sweeps or dashboard (in progress — see
  `COMMERCIAL-STATUS.md`).
- No guarantee a key is live. A finding means the key is still exposed in
  public code. Only the owner can confirm it still works.

## After the pilot

- If the team wants fingerprint monitoring: we talk about the Team tier
  (see `PRICING.md`).
- If not: they keep the free CLI and web scanner, and we keep their
  feedback. No data is held against them — their fingerprints are deleted
  on request, and the 30-day vault purge rule applies (see `SECURITY.md`).
