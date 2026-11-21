# KeySentry launch post — draft (not posted)

Prepared 2026-11-21 (Sat) morning. Product went live overnight (build b3bfe74,
https://key-sentry-inky.vercel.app) and the dogfood scan passed green.
Numbers below use the human-reviewed totals, not the pre-review 612.

## Numbers used (all from the masked-only reports)

- 604 distinct real-looking keys found in public GitHub code; all live at last check.
- 467 of them score 80+ on the confidence scorer — the proposed headline band.
- Candidate (modelled, not verified) savings on the 604: $7,006.83 conservative /
  $371,799.20 expected / $2,968,998.90 worst-case.
- Owner-verified savings: $0 — no stranger's key was ever tested against a provider.
- Source: `results/REVIEW_24_DISPUTED.md` (604 total, 467 ≥ 80) and
  `results/FRESH_LIVENESS_ALL.md` (580/580 still exposed on the Nov 20 re-check;
  the 32 fresh keys from the Nov 21 scan all matched live at discovery).

Do NOT use the old 612 / $376,955 figures — 8 demo/test rows were reclassified
to placeholder in the Nov 21 review.

## Post (Show HN / X / LinkedIn — same core text)

**Title:** We scanned public GitHub for leaked AI API keys — 467 high-confidence
keys are still live

I built KeySentry, a free scanner for leaked AI API keys (OpenAI, Anthropic,
Gemini, Groq, OpenRouter, Hugging Face, and more).

What it found, in public code, all still live when re-checked:

- 604 real-looking keys, 467 of them high-confidence (score 80+)
- Modelled exposure on those 604: ~$372K expected, up to ~$2.97M worst-case
- These are candidate figures, not verified losses — no key was tested
  against any provider, and owner-verified savings are $0. The honest claim
  is: exposed, live, and shaped like a usable key.

Why it matters: these are keys your CI secret scanner never saw — a
contractor's repo, a gist, a repo that went public later. KeySentry
re-fetches the live file to confirm the key is still there, and scores
each finding with visible evidence instead of just counting.

The free tool: https://key-sentry-inky.vercel.app
CLI + GitHub Action: https://github.com/Rtumma756/ai-key-scanner

For teams, the business mode watches fingerprints of keys you own — hashes
only, the key itself never leaves your machine — and alerts you if one
shows up in public code. Try the free fingerprint check; if it finds
nothing, that's the answer you wanted.

No key is shown anywhere in the report or the tool — masked first-4 only.

## Shorter LinkedIn version

AI API keys are leaking into public code faster than teams can track them.
I built KeySentry to find them: 604 real-looking keys found on public
GitHub, 467 high-confidence, all still live on re-check, ~$372K in
modelled expected exposure. Free scanner live now — and for teams, a
fingerprint check that tells you if *your* keys are out there, without
ever handing us the key itself.
https://key-sentry-inky.vercel.app

## Before posting — decisions for Rakesh

1. Headline number: 467 (≥80 band) is used here, per the proposed score
   policy. That policy is still undecided — if you prefer the 604 total,
   say so and the post changes in one line.
2. Channel: Show HN, LinkedIn, X, or all three? The draft above is written
   to work on any of them.
3. Nothing here has been posted, sent, or published. This file is the draft only.
