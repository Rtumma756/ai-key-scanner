# KeySentry — Email Alerts for Fingerprint Matches

Email alerts fire when a watched fingerprint (a key you own) is seen
again in public code. They are a **Starter-tier feature** (see
`PRICING.md`: email alerts are Yes on Starter, Team, and Business;
Slack alerts start at Team).

Status: **built 2026-11-21, credential not yet supplied** — the code
is wired in, but no SMTP or Resend credential exists yet, so no email
can actually be sent until the user supplies one in Vercel env vars
(see "Enable it" below). Nothing was deployed as part of this work.

## What is sent

- **Trigger:** a NEW match recorded via `POST /api/matches` — i.e.
  the first sighting of a watched fingerprint at a given
  (repo, file, line). Repeat sightings only refresh `last_seen` and
  do not re-alert.
- **Channels:** the existing Slack-compatible webhook
  (`KEYSENTRY_ALERT_WEBHOOK`) fires first, then email. Either channel
  accepting counts as alerted (`alerted: true` in the POST response).
  Alert failure never fails the match recording.
- **Contents:** fingerprint (SHA-256, first 16 hex), provider, repo,
  file, line, first-seen time, and a link to the matches list in the
  live app. **The key itself is never included in alerts** — not raw,
  not masked. Only the one-way fingerprint is sent, so an alert email
  cannot be used to recover the key.

## How it is built

| Piece | File |
|---|---|
| Web sender (Resend API first, SMTP fallback) | `~/workspace/key-sentry/lib/email.ts` — exports `emailConfigured()`, `sendMatchEmail(match)`, `matchEmailSubject(match)`, `matchEmailBody(match)` |
| Wiring into the match event | `~/workspace/key-sentry/lib/alerts.ts` — `sendMatchAlert()` now sends webhook, then email, and returns true when either accepted. `app/api/matches/route.ts` needed **no edit**. |
| CLI sender (stdlib only: `urllib` + `smtplib`) | `~/workspace/ai-key-scanner/email_alert.py` — `send_match_email(match_dict, config=None)` |
| Web tests (mocked transports) | `~/workspace/key-sentry/lib/email.test.ts` |
| CLI tests (mocked transports) | `~/workspace/ai-key-scanner/tests/test_email_alerts.py` |

Transports, in priority order:

1. **Resend HTTP API** — when `RESEND_API_KEY` is set. Plain `fetch`
   to `https://api.resend.com/emails`, no new dependency. Free tier:
   100 emails/day.
2. **Plain SMTP** — when `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` /
   `SMTP_PASS` are set. Web app uses `nodemailer` (MIT, added to
   `package.json`); CLI uses stdlib `smtplib`. `SMTP_PORT` defaults
   to 587 (STARTTLS); port 465 uses implicit TLS.

Recipients: `KEYSENTRY_ALERT_EMAIL`, comma-separated.
From address: `KEYSENTRY_ALERT_FROM`, or the default
`KeySentry <alerts@key-sentry-inky.vercel.app>`.
App link in the email: `KEYSENTRY_APP_URL`, or
`https://key-sentry-inky.vercel.app`.

## Enable it

> **No SMTP/Resend credential exists yet.** Supplying one in Vercel
> env vars is a documented next step for the user. Do NOT invent
> credentials, and do not paste a real key into docs, chat, or code.

### Option A — Resend (recommended, free tier)

1. Sign up at https://resend.com (free tier: 100 emails/day).
2. Create an API key (Dashboard → API Keys → Create API Key).
3. In Vercel: project `key-sentry` → Settings → Environment
   Variables, add:
   - `RESEND_API_KEY` = the key from step 2
   - `KEYSENTRY_ALERT_EMAIL` = recipient address(es), comma-separated
   - optionally `KEYSENTRY_ALERT_FROM` = a verified sender, e.g.
     `KeySentry <alerts@yourdomain.com>` (Resend requires the sender
     domain to be verified for production sending; the default
     `alerts@key-sentry-inky.vercel.app` sender is unverified, so set
     a verified `KEYSENTRY_ALERT_FROM` before relying on this.)
4. Redeploy (env vars apply on redeploy, not to the running
   deployment).

### Option B — SMTP

1. In Vercel → Settings → Environment Variables, add:
   - `SMTP_HOST`, `SMTP_PORT` (587, or 465 for implicit TLS),
     `SMTP_USER`, `SMTP_PASS`
   - `KEYSENTRY_ALERT_EMAIL` = recipient address(es), comma-separated
   - optionally `KEYSENTRY_ALERT_FROM`
2. Redeploy.

Only one transport is needed: if `RESEND_API_KEY` is set, Resend is
used and SMTP is ignored.

### CLI use

The CLI sender reads the same env vars. From the repo root:

```bash
export KEYSENTRY_ALERT_EMAIL="owner@example.com"
export RESEND_API_KEY="re_..."   # or SMTP_HOST/SMTP_USER/SMTP_PASS
python3 -c "from email_alert import send_match_email; print(send_match_email({'fingerprint': '06fabb99a6b4976b', 'provider': 'Groq', 'repo': 'acme/app', 'file': '.env', 'line': 7, 'firstSeen': '2026-11-21T00:00:00.000Z'}))"
```

With no env set it prints `False` and raises nothing.

## Wiring the CLI into fingerprint_watch.py

`fingerprint_watch.py` is owned by another agent and was **not**
edited. To send email when `check` records a NEW match, apply this
one-line wiring inside `cmd_check()`, right after the NEW-match
branch (the `posted_new += 1` line):

```python
from email_alert import send_match_email
...
            if resp.get("isNew"):
                posted_new += 1
                send_match_email(match)   # match already carries
                                          # fingerprint / provider /
                                          # repo / file / line only
                print(f"    -> recorded as NEW match"
                      f"{' (alert sent)' if resp.get('alerted') else ''}")
```

Note: the web app already emails on every NEW match it records, so
the CLI call above is a second copy of the same alert — add it only
if a local email copy is wanted in addition to the server-side one,
or if the CLI is run against an app deployment without email
configured. `send_match_email` never raises, so it cannot break the
check run; it returns `False` when email is unconfigured.

## Test procedure

1. Set the env vars (Option A or B above) and redeploy the web app.
2. Add a fingerprint to watch (admin): `POST /api/fingerprints`
   with a fingerprint you own (compute it with
   `python3 fingerprint_watch.py hash`, reading the key from stdin).
3. Record a test match (admin): `POST /api/matches` with that
   fingerprint, a provider, repo, file, and line.
4. Check the inbox for `KEYSENTRY_ALERT_EMAIL`: subject
   `[KeySentry] Watched key <fingerprint> seen again (<provider>)`.
   Confirm the body shows the fingerprint, provider, repo/file/line,
   and the "key itself is never included" line — and contains no key.
5. Record the same match again: no second email (repeat sightings
   only refresh `last_seen`).

Automated checks (no credentials, mocked transports):

```bash
# CLI (10 tests)
cd ~/workspace/ai-key-scanner && python3 -m pytest tests/test_email_alerts.py -q
# CLI smoke: no env -> prints False, exit 0
python3 email_alert.py
# Web (9 tests; the web app has no test runner configured, so the
# tests compile to /tmp and run under node --test)
cd ~/workspace/key-sentry && npx tsc --noEmit false --outDir /tmp/email-test \
  --module nodenext --moduleResolution nodenext --target es2022 \
  --esModuleInterop --skipLibCheck --types node \
  lib/email.test.ts lib/email.ts lib/fingerprints-db.ts lib/vault-db.ts lib/vault-crypto.ts \
  && NODE_PATH=$PWD/node_modules node --test /tmp/email-test/email.test.js
# Web build (must pass)
cd ~/workspace/key-sentry && npm run build
```

## Troubleshooting

- **No email arrives, `alerted: false`:** check the Vercel env
  vars are set on the deployed project (env vars apply on redeploy)
  and that `KEYSENTRY_ALERT_EMAIL` has at least one address.
  `emailConfigured()` is false when recipients are missing or when
  neither `RESEND_API_KEY` nor SMTP credentials are set.
- **Resend 401/403:** the API key is wrong or lacks sending
  permission; create a fresh key in the Resend dashboard. A 403 can
  also mean the sender domain is unverified — set a verified
  `KEYSENTRY_ALERT_FROM`.
- **Resend rate limit (429):** free tier is 100 emails/day; the
  alert is best-effort and the match is still recorded.
- **SMTP auth failure:** verify `SMTP_USER` / `SMTP_PASS` and that
  the provider allows SMTP (some providers need an app password, not
  the account password). Port 465 = implicit TLS; 587 = STARTTLS.
- **Webhook works but email does not (or vice versa):** the channels
  are independent — `alerted` is true when either accepts. Check the
  Vercel function logs: email failures are logged as
  `KeySentry match email failed:`; webhook failures as
  `KeySentry match alert failed:`.
- **Duplicate emails:** the web app emails once per NEW match.
  If the CLI wiring above is also applied, a CLI `check` run sends a
  second copy for the same match — expected; remove the CLI call if
  only the server-side email is wanted.
- **Email contains no key:** by design. If a recipient asks for the
  key, do not send it — the fingerprint is the only identifier
  alerts carry, and the owner must rotate the key from their own
  records.

## Still open

- **Credential not supplied:** no Resend API key and no SMTP
  credentials exist. The user must supply one in Vercel env vars
  (see "Enable it") and redeploy before any email can be sent.
- **Not deployed:** the email code was built and verified locally
  (`npm run build` passes); no deployment was done in this work.
- **CLI wiring not applied:** `fingerprint_watch.py` was not edited
  (owned by another agent); the one-line wiring above is documented
  for its owner.
- **Sender domain unverified:** the default from address
  `alerts@key-sentry-inky.vercel.app` is not a verified Resend
  sender; set a verified `KEYSENTRY_ALERT_FROM` for production use.
