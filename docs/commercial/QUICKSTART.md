# KeySentry — Pilot Quickstart

Get from zero to your first real finding in 30 minutes. No account needed
for the free parts. No credentials needed for the demo.

## What you need

- Python 3.10 or newer.
- A copy of the scanner. The CLI lives in `~/workspace/ai-key-scanner/`
  (run it from that directory). The web app is at
  https://key-sentry-inky.vercel.app (repo:
  https://github.com/Rtumma756/key-sentry).
- For live internet scans only: a GitHub token with code-search access.
  Local scans and the demo need no token.

## 1. Try the demo (2 minutes, no network, no token)

```bash
cd ai-key-scanner
python3 aiscan.py scan internet --demo   # bundled fake leaks
python3 aiscan.py selftest               # precision/recall scorecard
```

This shows what a finding looks like — masked value, fingerprint, file,
line, remediation steps — without touching the network.

## 2. Scan your own code (10 minutes)

```bash
# Scan a directory tree
python3 aiscan.py scan local ~/myrepo

# Include git history — deleting a file does not delete the secret
python3 aiscan.py scan local ~/myrepo --git-history

# Save a Markdown remediation report
python3 aiscan.py scan local ~/myrepo --format md --output report.md
```

Every finding shows a masked value (first 4 characters + `...`) and a
SHA-256 fingerprint (first 16 hex). The full key is never written to the
report. If a finding is real, rotate the key first, then remove it from
history — removing the file alone is not enough.

## 3. Try the web scanner (5 minutes)

Open https://key-sentry-inky.vercel.app and run a scan from the browser.
Same rules as the CLI: masked values and fingerprints only, strangers'
keys are never tested against a provider.

## 4. Add a fingerprint of your own key (10 minutes)

Fingerprint monitoring watches public code for your own keys, without you
ever sharing the key itself.

1. Compute the fingerprint of one of your own keys:
   SHA-256 of the key value, first 16 hex characters.
2. Register that fingerprint for monitoring (pilot feature — see
   `PILOT-GUIDE.md` for the current state).
3. When the fingerprint appears in a public scan, you get an alert with
   the masked value, the file location, and remediation steps. The raw key
   is never included.

Note: fingerprint monitoring is item 1 of the commercial build and is
still in progress (see `COMMERCIAL-STATUS.md`). If it is not live yet when
you start the pilot, use local scans and the web scanner first, and ask
for fingerprint monitoring as your first request.

## 5. Store your own findings in the vault (optional)

```bash
python3 aiscan.py vault init                       # set admin passphrase
python3 aiscan.py scan local ~/myrepo --vault      # store OWN findings
python3 aiscan.py vault list                       # masked only
python3 aiscan.py vault reveal vlt_abc123          # admin passphrase; audit-logged
python3 aiscan.py vault rotate vlt_abc123          # mark rotated
python3 aiscan.py vault purge                      # drop rotated/expired > 30 days
```

The vault is for your own keys only. Live internet findings are never
vaulted — the CLI refuses `--vault` on live internet scans.

## What to try in the first 30 minutes

1. Run the demo and the selftest.
2. Scan one of your own repos, with `--git-history`.
3. Run the web scanner once.
4. Pick one finding (real or demo) and walk through its remediation steps.
5. Write down anything that looked wrong: a false positive, a key the
   scanner missed, or a step that was unclear. That list is your pilot
   feedback — see `PILOT-GUIDE.md`.

## What KeySentry is not

- Not a replacement for your existing CI secret scanners. It is an add-on
  that catches AI-specific keys and leaks outside the pipeline.
- Not a guarantee. A finding marked "live" means the key is still exposed
  in public code. Only the key's owner can confirm it still works.
- Not a place to paste real keys. Never paste a live key into a report,
  an issue, or an email. Masked value + fingerprint only.
