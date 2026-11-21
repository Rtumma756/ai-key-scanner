#!/usr/bin/env python3
"""email_alert.py — KeySentry fingerprint-match email alerts (CLI side).

Mirrors the web app's lib/email.ts: same priority, same env vars, same
message contents, same safety rules.

Priority:
  (a) Resend HTTP API when RESEND_API_KEY is set — plain urllib POST to
      https://api.resend.com/emails. Free tier: 100 emails/day.
  (b) Plain SMTP when SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS are
      set, via stdlib smtplib. SMTP_PORT defaults to 587 (STARTTLS);
      port 465 uses implicit TLS (SMTP_SSL).

Recipients: KEYSENTRY_ALERT_EMAIL, comma-separated.
From: KEYSENTRY_ALERT_FROM, or
      "KeySentry <alerts@key-sentry-inky.vercel.app>".
App link: KEYSENTRY_APP_URL, or https://key-sentry-inky.vercel.app.

HARD RULES (same as the web app and fingerprint_watch.py):
  * Only the fingerprint (SHA-256, first 16 hex), the provider, and
    where it was seen are ever sent — never a raw or masked key.
  * send_match_email() never raises: it logs errors and returns False,
    so alerting can never break match recording.
  * Stdlib only (smtplib/email/urllib). No new dependency.

Config: pass a dict, or None to read from the environment. A config
dict overrides env for the keys it provides (empty-string values in
the dict count as unset). Keys:
  recipients (list[str]) | email (str, comma-separated, env fallback)
  resend_api_key | smtp_host | smtp_port | smtp_user | smtp_pass
  from_addr | app_url

Wiring (fingerprint_watch.py is owned by another agent — do NOT edit
it; apply this one line next to its existing webhook/POST handling,
inside cmd_check() after a NEW match is recorded, i.e. right after
the `posted_new += 1` line):
    from email_alert import send_match_email
    ...
    send_match_email(match)   # match already carries fingerprint /
                              # provider / repo / file / line only
See docs/commercial/EMAIL-ALERTS.md for the full procedure.
"""

from __future__ import annotations

import json
import os
import smtplib
import sys
import urllib.error
import urllib.request
from email.message import EmailMessage

DEFAULT_ALERT_FROM = "KeySentry <alerts@key-sentry-inky.vercel.app>"
DEFAULT_APP_URL = "https://key-sentry-inky.vercel.app"
RESEND_API_URL = "https://api.resend.com/emails"


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _cfg(config: dict | None, *keys: str) -> str:
    """First non-empty value among config keys, then the matching env var.

    Config keys are checked in order, then env vars named by the same
    keys upper-cased (e.g. "resend_api_key" -> RESEND_API_KEY)."""
    config = config or {}
    for key in keys:
        value = config.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in keys:
        value = _env(key.upper())
        if value:
            return value
    return ""


def alert_recipients(config: dict | None = None) -> list[str]:
    """Recipient list from config['recipients'] or KEYSENTRY_ALERT_EMAIL."""
    config = config or {}
    recipients = config.get("recipients")
    if isinstance(recipients, (list, tuple)):
        return [str(r).strip() for r in recipients if str(r).strip()]
    raw = _cfg(config, "email", "alert_email")
    if not raw:
        raw = _env("KEYSENTRY_ALERT_EMAIL")
    return [addr.strip() for addr in raw.split(",") if addr.strip()]


def alert_from(config: dict | None = None) -> str:
    return _cfg(config, "from_addr", "from") or DEFAULT_ALERT_FROM


def alert_app_url(config: dict | None = None) -> str:
    return _cfg(config, "app_url") or DEFAULT_APP_URL


def _smtp_config(config: dict | None = None) -> dict | None:
    host = _cfg(config, "smtp_host")
    user = _cfg(config, "smtp_user")
    password = _cfg(config, "smtp_pass")
    if not host or not user or not password:
        return None
    try:
        port = int(_cfg(config, "smtp_port") or 587)
    except ValueError:
        port = 587
    if port <= 0:
        port = 587
    return {"host": host, "port": port, "user": user, "pass": password}


def email_configured(config: dict | None = None) -> bool:
    """True when an email can be sent: recipients AND a transport."""
    if not alert_recipients(config):
        return False
    return bool(_cfg(config, "resend_api_key")) or _smtp_config(config) is not None


def match_email_subject(match: dict) -> str:
    provider = str(match.get("provider") or "unknown provider")
    return (
        f"[KeySentry] Watched key {match.get('fingerprint', '')} "
        f"seen again ({provider})"
    )


def match_email_body(match: dict, config: dict | None = None) -> dict:
    """Return {'text': ..., 'html': ...} for a match dict.

    Accepts the web/CLI match shape: fingerprint, provider, repo,
    file, line, firstSeen (or first_seen). No key material is read
    from the dict — anything else in it is ignored."""
    provider = str(match.get("provider") or "unknown provider")
    fingerprint = str(match.get("fingerprint") or "")
    repo = str(match.get("repo") or "")
    file = str(match.get("file") or "")
    where = " · ".join(part for part in (repo, file) if part)
    line = match.get("line") or 0
    line_suffix = f":{line}" if isinstance(line, int) and line > 0 else ""
    location = f"{where}{line_suffix}" if where else "(location not recorded)"
    first_seen = str(match.get("firstSeen") or match.get("first_seen") or "")
    app_url = alert_app_url(config).rstrip("/")

    text = (
        "KeySentry: a watched key was seen again.\n"
        "\n"
        f"Fingerprint: {fingerprint}\n"
        f"Provider: {provider}\n"
        f"Seen in: {location}\n"
        f"First seen: {first_seen}\n"
        "\n"
        f"Acknowledge or resolve it at {app_url} (matches list).\n"
        "\n"
        "The key itself is never included in alerts — only its SHA-256 "
        "fingerprint (a one-way hash) is sent, so this email cannot be used "
        "to recover the key. Rotate the key if it should no longer work."
    )

    def esc(value: str) -> str:
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    html = (
        "<p>KeySentry: a watched key was seen again.</p>"
        "<ul>"
        f"<li><strong>Fingerprint:</strong> <code>{esc(fingerprint)}</code></li>"
        f"<li><strong>Provider:</strong> {esc(provider)}</li>"
        f"<li><strong>Seen in:</strong> {esc(location)}</li>"
        f"<li><strong>First seen:</strong> {esc(first_seen)}</li>"
        "</ul>"
        f'<p>Acknowledge or resolve it in the <a href="{esc(app_url)}">'
        "KeySentry matches list</a>.</p>"
        "<p><small>The key itself is never included in alerts — only its "
        "SHA-256 fingerprint (a one-way hash) is sent, so this email cannot "
        "be used to recover the key. Rotate the key if it should no longer "
        "work.</small></p>"
    )
    return {"text": text, "html": html}


def _send_via_resend(match: dict, config: dict | None) -> bool:
    api_key = _cfg(config, "resend_api_key")
    if not api_key:
        return False
    body = match_email_body(match, config)
    payload = json.dumps(
        {
            "from": alert_from(config),
            "to": alert_recipients(config),
            "subject": match_email_subject(match),
            "text": body["text"],
            "html": body["html"],
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        RESEND_API_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as exc:
        print(f"email_alert: Resend answered HTTP {exc.code}", file=sys.stderr)
        return False


def _send_via_smtp(match: dict, config: dict | None) -> bool:
    smtp = _smtp_config(config)
    if smtp is None:
        return False
    body = match_email_body(match, config)
    msg = EmailMessage()
    msg["From"] = alert_from(config)
    msg["To"] = ", ".join(alert_recipients(config))
    msg["Subject"] = match_email_subject(match)
    msg.set_content(body["text"])
    msg.add_alternative(body["html"], subtype="html")
    if smtp["port"] == 465:
        server = smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=10)
    else:
        server = smtplib.SMTP(smtp["host"], smtp["port"], timeout=10)
        server.starttls()
    try:
        server.login(smtp["user"], smtp["pass"])
        server.send_message(msg)
        return True
    finally:
        try:
            server.quit()
        except Exception:
            pass


def send_match_email(match: dict, config: dict | None = None) -> bool:
    """Send a fingerprint-match email. Never raises.

    Returns True when a transport accepted it, False when email is
    unconfigured or delivery failed. Resend is tried first when its
    API key is set; otherwise plain SMTP.
    """
    try:
        if not email_configured(config):
            return False
        # Resend first when its key is set; otherwise plain SMTP.
        if _cfg(config, "resend_api_key"):
            return _send_via_resend(match, config)
        return _send_via_smtp(match, config)
    except Exception as exc:  # transport errors must never break the caller
        print(f"email_alert: send failed: {exc}", file=sys.stderr)
        return False


if __name__ == "__main__":
    # Smoke check: with no env set this must print False, not raise.
    demo = {
        "fingerprint": "06fabb99a6b4976b",
        "provider": "Groq",
        "repo": "acme/app",
        "file": ".env",
        "line": 7,
        "firstSeen": "2026-11-21T00:00:00.000Z",
    }
    print(send_match_email(demo))
