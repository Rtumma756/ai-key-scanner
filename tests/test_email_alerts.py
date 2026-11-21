#!/usr/bin/env python3
"""Tests for email_alert.py (fingerprint-match email alerts, CLI side).

All transports are mocked — no real network, no real credentials.
Run with:  python3 -m pytest tests/test_email_alerts.py

All fixture keys use the obviously-fake TESTFAKE marker and are never
real-looking keys. The "raw key" asserted absent from every email is
a dummy TESTFAKE string, never a stranger's key.
"""
import io
import json
import os
import sys
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import email_alert  # noqa: E402

# Dummy "raw key" — obviously fake, used ONLY to assert it never
# appears in any email subject or body.
DUMMY_RAW_KEY = "sk-TESTFAKE-DO-NOT-USE-1234567890abcdef"

MATCH = {
    "fingerprint": "06fabb99a6b4976b",
    "provider": "Groq",
    "repo": "acme/app",
    "file": ".env",
    "line": 7,
    "firstSeen": "2026-11-21T00:00:00.000Z",
}

EMAIL_ENV_KEYS = [
    "KEYSENTRY_ALERT_EMAIL",
    "KEYSENTRY_ALERT_FROM",
    "KEYSENTRY_APP_URL",
    "RESEND_API_KEY",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASS",
]


def _clear_env(monkeypatch):
    for key in EMAIL_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return b'{"id": "test-id"}'


def test_unconfigured_returns_false_without_raising(monkeypatch):
    _clear_env(monkeypatch)
    assert email_alert.email_configured() is False
    assert email_alert.send_match_email(MATCH) is False


def test_recipients_without_transport_returns_false(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("KEYSENTRY_ALERT_EMAIL", "owner@example.com")
    assert email_alert.email_configured() is False
    assert email_alert.send_match_email(MATCH) is False


def test_resend_ok_returns_true_and_payload_has_match_no_raw_key(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("KEYSENTRY_ALERT_EMAIL",
                       "owner@example.com, ops@example.com")
    monkeypatch.setenv("RESEND_API_KEY", "re_TESTFAKE")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse(200)

    monkeypatch.setattr(email_alert.urllib.request, "urlopen", fake_urlopen)
    assert email_alert.email_configured() is True
    assert email_alert.send_match_email(MATCH) is True
    assert captured["url"] == "https://api.resend.com/emails"
    assert captured["headers"]["Authorization"] == "Bearer re_TESTFAKE"
    body = captured["body"]
    assert body["to"] == ["owner@example.com", "ops@example.com"]
    assert MATCH["fingerprint"] in body["subject"]
    for part in (body["text"], body["html"]):
        assert MATCH["fingerprint"] in part
        assert "Groq" in part
        assert "acme/app" in part
        assert DUMMY_RAW_KEY not in part
    assert "never included in alerts" in body["text"]


def test_resend_http_error_returns_false_without_raising(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("KEYSENTRY_ALERT_EMAIL", "owner@example.com")
    monkeypatch.setenv("RESEND_API_KEY", "re_TESTFAKE")

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "bad key", {}, io.BytesIO(b""))

    monkeypatch.setattr(email_alert.urllib.request, "urlopen", fake_urlopen)
    assert email_alert.send_match_email(MATCH) is False


def test_resend_network_failure_returns_false_without_raising(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("KEYSENTRY_ALERT_EMAIL", "owner@example.com")
    monkeypatch.setenv("RESEND_API_KEY", "re_TESTFAKE")

    def fake_urlopen(req, timeout=None):
        raise ConnectionError("network down")

    monkeypatch.setattr(email_alert.urllib.request, "urlopen", fake_urlopen)
    assert email_alert.send_match_email(MATCH) is False


def test_smtp_ok_returns_true_and_mail_has_match_no_raw_key(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("KEYSENTRY_ALERT_EMAIL", "owner@example.com")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "user@example.com")
    monkeypatch.setenv("SMTP_PASS", "TESTFAKE-pass")
    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            captured["host"] = host
            captured["port"] = port

        def starttls(self):
            captured["starttls"] = True

        def login(self, user, password):
            captured["login"] = (user, password)

        def send_message(self, msg):
            captured["msg"] = msg

        def quit(self):
            captured["quit"] = True

    monkeypatch.setattr(email_alert.smtplib, "SMTP", FakeSMTP)
    assert email_alert.email_configured() is True
    assert email_alert.send_match_email(MATCH) is True
    assert captured["host"] == "smtp.example.com"
    assert captured["port"] == 587
    assert captured["starttls"] is True
    assert captured["login"] == ("user@example.com", "TESTFAKE-pass")
    msg = captured["msg"]
    assert MATCH["fingerprint"] in msg["Subject"]
    text = msg.get_body(preferencelist=("plain",)).get_content()
    html = msg.get_body(preferencelist=("html",)).get_content()
    for part in (str(msg["Subject"]), text, html):
        assert MATCH["fingerprint"] in part
        assert DUMMY_RAW_KEY not in part
    assert "Groq" in text
    assert "acme/app" in text
    assert "never included in alerts" in text


def test_smtp_failure_returns_false_without_raising(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("KEYSENTRY_ALERT_EMAIL", "owner@example.com")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "user@example.com")
    monkeypatch.setenv("SMTP_PASS", "TESTFAKE-pass")

    class FailingSMTP:
        def __init__(self, *args, **kwargs):
            raise ConnectionError("SMTP refused")

    monkeypatch.setattr(email_alert.smtplib, "SMTP", FailingSMTP)
    assert email_alert.send_match_email(MATCH) is False


def test_resend_wins_over_smtp_when_both_configured(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("KEYSENTRY_ALERT_EMAIL", "owner@example.com")
    monkeypatch.setenv("RESEND_API_KEY", "re_TESTFAKE")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "user@example.com")
    monkeypatch.setenv("SMTP_PASS", "TESTFAKE-pass")
    called = {}

    def fake_urlopen(req, timeout=None):
        called["resend"] = True
        return _FakeResponse(200)

    class ExplodingSMTP:
        def __init__(self, *args, **kwargs):
            raise AssertionError("SMTP must not be used when Resend is set")

    monkeypatch.setattr(email_alert.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(email_alert.smtplib, "SMTP", ExplodingSMTP)
    assert email_alert.send_match_email(MATCH) is True
    assert called.get("resend") is True


def test_subject_and_body_contain_match_never_raw_key(monkeypatch):
    _clear_env(monkeypatch)
    subject = email_alert.match_email_subject(MATCH)
    body = email_alert.match_email_body(MATCH)
    for part in (subject, body["text"], body["html"]):
        assert MATCH["fingerprint"] in part
        assert DUMMY_RAW_KEY not in part
    assert "Groq" in body["text"]
    assert "acme/app" in body["text"]
    assert ".env" in body["text"]
    assert "https://key-sentry-inky.vercel.app" in body["text"]
    assert "never included in alerts" in body["text"]
    assert "never included in alerts" in body["html"]


def test_explicit_config_dict_overrides_env(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("RESEND_API_KEY", "re_TESTFAKE-ENV")
    config = {
        "recipients": ["cfg@example.com"],
        "resend_api_key": "re_TESTFAKE-CFG",
    }
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse(200)

    monkeypatch.setattr(email_alert.urllib.request, "urlopen", fake_urlopen)
    assert email_alert.send_match_email(MATCH, config) is True
    assert captured["headers"]["Authorization"] == "Bearer re_TESTFAKE-CFG"
    assert captured["body"]["to"] == ["cfg@example.com"]
