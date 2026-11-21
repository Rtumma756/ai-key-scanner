#!/usr/bin/env python3
"""Tests for the example / test-key filter (detectors.is_example_key).

The filter drops values that are marked as examples from findings, so a
repo's docs, tests and fixtures do not fail a CI gate with fake keys.
Detection itself is unchanged: scan_line(..., allow_examples=True)
still matches a marked value. Real-looking values (no marker) must
never be filtered — a false negative here is a missed real leak.

All values below are synthetic test data, never real credentials. The
"realistic" values are built at runtime from hashes / repetition so no
real-looking literal sits in the repo.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from detectors import is_example_key, scan_line  # noqa: E402
from engine import scan_source  # noqa: E402
from sources import LocalSource  # noqa: E402


# --- is_example_key: compound markers ------------------------------------
def test_testfake_marker_is_example():
    assert is_example_key("sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")
    assert is_example_key("AIzaTESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b")
    assert is_example_key("testfakeMn2pQr7St4Uv9Wk3Yz8Kd5Fg2Hj6Lp")


def test_demofake_marker_is_example():
    assert is_example_key("sk-proj-DEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")
    assert is_example_key("gsk_DEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")


def test_deadbeef_hex_marker_is_example():
    assert is_example_key("sk-deadbeefdeadbeefdeadbeefdeadbeef")
    assert is_example_key("deadbeef9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4")


def test_test_key_prefixes_are_examples():
    assert is_example_key("sk_test_4eC39HqLyjWDarjtT1zdp7dc")
    assert is_example_key("pk_test_TYooMQauvdEDq54NiTphI7jx")
    assert is_example_key("rk_test_4eC39HqLyjWDarjtT1zdp7dc")


def test_delimited_example_words_are_examples():
    assert is_example_key("sk-proj-EXAMPLE-key-0123456789abcdef")
    assert is_example_key("sk-FAKE-KEY-0123456789abcdef0123456789ab")
    assert is_example_key("sk-proj-sample-key-0123456789abcdef")
    assert is_example_key("sk-proj-your-api-key-here-0123456789")
    assert is_example_key("sk-proj-changeme1234567890abcdef")
    assert is_example_key("sk-proj-xxx-0123456789abcdef0123456789")


# --- is_example_key: must NOT flag real-looking values --------------------
def test_realistic_values_are_not_examples():
    # All values here are built at runtime (hashes / repetition), never
    # written as literals: a realistic-looking literal in this file would
    # itself be flagged by the repo's own dogfood scan.
    # Legacy OpenAI format, random-looking, no marker.
    assert not is_example_key(
        "sk-" + hashlib.sha256(b"legacy-realistic").hexdigest()[:48])
    # Gemini format, random-looking.
    assert not is_example_key(
        "AIza" + hashlib.sha256(b"gemini-realistic").hexdigest()[:35])
    # Groq format, random-looking.
    assert not is_example_key(
        "gsk_" + hashlib.sha256(b"groq-realistic").hexdigest()[:32])
    # DeepSeek format: the OLD demo value (sequential hex, no marker) is
    # deliberately NOT an example by value alone — it is only fake because
    # we planted it. The repo's copy is marked deadbeef instead.
    assert not is_example_key("sk-" + "abcdef0123456789" * 2)
    # A random 64-hex Together-style value with no marker.
    assert not is_example_key(hashlib.sha256(b"realistic-hex").hexdigest())
    # "test" as a substring of a random-looking value is not enough:
    # token matching requires a delimiter.
    assert not is_example_key("sk-proj-" + "aTestKey9Zk2mN4pL6sT8vB1cD3eF5gH7jK")
    assert not is_example_key("sk-proj-" + "contestWinner9Zk2mN4pL6sT8vB1cD3")


def test_empty_value_is_not_example():
    assert not is_example_key("")


# --- scan_line: filter on by default, bypassable --------------------------
def test_scan_line_filters_marked_values_by_default():
    assert scan_line('OPENAI_API_KEY="sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"') == []
    assert scan_line('GROQ_API_KEY="gsk_DEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"') == []
    assert scan_line('DEEPSEEK_API_KEY="sk-deadbeefdeadbeefdeadbeefdeadbeef"') == []
    assert scan_line('OPENAI_API_KEY="sk_test_4eC39HqLyjWDarjtT1zdp7dc"') == []


def test_scan_line_still_detects_marked_values_with_allow_examples():
    found = scan_line(
        'OPENAI_API_KEY="sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"',
        allow_examples=True)
    assert len(found) == 1 and found[0].provider == "OpenAI"
    found = scan_line(
        'DEEPSEEK_API_KEY="sk-deadbeefdeadbeefdeadbeefdeadbeef"',
        allow_examples=True)
    assert len(found) == 1 and found[0].provider == "DeepSeek"


def test_scan_line_keeps_realistic_values():
    value = "sk-" + hashlib.sha256(b"scan-line-realistic").hexdigest()[:48]
    found = scan_line(f'OPENAI_API_KEY="{value}"')
    assert len(found) == 1 and found[0].provider == "OpenAI"
    assert found[0].value == value


def test_scan_line_keeps_real_key_next_to_example():
    real = "sk-" + hashlib.sha256(b"real-next-to-example").hexdigest()[:48]
    line = (f'OPENAI_API_KEY="{real}" '
            f'# old: OPENAI_API_KEY="sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"')
    found = scan_line(line)
    assert [f.value for f in found] == [real]


# --- scan_source integration: mixed directory -----------------------------
def test_scan_source_filters_examples_but_keeps_real(tmp_path):
    (tmp_path / "example.py").write_text(
        'OPENAI_API_KEY = "sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"\n'
        'DEEPSEEK_API_KEY = "sk-deadbeefdeadbeefdeadbeefdeadbeef"\n',
        encoding="utf-8")
    real = "sk-" + hashlib.sha256(b"integration-real").hexdigest()[:48]
    (tmp_path / "app.py").write_text(
        f'OPENAI_API_KEY = "{real}"\n', encoding="utf-8")
    filtered = scan_source(LocalSource(str(tmp_path)))
    assert [f.value for f in filtered] == [real]
    unfiltered = scan_source(LocalSource(str(tmp_path)), allow_examples=True)
    assert len(unfiltered) == 3
