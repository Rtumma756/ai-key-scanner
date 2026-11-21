#!/usr/bin/env python3
"""Tests for confidence scoring (confidence.py).

All fixture keys use the obviously-fake TESTFAKE marker and are never
real-looking keys. Run with:  python3 -m pytest tests/test_confidence.py
(or: python3 -m pytest tests/ from the repo root).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from common import Finding  # noqa: E402
from confidence import score_finding  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(ROOT, "..")

# --- Fixtures: obviously fake TESTFAKE keys, never real-looking ----------
# Gemini key, exact 39-char format (AIza + 35).
GEMINI_REAL = "AIzaSyTESTFAKEQ7w9Kx2mZv8Np4Rt6Yh3Jf5Gd"
assert len(GEMINI_REAL) == 39

# Entropy-only value: no provider prefix, random-looking, no sequential runs.
ENTROPY_VALUE = "TESTFAKEMn2pQr7St4Uv9Wk3Yz8Kd5Fg2Hj6Lp"

# Explicit test key marker.
PLACEHOLDER_VALUE = "sk_test_TESTFAKE4eC39HqLyjWDarjtT1zdp7dc"


def _gemini_in_app_code() -> Finding:
    return Finding(
        provider="Google Gemini",
        credential_type="API key",
        value=GEMINI_REAL,
        file_path="app.py",
        line_number=12,
        snippet=('import google.generativeai as genai\n'
                 'api_key = "AIza..."\n'
                 'client = genai.Client(api_key=api_key)'),
        severity="high",
        detected_via="regex",
    )


def test_real_gemini_in_app_code_scores_high():
    score, evidence = score_finding(_gemini_in_app_code())
    assert score >= 80, (score, evidence)
    assert any("exact" in e for e in evidence)
    assert any("application code" in e for e in evidence)
    assert any("client" in e for e in evidence)


def test_example_key_in_docs_scores_low():
    finding = Finding(
        provider="Google Gemini",
        credential_type="API key",
        value=GEMINI_REAL,
        file_path="README.md",
        line_number=3,
        snippet="Get a key at https://aistudio.google.com and set GOOGLE_API_KEY.",
        severity="high",
        detected_via="regex",
    )
    score, evidence = score_finding(finding)
    assert score < 50, (score, evidence)
    assert any("docs" in e for e in evidence)


def test_entropy_only_scores_lower_than_exact_format():
    exact_score, _ = score_finding(_gemini_in_app_code())
    entropy_finding = Finding(
        provider="Mistral",
        credential_type="API key (entropy-detected)",
        value=ENTROPY_VALUE,
        file_path="app.py",
        line_number=7,
        snippet='api_key = "Mn2p..."',
        severity="medium",
        detected_via="entropy",
    )
    entropy_score, entropy_evidence = score_finding(entropy_finding)
    assert entropy_score < exact_score, (entropy_score, exact_score)
    assert entropy_score < 60, (entropy_score, entropy_evidence)
    assert any("entropy-only" in e for e in entropy_evidence)


def test_known_placeholder_scores_near_zero():
    finding = Finding(
        provider="OpenAI",
        credential_type="API key",
        value=PLACEHOLDER_VALUE,
        file_path="app.py",
        line_number=1,
        snippet='api_key = "sk_test_..."',
        severity="high",
        detected_via="regex",
    )
    score, evidence = score_finding(finding)
    assert score <= 5, (score, evidence)
    assert any("placeholder" in e for e in evidence)


def test_corpus_placeholder_classification_scores_near_zero():
    row = {
        "provider": "Google Gemini",
        "masked": "AIza...",
        "fingerprint": "deadbeef01234567",
        "file": "github:some/repo/app.js",
        "line": 5,
        "classification": "placeholder",
        "length": 39,
        "status": "matched",
    }
    score, evidence = score_finding(row)
    assert score <= 5, (score, evidence)


def test_corpus_row_dict_scores_without_snippet():
    row = {
        "provider": "Google Gemini",
        "masked": "AIza...",
        "fingerprint": "00db8fc282cff8a6",
        "file": "github:0utKast/firebase04/app.js",
        "line": 5,
        "classification": "real",
        "length": 39,
        "status": "matched",
        "exposed_since": {"date": "2016-11-29T19:25:15Z"},
        "in_trial_67": True,
    }
    score, evidence = score_finding(
        row, context={"still_live": True, "as_of": "2026-11-21"})
    # 40 base + 25 exact format + 10 code + 10 liveness age + 5 still-live
    # + 5 corroboration (trial-67) = 95
    assert score == 95, (score, evidence)


def test_score_is_clamped_to_0_100():
    finding = _gemini_in_app_code()
    score, _ = score_finding(
        finding,
        context={"still_live": True, "report_count": 5,
                 "exposed_since": "2015-01-01", "as_of": "2026-11-21"})
    assert 0 <= score <= 100


def test_public_dict_carries_confidence_and_never_raw_value():
    finding = _gemini_in_app_code()
    public = finding.public_dict()
    assert "confidence" in public
    assert "confidence_evidence" in public
    assert isinstance(public["confidence"], int)
    assert 0 <= public["confidence"] <= 100
    assert isinstance(public["confidence_evidence"], list)
    dumped = json.dumps(public)
    assert GEMINI_REAL not in dumped
    assert "AIza" in public["masked"]  # masked form only


def test_score_results_runs_on_corpus_files():
    from score_results import score_file
    from confidence import build_corpus_context

    stress = os.path.join(REPO, "results", "STRESS_606_CLASSIFICATION.json")
    fresh = os.path.join(REPO, "results", "CLASSIFY_FRESH_41.json")
    liveness = os.path.join(REPO, "results", "FRESH_LIVENESS_ALL.json")
    if not (os.path.isfile(stress) and os.path.isfile(fresh)):
        import pytest
        pytest.skip("corpus files not present")
    corpus = build_corpus_context(
        [json.load(open(p)) for p in (stress, fresh, liveness)
         if os.path.isfile(p)])
    total = 0
    for path in (stress, fresh):
        scored = score_file(path, corpus, as_of="2026-11-21")
        summary = scored["confidence_summary"]
        assert summary["total"] == sum(
            summary[k] for k in ("high (>=80)", "medium (50-79)", "low (<50)"))
        total += summary["total"]
        rows = scored.get("keys") or scored.get("rows")
        assert all("confidence" in r and "confidence_evidence" in r
                   for r in rows)
        assert all(0 <= r["confidence"] <= 100 for r in rows)
    assert total == 660 + 41
