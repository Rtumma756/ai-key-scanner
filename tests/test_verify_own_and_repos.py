#!/usr/bin/env python3
"""Tests for repos.py (repo connection) and verify_own.py (owner-authorized
verification).

TESTFAKE keys only — no real-looking key appears in any test or fixture.
No network is used: provider probes are monkeypatched, GitHub API calls
are monkeypatched or exercised through the pure parsers against the
canned fixture in tests/fixtures/github_repos_response.json.

Run:
  python3 -m unittest discover -s tests -v
  python3 tests/test_verify_own_and_repos.py
"""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import repos  # noqa: E402
import verify_own  # noqa: E402

# Deliberately fake: the word TESTFAKE plus a short token. Never a
# real-looking provider key format.
TESTFAKE_KEY = "TESTFAKE-KEY-0001-AbCdEfGh"
TESTFAKE_KEY_2 = "TESTFAKE-KEY-0002-ZzYyXxWw"
DUMMY_TOKEN = "DUMMY-TOKEN-FOR-TEST-ONLY"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "github_repos_response.json")


def _fake_verify_live(provider, value, timeout=10):
    return ("live", "HTTP 200 — key accepted (TESTFAKE probe)")


def _verify_must_not_be_called(provider, value, timeout=10):
    raise AssertionError(
        "verify_key must not be called for this input — a guard should "
        "have refused first")


def _run_verify(argv, stdin_text=None):
    """Run verify_own.main capturing stdout/stderr; return (code, out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = verify_own.main(argv, stdin_text=stdin_text)
    return code, out.getvalue(), err.getvalue()


def _run_repos(argv, env_token=DUMMY_TOKEN):
    """Run repos.main capturing stdout/stderr; return (code, out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"GITHUB_TOKEN": env_token}):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = repos.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestVerifyOwnGuards(unittest.TestCase):
    def test_consent_flag_required(self):
        with mock.patch.object(verify_own, "verify_key",
                               _verify_must_not_be_called):
            code, out, err = _run_verify(
                ["--provider", "groq"], stdin_text=TESTFAKE_KEY)
        self.assertEqual(code, 2)
        self.assertIn("--i-own-these-keys", err)
        self.assertNotIn(TESTFAKE_KEY, out + err)

    def test_results_json_object_input_refused(self):
        findings_json = json.dumps({
            "tool": "aiscan",
            "findings": [{
                "provider": "Groq",
                "masked": "TEST...",
                "fingerprint_sha256_16": "ab12cd34ef56ab78",
            }],
        })
        with mock.patch.object(verify_own, "verify_key",
                               _verify_must_not_be_called):
            code, out, err = _run_verify(
                ["--provider", "groq", "--i-own-these-keys"],
                stdin_text=findings_json)
        self.assertEqual(code, 2)
        self.assertIn("findings", err.lower())
        self.assertNotIn("ab12cd34ef56ab78", out)

    def test_results_json_list_input_refused(self):
        findings_json = json.dumps(
            [{"masked": "TEST...", "fingerprint_sha256_16": "ab12cd34ef56ab78"}])
        with mock.patch.object(verify_own, "verify_key",
                               _verify_must_not_be_called):
            code, out, err = _run_verify(
                ["--provider", "groq", "--i-own-these-keys"],
                stdin_text=findings_json)
        self.assertEqual(code, 2)

    def test_file_argument_refused(self):
        # A scan-results file passed as a positional arg is refused.
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump({"findings": []}, f)
            path = f.name
        try:
            with mock.patch.object(verify_own, "verify_key",
                                   _verify_must_not_be_called):
                code, out, err = _run_verify(
                    ["--provider", "groq", "--i-own-these-keys", path],
                    stdin_text=TESTFAKE_KEY)
            self.assertEqual(code, 2)
            self.assertIn("Refused", err)
        finally:
            os.unlink(path)

    def test_multiple_keys_on_stdin_refused(self):
        with mock.patch.object(verify_own, "verify_key",
                               _verify_must_not_be_called):
            code, out, err = _run_verify(
                ["--provider", "groq", "--i-own-these-keys"],
                stdin_text=f"{TESTFAKE_KEY}\n{TESTFAKE_KEY_2}\n")
        self.assertEqual(code, 2)
        self.assertIn("one key at a time", err)

    def test_empty_stdin_refused(self):
        with mock.patch.object(verify_own, "verify_key",
                               _verify_must_not_be_called):
            code, out, err = _run_verify(
                ["--provider", "groq", "--i-own-these-keys"], stdin_text="  \n")
        self.assertEqual(code, 2)


class TestVerifyOwnOutcomes(unittest.TestCase):
    def test_unsupported_provider_reports_unsupported_no_network(self):
        # Anthropic has no read-only verifier in verifiers/registry.py.
        with mock.patch.object(verify_own, "verify_key",
                               _verify_must_not_be_called):
            code, out, err = _run_verify(
                ["--provider", "anthropic", "--i-own-these-keys"],
                stdin_text=TESTFAKE_KEY)
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["provider"], "anthropic")
        self.assertNotIn(TESTFAKE_KEY, out)

    def test_live_result_shape_masked_only(self):
        with mock.patch.object(verify_own, "verify_key", _fake_verify_live):
            code, out, err = _run_verify(
                ["--provider", "groq", "--i-own-these-keys"],
                stdin_text=TESTFAKE_KEY)
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual(result["status"], "live")
        self.assertEqual(result["provider"], "groq")
        self.assertEqual(result["masked"], "TEST...")
        self.assertEqual(result["fingerprint"],
                         hashlib.sha256(TESTFAKE_KEY.encode()).hexdigest()[:16])
        self.assertEqual(result["source"], "stdin")
        self.assertNotIn(TESTFAKE_KEY, out)
        self.assertNotIn(TESTFAKE_KEY, err)

    def test_dead_result_shape(self):
        def fake_dead(provider, value, timeout=10):
            return ("dead", "HTTP 401 — revoked or invalid")
        with mock.patch.object(verify_own, "verify_key", fake_dead):
            code, out, err = _run_verify(
                ["--provider", "openai", "--i-own-these-keys"],
                stdin_text=TESTFAKE_KEY)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "dead")

    def test_mark_verified_writes_fingerprint_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            verified_path = os.path.join(tmp, "verified-fingerprints.json")
            with mock.patch.object(verify_own, "verify_key", _fake_verify_live):
                code, out, err = _run_verify(
                    ["--provider", "groq", "--i-own-these-keys",
                     "--mark-verified", "--verified-file", verified_path],
                    stdin_text=TESTFAKE_KEY)
            self.assertEqual(code, 0)
            result = json.loads(out)
            self.assertTrue(result["marked_verified"])
            with open(verified_path, encoding="utf-8") as f:
                stored = json.load(f)
            fp = hashlib.sha256(TESTFAKE_KEY.encode()).hexdigest()[:16]
            self.assertIn(fp, stored["fingerprints"])
            self.assertNotIn(TESTFAKE_KEY, json.dumps(stored))

    def test_mark_verified_not_set_when_not_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            verified_path = os.path.join(tmp, "verified-fingerprints.json")
            with mock.patch.object(verify_own, "verify_key",
                                   lambda p, v, timeout=10: ("dead", "HTTP 401")):
                code, out, err = _run_verify(
                    ["--provider", "groq", "--i-own-these-keys",
                     "--mark-verified", "--verified-file", verified_path],
                    stdin_text=TESTFAKE_KEY)
            self.assertEqual(code, 0)
            self.assertNotIn("marked_verified", out)
            self.assertFalse(os.path.exists(verified_path))


class TestReposParsers(unittest.TestCase):
    def test_parse_repos_response_fixture(self):
        with open(FIXTURE, encoding="utf-8") as f:
            data = json.load(f)
        parsed = repos.parse_repos_response(data)
        # 4 real repos; the trailing non-dict entry is skipped.
        self.assertEqual(len(parsed), 4)
        by_name = {r["full_name"]: r for r in parsed}
        self.assertEqual(by_name["example-org/alpha-service"]["default_branch"], "main")
        self.assertFalse(by_name["example-org/alpha-service"]["private"])
        self.assertTrue(by_name["example-org/beta-worker"]["private"])
        self.assertEqual(by_name["example-org/beta-worker"]["default_branch"], "develop")
        self.assertTrue(by_name["example-org/old-archived"]["archived"])
        # Missing default_branch falls back to "main".
        self.assertEqual(by_name["example-org/no-branch-field"]["default_branch"], "main")

    def test_select_repos_skips_archived(self):
        with open(FIXTURE, encoding="utf-8") as f:
            parsed = repos.parse_repos_response(json.load(f))
        scannable = repos.select_repos_for_scan(parsed)
        self.assertEqual(len(scannable), 3)
        self.assertNotIn("example-org/old-archived",
                         [r["full_name"] for r in scannable])

    def test_parse_tree_filters_binary_and_large(self):
        tree = {"tree": [
            {"type": "blob", "path": "src/app.py", "size": 1200},
            {"type": "blob", "path": "assets/logo.png", "size": 5000},
            {"type": "blob", "path": "data/big.csv", "size": 900_000},
            {"type": "blob", "path": "config/settings.json", "size": 300},
            {"type": "tree", "path": "src"},
        ]}
        paths = [e["path"] for e in repos.parse_tree_response(tree)]
        self.assertEqual(paths, ["src/app.py", "config/settings.json"])

    def test_is_scannable_path(self):
        self.assertTrue(repos.is_scannable_path("src/app.py"))
        self.assertTrue(repos.is_scannable_path("README.md"))
        self.assertFalse(repos.is_scannable_path("assets/logo.png"))
        self.assertFalse(repos.is_scannable_path("a.py", size=600_000))


class TestReposDryRun(unittest.TestCase):
    def test_dry_run_lists_repos_only_no_scan_no_token_leak(self):
        with open(FIXTURE, encoding="utf-8") as f:
            parsed = repos.parse_repos_response(json.load(f))
        with mock.patch.object(repos.GitHubClient, "list_repos",
                               return_value=parsed):
            with mock.patch.object(repos, "scan_repo") as mock_scan:
                mock_scan.side_effect = AssertionError(
                    "dry-run must not scan")
                code, out, err = _run_repos(["--org", "example-org", "--dry-run"])
        self.assertEqual(code, 0)
        for name in ("example-org/alpha-service", "example-org/beta-worker",
                     "example-org/old-archived"):
            self.assertIn(name, out)
        self.assertIn("Dry run", out)
        self.assertIn("archived", out)
        self.assertNotIn("Scanning", err)
        self.assertNotIn(DUMMY_TOKEN, out + err)

    def test_auth_failure_reported_cleanly_without_token(self):
        def boom(self, *args, **kwargs):
            raise repos.RepoError(
                "GitHub rejected the token (401). Check GITHUB_TOKEN — it "
                "must be a valid personal access token with access to "
                "these repositories.")
        with mock.patch.object(repos.GitHubClient, "list_repos", boom):
            code, out, err = _run_repos(["--org", "example-org", "--dry-run"])
        self.assertEqual(code, 1)
        self.assertIn("401", err)
        self.assertNotIn(DUMMY_TOKEN, out + err)

    def test_missing_token_refused(self):
        code, out, err = _run_repos(["--org", "example-org", "--dry-run"],
                                    env_token="")
        self.assertEqual(code, 2)
        self.assertIn("GITHUB_TOKEN", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
