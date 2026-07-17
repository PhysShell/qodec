"""Unit tests for pytest_requests_duration_canonicalizer_v1.py -- the
repo-requests-only pytest final-summary-duration canonicalizer, independently
derived from pytest 9.1.1's own installed _pytest/terminal.py source (see
pytest-requests-duration-capture-canonicalization-policy-v1.json's
pytest_source_derivation).

This module and its tests are entirely independent of maven_canonicalizer.py,
vstest_canonicalizer.py, gradle_canonicalizer.py (v1), gradle_canonicalizer_v2.py,
gradle_canonicalizer_helm_values_v1.py, cargo_test_canonicalizer.py, and the
REJECTED pytest_requests_canonicalizer.py (v1) -- none is imported, modified,
revived, or broadened here.
"""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import pytest_requests_duration_canonicalizer_v1 as prdc  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
POLICY_PATH = BASE_DIR / "pytest-requests-duration-capture-canonicalization-policy-v1.json"


def _lines(*texts: str) -> bytes:
    return ("\n".join(texts) + "\n").encode("utf-8")


# The exact real evidence: focused diagnostic probe run 29549403465
# (commit c75c60d), capture-a/capture-b's own genuinely successful raw
# stdout, differing in exactly this one line.
REAL_LINE_A = "====== 619 passed, 15 skipped, 1 xfailed, 18 warnings in 78.47s (0:01:18) ======"
REAL_LINE_B = "====== 619 passed, 15 skipped, 1 xfailed, 18 warnings in 78.71s (0:01:18) ======"

REAL_DEPRECATION_LINES = [
    "  /home/runner/work/_temp/source-artifact/repo-requests/source/src/requests/auth.py:45: "
    "DeprecationWarning: Non-string usernames will no longer be supported in Requests 3.0.0. "
    "Please convert the object you've passed in (42) to a string or bytes object in the near "
    "future to avoid problems.",
]
REAL_OTHER_SEPARATOR_LINES = [
    "============================= test session starts ==============================",
    "=============================== warnings summary ===============================",
]

POSITIVE_SUMMARY_LINES = [
    REAL_LINE_A,
    REAL_LINE_B,
    "====== 619 passed, 15 skipped, 1 xfailed, 18 warnings in <DURATION> ======",  # already canonical
    "= 1 passed in 0.12s =",  # under-60s branch, no parenthetical
    "= 1 passed in 45.00s =",  # under-60s branch, boundary-adjacent
    "===== 12 passed, 3 skipped in 61.00s (0:01:01) =====",  # >=60s branch
    "===== 1 passed in 3661.99s (1:01:01) =====",  # multi-digit hours
]

NEGATIVE_SUMMARY_LINES = [
    "====== 619 passed in 78.4s ======",  # 1 decimal, not 2
    "====== 619 passed in 78.470s ======",  # 3 decimals
    "====== 619 passed in 78.47 ======",  # missing trailing 's'
    "====== 619 passed in 78.47s (1:1:18) ======",  # minutes not zero-padded
    "====== 619 passed in 78.47s (0:01:1) ======",  # seconds not zero-padded
    "====== 619 passed in -78.47s ======",  # negative
]


class TestGrammarPositive(unittest.TestCase):
    def test_every_valid_summary_line_canonicalizes_duration_only(self):
        for line in POSITIVE_SUMMARY_LINES:
            with self.subTest(line=line):
                out, report = prdc.canonicalize_stream(_lines(line))
                out_text = out.decode()
                self.assertIn("<DURATION>", out_text)
                self.assertEqual(report["rule_match_counts"][prdc.RULE_NAME], 1)

    def test_real_evidence_pair_canonicalizes_to_byte_identical_output(self):
        out_a, _ = prdc.canonicalize_stream(_lines(REAL_LINE_A))
        out_b, _ = prdc.canonicalize_stream(_lines(REAL_LINE_B))
        self.assertEqual(out_a, out_b)

    def test_counts_and_padding_are_preserved(self):
        out, _ = prdc.canonicalize_stream(_lines(REAL_LINE_A))
        text = out.decode()
        self.assertIn("619 passed, 15 skipped, 1 xfailed, 18 warnings", text)
        self.assertTrue(text.rstrip("\n").startswith("======"))
        self.assertTrue(text.rstrip("\n").endswith("======"))

    def test_already_canonical_input_is_idempotent(self):
        out1, _ = prdc.canonicalize_stream(_lines(REAL_LINE_A))
        out2, report2 = prdc.canonicalize_stream(out1)
        self.assertEqual(out1, out2)
        self.assertEqual(report2["replacement_count"], 0)

    def test_replacement_records_line_number_and_hashes(self):
        _, report = prdc.canonicalize_stream(_lines(REAL_LINE_A))
        self.assertEqual(len(report["replacements"]), 1)
        rep = report["replacements"][0]
        self.assertEqual(rep["rule_name"], prdc.RULE_NAME)
        self.assertEqual(rep["line_number"], 1)
        self.assertEqual(rep["before_line_sha256"], hashlib.sha256(REAL_LINE_A.encode()).hexdigest())


class TestGrammarNegativeFailsClosed(unittest.TestCase):
    def test_malformed_duration_grammar_raises(self):
        for line in NEGATIVE_SUMMARY_LINES:
            with self.subTest(line=line):
                with self.assertRaises(prdc.CanonicalizerError):
                    prdc.canonicalize_stream(_lines(line))


class TestStructuralExclusionOfUnrelatedLines(unittest.TestCase):
    """Real evidence: a bare ' in ' substring also appears inside
    repo-requests' own DeprecationWarning text, and pytest emits two OTHER
    '='-decorated separator lines with no duration at all -- none of these
    may be flagged as malformed."""

    def test_deprecation_warning_lines_are_untouched_and_do_not_raise(self):
        for line in REAL_DEPRECATION_LINES:
            with self.subTest(line=line):
                out, report = prdc.canonicalize_stream(_lines(line))
                self.assertEqual(out, _lines(line))
                self.assertEqual(report["replacement_count"], 0)

    def test_other_separator_lines_are_untouched_and_do_not_raise(self):
        for line in REAL_OTHER_SEPARATOR_LINES:
            with self.subTest(line=line):
                out, report = prdc.canonicalize_stream(_lines(line))
                self.assertEqual(out, _lines(line))
                self.assertEqual(report["replacement_count"], 0)

    def test_full_real_capture_shape_canonicalizes_only_the_summary_line(self):
        full = REAL_OTHER_SEPARATOR_LINES[:1] + REAL_DEPRECATION_LINES + REAL_OTHER_SEPARATOR_LINES[1:] + [REAL_LINE_A]
        out, report = prdc.canonicalize_stream(_lines(*full))
        self.assertEqual(report["replacement_count"], 1)
        self.assertEqual(report["rule_match_counts"][prdc.RULE_NAME], 1)


class TestStructuralPreservation(unittest.TestCase):
    def test_line_count_preserved(self):
        _, report = prdc.canonicalize_stream(_lines(REAL_LINE_A))
        self.assertEqual(report["line_count_in"], report["line_count_out"])

    def test_trailing_newline_preserved_when_present(self):
        out, report = prdc.canonicalize_stream(_lines(REAL_LINE_A))
        self.assertTrue(report["trailing_newline_preserved"])
        self.assertTrue(out.endswith(b"\n"))

    def test_trailing_newline_preserved_when_absent(self):
        raw = REAL_LINE_A.encode("utf-8")
        out, report = prdc.canonicalize_stream(raw)
        self.assertTrue(report["trailing_newline_preserved"])
        self.assertFalse(out.endswith(b"\n"))

    def test_invalid_utf8_raises(self):
        with self.assertRaises(prdc.CanonicalizerError):
            prdc.canonicalize_stream(b"\xff\xfe not utf-8")


class TestPolicyRecordIsCommittedAndSelfConsistent(unittest.TestCase):
    def test_policy_file_exists(self):
        self.assertTrue(POLICY_PATH.is_file())

    def test_policy_loads_and_verifies(self):
        body = prdc.load_and_verify_policy(POLICY_PATH)
        self.assertEqual(body["applicable_case_ids"], ["repo-requests"])

    def test_policy_identity_is_distinct_from_rejected_v1(self):
        body = json.loads(POLICY_PATH.read_text())
        self.assertNotEqual(
            body["approving_decision_identity"],
            "n2d1b-repo-requests-loopback-only-authorization-2026-07-17",
        )
        self.assertIn("duration", body["approving_decision_identity"])

    def test_tampered_self_hash_fails_closed(self):
        body = json.loads(POLICY_PATH.read_text())
        body["policy_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "tampered.json"
            tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(prdc.PolicyIntegrityError):
                prdc.load_and_verify_policy(tampered)

    def test_tampered_applicable_case_ids_fails_closed(self):
        body = json.loads(POLICY_PATH.read_text())
        body["applicable_case_ids"] = []
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        body["policy_sha256"] = hashlib.sha256(
            (json.dumps(without_hash, indent=2, sort_keys=True) + "\n").encode()
        ).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "tampered.json"
            tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(prdc.PolicyIntegrityError):
                prdc.load_and_verify_policy(tampered)

    def test_tampered_rule_regex_fails_closed(self):
        body = json.loads(POLICY_PATH.read_text())
        body["rules"][0]["anchored_regex"] = "^doesnotmatchthecode$"
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        body["policy_sha256"] = hashlib.sha256(
            (json.dumps(without_hash, indent=2, sort_keys=True) + "\n").encode()
        ).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "tampered.json"
            tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(prdc.PolicyIntegrityError):
                prdc.load_and_verify_policy(tampered)


if __name__ == "__main__":
    unittest.main()
