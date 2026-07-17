"""Unit tests for cargo_test_canonicalizer.py -- the exact closed-grammar
libtest summary-line-duration canonicalizer shared by repo-rustlings and
repo-dockerfile-parser-rs (N2-D1b Stage 2), independently derived from
Rust's own libtest source (tag v1.97.0, commit
2d8144b7880597b6e6d3dfd63a9a9efae3f533d3 -- see
cargo-test-capture-canonicalization-policy.json's libtest_source_derivation).

This module and its tests are entirely independent of maven_canonicalizer.py,
vstest_canonicalizer.py, gradle_canonicalizer.py (v1), gradle_canonicalizer_v2.py,
and gradle_canonicalizer_helm_values_v1.py -- none is imported, modified, or
broadened here.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import cargo_test_canonicalizer as ctc  # noqa: E402


def _line(text: str) -> bytes:
    return (text + "\n").encode("utf-8")


POSITIVE_SUMMARY_LINES = [
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s",
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.80s",
    "test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
    "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 123.45s",
    "test result: FAILED. 5 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.18s",
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in <ELAPSED>",
]

NEGATIVE_SUMMARY_LINES = [
    "",
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",  # missing duration entirely
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.8s",  # 1 decimal
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.800s",  # 3 decimals
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in .80s",  # no leading digit
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.80",  # missing 's'
    "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in -0.80s",  # negative
    "test result: unknown. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.80s",
    "test result: ok. 6 passed; 0 failed; 0 ignored; finished in 0.80s",  # missing counts
]


class TestGrammarPositive(unittest.TestCase):
    def test_every_valid_summary_line_canonicalizes_duration_only(self):
        for line in POSITIVE_SUMMARY_LINES:
            with self.subTest(line=line):
                out, report = ctc.canonicalize_stream(_line(line))
                out_text = out.decode()
                self.assertTrue(out_text.rstrip("\n").endswith("finished in <ELAPSED>"))
                self.assertEqual(report["rule_match_counts"]["cargo_test_summary_duration"], 1)

    def test_counts_and_outcome_word_are_preserved(self):
        out, _ = ctc.canonicalize_stream(_line(
            "test result: FAILED. 5 passed; 3 failed; 2 ignored; 1 measured; 4 filtered out; finished in 0.18s"
        ))
        self.assertIn(b"FAILED. 5 passed; 3 failed; 2 ignored; 1 measured; 4 filtered out", out)


class TestGrammarNegative(unittest.TestCase):
    def test_every_invalid_summary_line_raises(self):
        for line in NEGATIVE_SUMMARY_LINES:
            if not line:
                continue
            with self.subTest(line=line):
                with self.assertRaises(ctc.CanonicalizerError):
                    ctc.canonicalize_stream(_line(line))

    def test_missing_duration_raises(self):
        with self.assertRaises(ctc.CanonicalizerError):
            ctc.canonicalize_stream(_line(
                "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
            ))

    def test_three_decimal_places_raises(self):
        # TestExecTime (per-test, {:.3}s) is a DIFFERENT libtest type from
        # TestSuiteExecTime (the suite summary, {:.2}s) -- 3 decimals here
        # would be a real format change or a wrong-type line, never silently
        # accepted.
        with self.assertRaises(ctc.CanonicalizerError):
            ctc.canonicalize_stream(_line(
                "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.800s"
            ))

    def test_negative_duration_raises(self):
        with self.assertRaises(ctc.CanonicalizerError):
            ctc.canonicalize_stream(_line(
                "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in -0.80s"
            ))

    def test_prefix_text_before_trigger_raises(self):
        with self.assertRaises(ctc.CanonicalizerError):
            ctc.canonicalize_stream(_line(
                "prefix test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.80s"
            ))

    def test_suffix_text_after_duration_raises(self):
        with self.assertRaises(ctc.CanonicalizerError):
            ctc.canonicalize_stream(_line(
                "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.80s suffix"
            ))


class TestRealObservedCapturePairsCanonicalizeIdentically(unittest.TestCase):
    """The exact two real capture-a/capture-b pairs observed in CI (Stage 2,
    second full run) after RUST_TEST_THREADS=1 made ordering deterministic --
    the summary line's duration was the sole remaining raw difference."""

    def test_dockerfile_parser_rs_pair(self):
        a, _ = ctc.canonicalize_stream(_line(
            "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s"
        ))
        b, _ = ctc.canonicalize_stream(_line(
            "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.80s"
        ))
        self.assertEqual(a, b)

    def test_rustlings_pair(self):
        a, _ = ctc.canonicalize_stream(_line(
            "test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.74s"
        ))
        b, _ = ctc.canonicalize_stream(_line(
            "test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.89s"
        ))
        self.assertEqual(a, b)

    def test_a_genuinely_different_outcome_never_canonicalizes_identically(self):
        # A real difference in pass/fail counts must NEVER be masked -- this
        # is the exact discipline that distinguishes rustlings' own genuine
        # 3-test failure (fixed by a real write-permission grant, not by
        # canonicalization) from timing noise.
        a, _ = ctc.canonicalize_stream(_line(
            "test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.74s"
        ))
        b, _ = ctc.canonicalize_stream(_line(
            "test result: FAILED. 5 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.18s"
        ))
        self.assertNotEqual(a, b)


class TestStructuralPreservation(unittest.TestCase):
    def _real_shaped_stream(self, *, duration="0.85s", newline=b"\n") -> bytes:
        lines = [
            "running 6 tests",
            "test image::tests::test_image_parse_registry ... ok",
            "",
            f"test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in {duration}",
            "",
        ]
        return newline.join(line.encode("utf-8") for line in lines) + newline

    def test_line_count_preserved(self):
        raw = self._real_shaped_stream()
        out, report = ctc.canonicalize_stream(raw)
        self.assertEqual(len(raw.splitlines()), len(out.splitlines()))
        self.assertEqual(report["line_count_in"], report["line_count_out"])

    def test_trailing_newline_preserved_when_present(self):
        raw = self._real_shaped_stream()
        out, report = ctc.canonicalize_stream(raw)
        self.assertTrue(out.endswith(b"\n"))
        self.assertTrue(report["trailing_newline_preserved"])

    def test_trailing_newline_preserved_when_absent(self):
        raw = self._real_shaped_stream().rstrip(b"\n")
        out, report = ctc.canonicalize_stream(raw)
        self.assertFalse(out.endswith(b"\n"))
        self.assertTrue(report["trailing_newline_preserved"])

    def test_crlf_preserved(self):
        raw = self._real_shaped_stream(newline=b"\r\n")
        out, _ = ctc.canonicalize_stream(raw)
        self.assertEqual(out.count(b"\r\n"), raw.count(b"\r\n"))
        for line in out.split(b"\r\n")[:-1]:
            self.assertNotIn(b"\n", line)

    def test_untouched_lines_are_byte_identical(self):
        raw = self._real_shaped_stream()
        out, _ = ctc.canonicalize_stream(raw)
        raw_lines = raw.decode().splitlines()
        out_lines = out.decode().splitlines()
        for i, line in enumerate(raw_lines):
            if "test result:" not in line:
                self.assertEqual(raw_lines[i], out_lines[i])

    def test_no_line_removed_including_blank_lines(self):
        raw = self._real_shaped_stream()
        out, _ = ctc.canonicalize_stream(raw)
        self.assertIn("", out.decode().splitlines())


class TestIdempotence(unittest.TestCase):
    def test_applying_twice_changes_zero_bytes(self):
        raw = _line(
            "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s"
        )
        once, _ = ctc.canonicalize_stream(raw)
        twice, report_twice = ctc.canonicalize_stream(once)
        self.assertEqual(once, twice)
        self.assertEqual(report_twice["replacement_count"], 0)


class TestStrictUtf8(unittest.TestCase):
    def test_invalid_utf8_raises(self):
        raw = b"\xff\xfe not valid utf-8 \x00\x01"
        with self.assertRaises(ctc.CanonicalizerError):
            ctc.canonicalize_stream(raw)


class TestReplacementRecordShape(unittest.TestCase):
    def test_replacement_records_rule_name_line_number_and_hashes(self):
        raw = _line(
            "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s"
        )
        out, report = ctc.canonicalize_stream(raw)
        self.assertEqual(len(report["replacements"]), 1)
        entry = report["replacements"][0]
        self.assertEqual(entry["rule_name"], "cargo_test_summary_duration")
        self.assertEqual(entry["line_number"], 1)
        before_line = raw.decode().splitlines()[0]
        after_line = out.decode().splitlines()[0]
        self.assertEqual(entry["before_line_sha256"], hashlib.sha256(before_line.encode()).hexdigest())
        self.assertEqual(entry["after_line_sha256"], hashlib.sha256(after_line.encode()).hexdigest())

    def test_report_records_type_and_version(self):
        out, report = ctc.canonicalize_stream(_line(
            "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s"
        ))
        self.assertEqual(report["report_type"], "n2d1b-cargo-test-canonicalization-report-v1")
        self.assertEqual(report["canonicalizer_version"], 1)


class TestPolicyIntegrity(unittest.TestCase):
    POLICY_PATH = TOOLS.parent / "cargo-test-capture-canonicalization-policy.json"

    def test_policy_file_verifies_against_code(self):
        policy = ctc.load_and_verify_policy(self.POLICY_PATH)
        self.assertEqual(set(policy["applicable_case_ids"]), {"repo-rustlings", "repo-dockerfile-parser-rs"})
        self.assertEqual(policy["canonicalizer_module"], "cargo_test_canonicalizer.py")
        self.assertEqual(policy["policy_type"], "n2d1b-cargo-test-capture-canonicalization-policy-v1")
        self.assertEqual(policy["policy_version"], 1)

    def test_policy_records_libtest_source_derivation(self):
        policy = ctc.load_and_verify_policy(self.POLICY_PATH)
        derivation = policy["libtest_source_derivation"]
        self.assertEqual(derivation["repository_url"], "https://github.com/rust-lang/rust")
        self.assertEqual(derivation["tag"], "1.97.0")
        self.assertTrue(derivation["commit_sha"])

    def test_tampered_policy_hash_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_sha256"] = "0" * 64
        tampered = self.POLICY_PATH.parent / "tests" / "_tmp_tampered_ctc_policy.json"
        tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(ctc.PolicyIntegrityError):
                ctc.load_and_verify_policy(tampered)
        finally:
            tampered.unlink()

    def test_policy_code_regex_drift_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["rules"][0]["anchored_regex"] = "^test result: (.*)$"
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        drifted = self.POLICY_PATH.parent / "tests" / "_tmp_drifted_ctc_policy.json"
        drifted.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(ctc.PolicyIntegrityError):
                ctc.load_and_verify_policy(drifted)
        finally:
            drifted.unlink()

    def test_wrong_policy_type_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_type"] = "n2d1b-gradle-capture-canonicalization-policy-v2"
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_type = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_type_ctc_policy.json"
        wrong_type.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(ctc.PolicyIntegrityError):
                ctc.load_and_verify_policy(wrong_type)
        finally:
            wrong_type.unlink()

    def test_wrong_policy_version_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_version"] = 2
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_version = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_version_ctc_policy.json"
        wrong_version.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(ctc.PolicyIntegrityError):
                ctc.load_and_verify_policy(wrong_version)
        finally:
            wrong_version.unlink()

    def test_empty_applicable_case_ids_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["applicable_case_ids"] = []
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        empty_cases = self.POLICY_PATH.parent / "tests" / "_tmp_empty_cases_ctc_policy.json"
        empty_cases.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(ctc.PolicyIntegrityError):
                ctc.load_and_verify_policy(empty_cases)
        finally:
            empty_cases.unlink()

    def test_applying_to_a_case_other_than_the_two_authorized_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["applicable_case_ids"] = ["repo-moshi"]
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_case = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_case_ctc_policy.json"
        wrong_case.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(ctc.PolicyIntegrityError):
                ctc.load_and_verify_policy(wrong_case)
        finally:
            wrong_case.unlink()

    def test_only_one_of_the_two_authorized_cases_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["applicable_case_ids"] = ["repo-rustlings"]
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        partial_cases = self.POLICY_PATH.parent / "tests" / "_tmp_partial_cases_ctc_policy.json"
        partial_cases.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(ctc.PolicyIntegrityError):
                ctc.load_and_verify_policy(partial_cases)
        finally:
            partial_cases.unlink()


if __name__ == "__main__":
    unittest.main()
