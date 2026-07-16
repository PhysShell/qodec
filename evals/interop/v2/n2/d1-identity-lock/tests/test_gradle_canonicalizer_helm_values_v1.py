"""Unit tests for gradle_canonicalizer_helm_values_v1.py -- the exact
closed-grammar Gradle build-duration canonicalizer authorized for
repo-helm-values (N2-D1b Stage 2's deterministically selected jvm-gradle
repository-miner replacement for repo-spotless), independently derived from
Gradle 9.5.0's own TimeFormatting.formatDurationTerse source (confirmed
byte-for-byte identical to repo-moshi's authorized v9.5.1 -- see
gradle-capture-canonicalization-policy-helm-values-v1.json's
gradle_source_derivation).

This module and its tests are entirely independent of gradle_canonicalizer.py
(v1) and gradle_canonicalizer_v2.py (repo-moshi) -- neither is imported,
modified, or broadened here.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import gradle_canonicalizer_helm_values_v1 as gchv  # noqa: E402


def _line(text: str) -> bytes:
    return (text + "\n").encode("utf-8")


POSITIVE_DURATIONS = [
    "0ms", "1ms", "999ms",
    "1s", "59s",
    "1m", "59m",
    "1m 1s", "59m 59s",
    "1h", "12h",
    "1h 1s", "1h 59s",
    "1h 1m", "1h 59m",
    "1h 1m 1s", "12h 59m 59s",
    "<ELAPSED>",
]

NEGATIVE_DURATIONS = [
    "",
    "00ms", "01ms", "1000ms", "-1ms",
    "0s", "01s", "60s",
    "0m", "01m", "60m",
    "1m 0s", "1m 60s",
    "1h 0m", "1h 0s", "1h 60m",
    "1h 1m 0s", "1h 1m 60s",
    "1.5s", "1sec", "1MS", "1M", "1H",
    "1m  1s",
    "1m\t1s",
]


class TestGrammarPositive(unittest.TestCase):
    def test_every_valid_duration_canonicalizes_to_elapsed_placeholder(self):
        for duration in POSITIVE_DURATIONS:
            with self.subTest(duration=duration):
                out, report = gchv.canonicalize_stream(_line(f"BUILD SUCCESSFUL in {duration}"))
                self.assertEqual(out, _line("BUILD SUCCESSFUL in <ELAPSED>"))
                self.assertEqual(report["rule_match_counts"]["gradle_build_duration_helm_values_v1"], 1)


class TestGrammarNegative(unittest.TestCase):
    def test_every_invalid_duration_raises(self):
        for duration in NEGATIVE_DURATIONS:
            with self.subTest(duration=duration):
                raw = _line(f"BUILD SUCCESSFUL in {duration}") if duration else _line("BUILD SUCCESSFUL in")
                with self.assertRaises(gchv.CanonicalizerError):
                    gchv.canonicalize_stream(raw)

    def test_leading_space_before_trigger_raises(self):
        with self.assertRaises(gchv.CanonicalizerError):
            gchv.canonicalize_stream(_line(" BUILD SUCCESSFUL in 1s"))

    def test_trailing_space_after_duration_raises(self):
        with self.assertRaises(gchv.CanonicalizerError):
            gchv.canonicalize_stream(b"BUILD SUCCESSFUL in 1s \n")

    def test_prefix_text_before_trigger_raises(self):
        with self.assertRaises(gchv.CanonicalizerError):
            gchv.canonicalize_stream(_line("prefix BUILD SUCCESSFUL in 1s"))

    def test_suffix_text_after_duration_raises(self):
        with self.assertRaises(gchv.CanonicalizerError):
            gchv.canonicalize_stream(_line("BUILD SUCCESSFUL in 1s suffix"))

    def test_build_failed_is_not_matched_or_touched(self):
        raw = _line("BUILD FAILED in 1s")
        out, report = gchv.canonicalize_stream(raw)
        self.assertEqual(raw, out)
        self.assertEqual(report["replacement_count"], 0)


class TestHoursSecondsWithoutMinutesIsARealProduction(unittest.TestCase):
    def test_hours_and_seconds_without_minutes_is_a_real_production(self):
        out, report = gchv.canonicalize_stream(_line("BUILD SUCCESSFUL in 1h 59s"))
        self.assertEqual(out, _line("BUILD SUCCESSFUL in <ELAPSED>"))
        self.assertEqual(report["rule_match_counts"]["gradle_build_duration_helm_values_v1"], 1)


class TestStructuralPreservation(unittest.TestCase):
    def _real_shaped_stream(self, *, duration="2m", newline=b"\n") -> bytes:
        lines = [
            "> Task :helm-values-shared:compileKotlin",
            "> Task :helm-values-shared:test",
            "",
            f"BUILD SUCCESSFUL in {duration}",
            "12 actionable tasks: 12 executed",
        ]
        return newline.join(line.encode("utf-8") for line in lines) + newline

    def test_line_count_preserved(self):
        raw = self._real_shaped_stream()
        out, report = gchv.canonicalize_stream(raw)
        self.assertEqual(len(raw.splitlines()), len(out.splitlines()))
        self.assertEqual(report["line_count_in"], report["line_count_out"])

    def test_trailing_newline_preserved_when_present(self):
        raw = self._real_shaped_stream()
        out, report = gchv.canonicalize_stream(raw)
        self.assertTrue(out.endswith(b"\n"))
        self.assertTrue(report["trailing_newline_preserved"])

    def test_trailing_newline_preserved_when_absent(self):
        raw = self._real_shaped_stream().rstrip(b"\n")
        out, report = gchv.canonicalize_stream(raw)
        self.assertFalse(out.endswith(b"\n"))
        self.assertTrue(report["trailing_newline_preserved"])

    def test_crlf_preserved(self):
        raw = self._real_shaped_stream(newline=b"\r\n")
        out, _ = gchv.canonicalize_stream(raw)
        self.assertEqual(out.count(b"\r\n"), raw.count(b"\r\n"))
        for line in out.split(b"\r\n")[:-1]:
            self.assertNotIn(b"\n", line)

    def test_untouched_lines_are_byte_identical(self):
        raw = self._real_shaped_stream()
        out, _ = gchv.canonicalize_stream(raw)
        raw_lines = raw.decode().splitlines()
        out_lines = out.decode().splitlines()
        for i, line in enumerate(raw_lines):
            if "BUILD SUCCESSFUL" not in line:
                self.assertEqual(raw_lines[i], out_lines[i])

    def test_no_line_removed_including_blank_lines(self):
        raw = self._real_shaped_stream()
        out, _ = gchv.canonicalize_stream(raw)
        self.assertIn("", out.decode().splitlines())


class TestIdempotence(unittest.TestCase):
    def test_applying_twice_changes_zero_bytes(self):
        raw = _line("BUILD SUCCESSFUL in 2m")
        once, _ = gchv.canonicalize_stream(raw)
        twice, report_twice = gchv.canonicalize_stream(once)
        self.assertEqual(once, twice)
        self.assertEqual(report_twice["replacement_count"], 0)

    def test_already_canonical_stream_produces_identical_bytes_and_zero_replacements(self):
        raw = (
            b"> Task :helm-values-shared:test\n"
            b"BUILD SUCCESSFUL in <ELAPSED>\n"
            b"12 actionable tasks: 12 executed\n"
        )
        out, report = gchv.canonicalize_stream(raw)
        self.assertEqual(out, raw)
        self.assertEqual(report["replacement_count"], 0)


class TestStrictUtf8(unittest.TestCase):
    def test_invalid_utf8_raises(self):
        raw = b"\xff\xfe not valid utf-8 \x00\x01"
        with self.assertRaises(gchv.CanonicalizerError):
            gchv.canonicalize_stream(raw)


class TestReplacementRecordShape(unittest.TestCase):
    def test_replacement_records_rule_name_line_number_and_hashes(self):
        raw = _line("BUILD SUCCESSFUL in 2m")
        out, report = gchv.canonicalize_stream(raw)
        self.assertEqual(len(report["replacements"]), 1)
        entry = report["replacements"][0]
        self.assertEqual(entry["rule_name"], "gradle_build_duration_helm_values_v1")
        self.assertEqual(entry["line_number"], 1)
        before_line = raw.decode().splitlines()[0]
        after_line = out.decode().splitlines()[0]
        self.assertEqual(entry["before_line_sha256"], hashlib.sha256(before_line.encode()).hexdigest())
        self.assertEqual(entry["after_line_sha256"], hashlib.sha256(after_line.encode()).hexdigest())

    def test_report_records_type_and_version(self):
        out, report = gchv.canonicalize_stream(_line("BUILD SUCCESSFUL in 2m"))
        self.assertEqual(report["report_type"], "n2d1b-gradle-canonicalization-report-helm-values-v1")
        self.assertEqual(report["canonicalizer_version"], 1)


class TestPolicyIntegrity(unittest.TestCase):
    POLICY_PATH = TOOLS.parent / "gradle-capture-canonicalization-policy-helm-values-v1.json"

    def test_policy_file_verifies_against_code(self):
        policy = gchv.load_and_verify_policy(self.POLICY_PATH)
        self.assertEqual(policy["applicable_case_ids"], ["repo-helm-values"])
        self.assertEqual(policy["canonicalizer_module"], "gradle_canonicalizer_helm_values_v1.py")
        self.assertEqual(policy["policy_type"], "n2d1b-gradle-capture-canonicalization-policy-helm-values-v1")
        self.assertEqual(policy["policy_version"], 1)

    def test_policy_records_gradle_source_derivation(self):
        policy = gchv.load_and_verify_policy(self.POLICY_PATH)
        derivation = policy["gradle_source_derivation"]
        self.assertEqual(derivation["repository_url"], "https://github.com/gradle/gradle")
        self.assertEqual(derivation["tag"], "v9.5.0")
        self.assertTrue(derivation["commit_sha"])
        self.assertIn("TimeFormatting.java", derivation["formatter_file"])
        self.assertIn("formatDurationTerse", derivation["formatter_method"])

    def test_tampered_policy_hash_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_sha256"] = "0" * 64
        tampered = self.POLICY_PATH.parent / "tests" / "_tmp_tampered_hv_policy.json"
        tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(gchv.PolicyIntegrityError):
                gchv.load_and_verify_policy(tampered)
        finally:
            tampered.unlink()

    def test_policy_code_regex_drift_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["rules"][0]["anchored_regex"] = "^BUILD SUCCESSFUL in (.*)$"
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        drifted = self.POLICY_PATH.parent / "tests" / "_tmp_drifted_hv_policy.json"
        drifted.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(gchv.PolicyIntegrityError):
                gchv.load_and_verify_policy(drifted)
        finally:
            drifted.unlink()

    def test_wrong_policy_type_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_type"] = "n2d1b-gradle-capture-canonicalization-policy-v2"
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_type = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_type_hv_policy.json"
        wrong_type.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(gchv.PolicyIntegrityError):
                gchv.load_and_verify_policy(wrong_type)
        finally:
            wrong_type.unlink()

    def test_wrong_policy_version_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_version"] = 2
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_version = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_version_hv_policy.json"
        wrong_version.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(gchv.PolicyIntegrityError):
                gchv.load_and_verify_policy(wrong_version)
        finally:
            wrong_version.unlink()

    def test_empty_applicable_case_ids_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["applicable_case_ids"] = []
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        empty_cases = self.POLICY_PATH.parent / "tests" / "_tmp_empty_cases_hv_policy.json"
        empty_cases.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(gchv.PolicyIntegrityError):
                gchv.load_and_verify_policy(empty_cases)
        finally:
            empty_cases.unlink()

    def test_applying_to_a_case_other_than_repo_helm_values_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["applicable_case_ids"] = ["repo-moshi"]
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_case = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_case_hv_policy.json"
        wrong_case.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(gchv.PolicyIntegrityError):
                gchv.load_and_verify_policy(wrong_case)
        finally:
            wrong_case.unlink()


if __name__ == "__main__":
    unittest.main()
