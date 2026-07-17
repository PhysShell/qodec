"""Unit tests for pytest_requests_canonicalizer.py -- the three exact
closed-grammar rules (object-repr address, pytest session-summary duration,
threading.Thread-repr native ident) used solely for repo-requests (N2-D1b
Stage 2), independently derived from CPython's object.__repr__ convention,
pytest's own source (tag v9.1.1, commit
cf470ec0bf7eb89cd97dd56df4859eae5db46447), and threading.Thread's own repr
format -- see
pytest-requests-capture-canonicalization-policy.json's
cpython_source_derivation / pytest_source_derivation /
threading_source_derivation.

This module and its tests are entirely independent of maven_canonicalizer.py,
vstest_canonicalizer.py, gradle_canonicalizer.py (v1), gradle_canonicalizer_v2.py,
gradle_canonicalizer_helm_values_v1.py, and cargo_test_canonicalizer.py --
none is imported, modified, or broadened here (only the shared
_sha256/_split_line_ending plumbing is reused, via maven_canonicalizer).
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import pytest_requests_canonicalizer as prc  # noqa: E402


def _line(text: str) -> bytes:
    return (text + "\n").encode("utf-8")


# --- Rule 1: object-repr address --------------------------------------------

POSITIVE_ADDRESS_LINES = [
    "self = <urllib3.connectionpool.HTTPConnectionPool object at 0x7f1a2b3c4d5e>",
    "conn = <requests.adapters.HTTPAdapter object at 0x7f0000000001>",
    "it = <list_iterator object at 0x7fabc0000000>",
    "self = <urllib3.connection.HTTPConnection(host='localhost', port=80) at 0x7f1a2b3c4d5e>",
    "x = <tests.test_requests.TestRequests object at 0xdeadbeef00>",
]



class TestObjectReprAddressRulePositive(unittest.TestCase):
    def test_every_valid_address_line_canonicalizes(self):
        for line in POSITIVE_ADDRESS_LINES:
            with self.subTest(line=line):
                out, report = prc.canonicalize_stream(_line(line))
                out_text = out.decode()
                self.assertIn("at 0xADDR>", out_text)
                self.assertNotIn("0x7f", out_text)
                self.assertGreaterEqual(report["rule_match_counts"]["python_object_repr_address"], 1)

    def test_prefix_before_bracket_is_preserved(self):
        out, _ = prc.canonicalize_stream(_line(
            "self = <urllib3.connectionpool.HTTPConnectionPool object at 0x7f1a2b3c4d5e>"
        ))
        self.assertIn(b"self = <urllib3.connectionpool.HTTPConnectionPool object at 0xADDR>", out)

    def test_multiple_addresses_on_one_line_all_canonicalize(self):
        raw = _line(
            "a=<A object at 0x7f0000000001>, b=<B object at 0x7f0000000002>"
        )
        out, report = prc.canonicalize_stream(raw)
        self.assertEqual(out.decode().count("0xADDR"), 2)
        self.assertEqual(report["rule_match_counts"]["python_object_repr_address"], 2)


class TestObjectReprAddressRuleNegative(unittest.TestCase):
    def test_uppercase_hex_digits_raise(self):
        with self.assertRaises(prc.CanonicalizerError):
            prc.canonicalize_stream(_line(
                "self = <urllib3.connectionpool.HTTPConnectionPool object at 0x7F1A2B3C4D5E>"
            ))

    def test_no_hex_digits_raise(self):
        with self.assertRaises(prc.CanonicalizerError):
            prc.canonicalize_stream(_line("self = <Foo object at 0x>"))

    def test_missing_closing_bracket_raises(self):
        with self.assertRaises(prc.CanonicalizerError):
            prc.canonicalize_stream(_line("self = <Foo object at 0x7f1a2b3c4d5e"))


# --- Rule 2: pytest session-summary duration --------------------------------

POSITIVE_DURATION_LINES = [
    "=========== 30 failed, 384 passed, 15 skipped in 14.49s =============",
    "=========== 30 failed, 384 passed, 15 skipped in 0.00s =============",
    "=========== 1 passed in 123.45s =============",
]

NEGATIVE_DURATION_LINES = [
    "=========== 30 failed, 384 passed, 15 skipped in 14.4s =============",  # 1 decimal
    "=========== 30 failed, 384 passed, 15 skipped in 14.490s =============",  # 3 decimals
]


class TestSessionSummaryDurationRulePositive(unittest.TestCase):
    def test_every_valid_duration_line_canonicalizes(self):
        for line in POSITIVE_DURATION_LINES:
            with self.subTest(line=line):
                out, report = prc.canonicalize_stream(_line(line))
                self.assertIn("in ELAPSEDs =", out.decode())
                self.assertEqual(report["rule_match_counts"]["pytest_session_summary_duration"], 1)

    def test_banner_starts_line_is_not_a_false_positive_trigger(self):
        # Regression: a plain "s =" substring trigger falsely matched inside
        # "===== test session starts =====" (the "s" of "starts" immediately
        # followed by " ="). This must NOT raise and must NOT be touched.
        raw = _line("=================== test session starts ====================")
        out, report = prc.canonicalize_stream(raw)
        self.assertEqual(out, raw)
        self.assertEqual(report["rule_match_counts"]["pytest_session_summary_duration"], 0)

    def test_counts_are_preserved(self):
        out, _ = prc.canonicalize_stream(_line(
            "=========== 30 failed, 384 passed, 15 skipped in 14.49s ============="
        ))
        self.assertIn(b"30 failed, 384 passed, 15 skipped", out)

    def test_already_canonicalized_form_is_idempotent_and_untouched(self):
        raw = _line("=========== 1 passed in ELAPSEDs =============")
        out, report = prc.canonicalize_stream(raw)
        self.assertEqual(out, raw)
        self.assertEqual(report["replacement_count"], 0)


class TestSessionSummaryDurationRuleNegative(unittest.TestCase):
    def test_every_invalid_duration_line_raises(self):
        for line in NEGATIVE_DURATION_LINES:
            with self.subTest(line=line):
                with self.assertRaises(prc.CanonicalizerError):
                    prc.canonicalize_stream(_line(line))


# --- Rule 3: threading.Thread repr's native ident ---------------------------

POSITIVE_THREAD_LINES = [
    "self = <Server(Thread-1, stopped 140547873863360)>",
    "self = <TLSServer(Thread-13, stopped 140410844776128)>",
    "self = <Server(Thread-26, stopped 1)>",
    "self = <Server(Thread-1, stopped IDENT)>",
]

NEGATIVE_THREAD_LINES = [
    "self = <Worker(Thread-1, stopped 140547873863360)>",  # wrong class name
    "self = <Server(Thread-1, stopped -140547873863360)>",  # negative ident
    "self = <Server(Thread-1, stopped )>",  # missing ident entirely (trigger present, no digits)
]


class TestThreadReprIdentRulePositive(unittest.TestCase):
    def test_every_valid_thread_line_canonicalizes(self):
        for line in POSITIVE_THREAD_LINES:
            with self.subTest(line=line):
                out, report = prc.canonicalize_stream(_line(line))
                self.assertIn("stopped IDENT)>", out.decode())
                self.assertGreaterEqual(report["rule_match_counts"]["python_thread_repr_ident"], 1)

    def test_class_name_and_thread_ordinal_are_preserved(self):
        out, _ = prc.canonicalize_stream(_line(
            "self = <TLSServer(Thread-13, stopped 140410844776128)>"
        ))
        self.assertIn(b"<TLSServer(Thread-13, stopped IDENT)>", out)

    def test_server_and_tlsserver_both_recognized(self):
        out_a, _ = prc.canonicalize_stream(_line("self = <Server(Thread-1, stopped 1)>"))
        out_b, _ = prc.canonicalize_stream(_line("self = <TLSServer(Thread-1, stopped 1)>"))
        self.assertIn(b"<Server(Thread-1, stopped IDENT)>", out_a)
        self.assertIn(b"<TLSServer(Thread-1, stopped IDENT)>", out_b)


class TestThreadReprIdentRuleNegative(unittest.TestCase):
    def test_every_invalid_thread_line_raises(self):
        for line in NEGATIVE_THREAD_LINES:
            with self.subTest(line=line):
                with self.assertRaises(prc.CanonicalizerError):
                    prc.canonicalize_stream(_line(line))

    def test_wrong_class_name_raises(self):
        with self.assertRaises(prc.CanonicalizerError):
            prc.canonicalize_stream(_line("self = <Worker(Thread-1, stopped 140547873863360)>"))

    def test_missing_ident_raises(self):
        with self.assertRaises(prc.CanonicalizerError):
            prc.canonicalize_stream(_line("self = <Server(Thread-1, stopped )>"))

    def test_a_status_word_never_seen_in_real_evidence_is_not_this_rules_concern(self):
        # This rule's trigger is the literal ", stopped " substring observed
        # in the real Stage 2 capture pair -- a hypothetical different status
        # word (never actually observed) simply does not trigger this rule at
        # all (same discipline as an unrecognized prefix for Rule 1); it is
        # not silently mis-canonicalized, it is left untouched.
        raw = _line("self = <Server(Thread-1, started 140547873863360)>")
        out, report = prc.canonicalize_stream(raw)
        self.assertEqual(out, raw)
        self.assertEqual(report["rule_match_counts"]["python_thread_repr_ident"], 0)


class TestGenuinelyDifferentOutcomeNeverMasked(unittest.TestCase):
    def test_different_pass_fail_counts_never_canonicalize_identically(self):
        a, _ = prc.canonicalize_stream(_line(
            "=========== 30 failed, 384 passed, 15 skipped in 14.49s ============="
        ))
        b, _ = prc.canonicalize_stream(_line(
            "=========== 31 failed, 383 passed, 15 skipped in 14.67s ============="
        ))
        self.assertNotEqual(a, b)


class TestRealObservedCapturePairCanonicalizesIdentically(unittest.TestCase):
    """A reduced excerpt shaped like the real Stage 2 fourth-run repo-requests
    capture-a/capture-b pair -- differing only in object-repr address,
    session-summary duration, and thread-repr ident, never in test outcome."""

    def test_reduced_real_shaped_excerpt_pair(self):
        excerpt_a = (
            "self = <urllib3.connectionpool.HTTPConnectionPool object at 0x7f1a2b3c4d5e>\n"
            "self = <Server(Thread-1, stopped 140547873863360)>\n"
            "self = <TLSServer(Thread-13, stopped 140410844776128)>\n"
            "=========== 30 failed, 384 passed, 15 skipped, 1 xfailed, 32 warnings, "
            "205 errors in 14.49s =============\n"
        )
        excerpt_b = (
            "self = <urllib3.connectionpool.HTTPConnectionPool object at 0x7fdeadbeef00>\n"
            "self = <Server(Thread-1, stopped 140222222222222)>\n"
            "self = <TLSServer(Thread-13, stopped 140333333333333)>\n"
            "=========== 30 failed, 384 passed, 15 skipped, 1 xfailed, 32 warnings, "
            "205 errors in 14.67s =============\n"
        )
        canon_a, _ = prc.canonicalize_stream(excerpt_a.encode("utf-8"))
        canon_b, _ = prc.canonicalize_stream(excerpt_b.encode("utf-8"))
        self.assertEqual(canon_a, canon_b)


class TestStructuralPreservation(unittest.TestCase):
    def _real_shaped_stream(self, *, newline=b"\n") -> bytes:
        lines = [
            "============================= test session starts ==============================",
            "collected 635 items",
            "",
            "self = <Server(Thread-1, stopped 140547873863360)>",
            "",
            "=========== 30 failed, 384 passed, 15 skipped in 14.49s =============",
            "",
        ]
        return newline.join(line.encode("utf-8") for line in lines) + newline

    def test_line_count_preserved(self):
        raw = self._real_shaped_stream()
        out, report = prc.canonicalize_stream(raw)
        self.assertEqual(len(raw.splitlines()), len(out.splitlines()))
        self.assertEqual(report["line_count_in"], report["line_count_out"])

    def test_trailing_newline_preserved_when_present(self):
        raw = self._real_shaped_stream()
        out, report = prc.canonicalize_stream(raw)
        self.assertTrue(out.endswith(b"\n"))
        self.assertTrue(report["trailing_newline_preserved"])

    def test_trailing_newline_preserved_when_absent(self):
        raw = self._real_shaped_stream().rstrip(b"\n")
        out, report = prc.canonicalize_stream(raw)
        self.assertFalse(out.endswith(b"\n"))
        self.assertTrue(report["trailing_newline_preserved"])

    def test_crlf_preserved(self):
        raw = self._real_shaped_stream(newline=b"\r\n")
        out, _ = prc.canonicalize_stream(raw)
        self.assertEqual(out.count(b"\r\n"), raw.count(b"\r\n"))
        for line in out.split(b"\r\n")[:-1]:
            self.assertNotIn(b"\n", line)

    def test_untouched_lines_are_byte_identical(self):
        raw = self._real_shaped_stream()
        out, _ = prc.canonicalize_stream(raw)
        raw_lines = raw.decode().splitlines()
        out_lines = out.decode().splitlines()
        for i, line in enumerate(raw_lines):
            if "at 0x" not in line and "stopped " not in line and "s =" not in line:
                self.assertEqual(raw_lines[i], out_lines[i])

    def test_no_line_removed_including_blank_lines(self):
        raw = self._real_shaped_stream()
        out, _ = prc.canonicalize_stream(raw)
        self.assertIn("", out.decode().splitlines())


class TestIdempotence(unittest.TestCase):
    def test_applying_twice_changes_zero_bytes(self):
        raw = _line(
            "self = <Foo object at 0x7f1a2b3c4d5e> <Server(Thread-1, stopped 140547873863360)> "
            "=========== 1 passed in 14.49s ============="
        )
        once, _ = prc.canonicalize_stream(raw)
        twice, report_twice = prc.canonicalize_stream(once)
        self.assertEqual(once, twice)
        self.assertEqual(report_twice["replacement_count"], 0)


class TestStrictUtf8(unittest.TestCase):
    def test_invalid_utf8_raises(self):
        raw = b"\xff\xfe not valid utf-8 \x00\x01"
        with self.assertRaises(prc.CanonicalizerError):
            prc.canonicalize_stream(raw)


class TestReplacementRecordShape(unittest.TestCase):
    def test_replacement_records_rule_name_line_number_and_hashes(self):
        raw = _line("self = <Server(Thread-1, stopped 140547873863360)>")
        out, report = prc.canonicalize_stream(raw)
        self.assertEqual(len(report["replacements"]), 1)
        entry = report["replacements"][0]
        self.assertEqual(entry["rule_name"], "python_thread_repr_ident")
        self.assertEqual(entry["line_number"], 1)
        before_line = raw.decode().splitlines()[0]
        after_line = out.decode().splitlines()[0]
        self.assertEqual(entry["before_line_sha256"], hashlib.sha256(before_line.encode()).hexdigest())
        self.assertEqual(entry["after_line_sha256"], hashlib.sha256(after_line.encode()).hexdigest())

    def test_report_records_type_and_version(self):
        out, report = prc.canonicalize_stream(_line(
            "self = <Server(Thread-1, stopped 140547873863360)>"
        ))
        self.assertEqual(report["report_type"], "n2d1b-pytest-requests-canonicalization-report-v1")
        self.assertEqual(report["canonicalizer_version"], 1)


class TestPolicyIntegrity(unittest.TestCase):
    POLICY_PATH = TOOLS.parent / "pytest-requests-capture-canonicalization-policy.json"

    def test_policy_file_verifies_against_code(self):
        policy = prc.load_and_verify_policy(self.POLICY_PATH)
        self.assertEqual(policy["applicable_case_ids"], ["repo-requests"])
        self.assertEqual(policy["canonicalizer_module"], "pytest_requests_canonicalizer.py")
        self.assertEqual(policy["policy_type"], "n2d1b-pytest-requests-capture-canonicalization-policy-v1")
        self.assertEqual(policy["policy_version"], 1)

    def test_policy_records_all_three_source_derivations(self):
        policy = prc.load_and_verify_policy(self.POLICY_PATH)
        self.assertEqual(policy["pytest_source_derivation"]["tag"], "9.1.1")
        self.assertTrue(policy["cpython_source_derivation"]["source_locator"])
        self.assertTrue(policy["threading_source_derivation"]["source_locator"])

    def test_policy_documents_exactly_three_rules(self):
        policy = prc.load_and_verify_policy(self.POLICY_PATH)
        rule_names = {r["rule_name"] for r in policy["rules"]}
        self.assertEqual(
            rule_names,
            {"python_object_repr_address", "pytest_session_summary_duration", "python_thread_repr_ident"},
        )

    def test_tampered_policy_hash_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_sha256"] = "0" * 64
        tampered = self.POLICY_PATH.parent / "tests" / "_tmp_tampered_prc_policy.json"
        tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(prc.PolicyIntegrityError):
                prc.load_and_verify_policy(tampered)
        finally:
            tampered.unlink()

    def test_policy_code_regex_drift_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["rules"][0]["anchored_regex"] = "at 0x.*>"
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        drifted = self.POLICY_PATH.parent / "tests" / "_tmp_drifted_prc_policy.json"
        drifted.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(prc.PolicyIntegrityError):
                prc.load_and_verify_policy(drifted)
        finally:
            drifted.unlink()

    def test_wrong_policy_type_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_type"] = "n2d1b-cargo-test-capture-canonicalization-policy-v1"
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_type = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_type_prc_policy.json"
        wrong_type.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(prc.PolicyIntegrityError):
                prc.load_and_verify_policy(wrong_type)
        finally:
            wrong_type.unlink()

    def test_wrong_policy_version_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["policy_version"] = 2
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_version = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_version_prc_policy.json"
        wrong_version.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(prc.PolicyIntegrityError):
                prc.load_and_verify_policy(wrong_version)
        finally:
            wrong_version.unlink()

    def test_applying_to_a_case_other_than_repo_requests_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["applicable_case_ids"] = ["repo-moshi"]
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        wrong_case = self.POLICY_PATH.parent / "tests" / "_tmp_wrong_case_prc_policy.json"
        wrong_case.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(prc.PolicyIntegrityError):
                prc.load_and_verify_policy(wrong_case)
        finally:
            wrong_case.unlink()

    def test_empty_applicable_case_ids_fails(self):
        body = json.loads(self.POLICY_PATH.read_text())
        body["applicable_case_ids"] = []
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
        body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        empty_cases = self.POLICY_PATH.parent / "tests" / "_tmp_empty_cases_prc_policy.json"
        empty_cases.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        try:
            with self.assertRaises(prc.PolicyIntegrityError):
                prc.load_and_verify_policy(empty_cases)
        finally:
            empty_cases.unlink()


if __name__ == "__main__":
    unittest.main()
