"""rtk-rust-cargo-test-summary-v1 dialect: semantic-projection + RAW<->RTK equivalence, grounded in
rtk @5d32d07 filter_cargo_test. GREEN closes the real captured streams (byte + semantic); the
source-grounded negatives and the byte-stream/semantic mutation matrix all fail closed.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_rust_cargo_dialect as D  # noqa: E402

STREAMS = N2E_DIR / "evidence/coreutils-6731/rtk-rust-cargo-dialect/streams"


def _rd(n):
    return (STREAMS / n).read_bytes()


# ---- source-grounded fixtures (constructed to the exact cargo / RTK @5d32d07 grammar) ----
RTK_PASS = b"cargo test: 10 passed, 3205 filtered out (3 suites, <dur>)\n"
RTK_FAIL = (b"FAILURES (2):\n1. ---- test_tr::t stdout ----\n2. ---- test_x::y stdout ----\n\n"
            b"test result: FAILED. 8 passed; 2 failed; 0 ignored; 0 measured; 5 filtered out\n")
RAW_FAIL = (b"running 10 tests\ntest test_tr::t ... FAILED\ntest test_x::y ... FAILED\n\n"
            b"failures:\n    test_tr::t\n    test_x::y\n\n"
            b"test result: FAILED. 8 passed; 2 failed; 0 ignored; 0 measured; 5 filtered out\n")
RTK_COMPILE = b"cargo test (0 crates compiled)\nerror[E0308]: mismatched types\n"
RAW_COMPILE = b"   Compiling coreutils v0.0.27\nerror[E0308]: mismatched types\n --> src/x.rs:1\n"
RTK_NOSUMMARY = b"running 10 tests\n"
RTK_MALFORMED = b"cargo test: lots of tests passed somewhere (unknown)\n"


class TestGreenRealStreams(unittest.TestCase):
    def test_real_streams_close_byte_and_semantic(self):
        rawc = D.parse_raw(_rd("raw.canonical.rep0.bin"))
        rtkc = D.parse_rtk(_rd("rtk.canonical.rep0.bin"))
        self.assertEqual(rawc["outcome"], "success")
        self.assertEqual((rawc["passed"], rawc["failed"], rawc["filtered_out"], rawc["suites"]),
                         (10, 0, 3205, 3))
        self.assertEqual((rtkc["passed"], rtkc["failed"], rtkc["filtered_out"], rtkc["suites"]),
                         (10, 0, 3205, 3))
        self.assertTrue(D.equivalence(rawc, rtkc)["equivalent"])

    def test_canonicalization_preserves_projection(self):
        self.assertEqual(D.parse_raw(_rd("raw.canonical.rep0.bin")), D.parse_raw(_rd("raw.raw.rep0.bin")))
        self.assertEqual(D.parse_rtk(_rd("rtk.canonical.rep0.bin")), D.parse_rtk(_rd("rtk.raw.rep0.bin")))

    def test_all_three_reps_project_identically(self):
        self.assertEqual({D.parse_rtk(_rd(f"rtk.canonical.rep{i}.bin"))["outcome"] for i in range(3)},
                         {"success"})


class TestSourceGroundedNegatives(unittest.TestCase):
    def test_test_failure(self):
        rtk = D.parse_rtk(RTK_FAIL)
        self.assertEqual(rtk["outcome"], "failure")
        self.assertEqual(rtk["failing_ids"], ["test_tr::t", "test_x::y"])
        self.assertEqual((rtk["passed"], rtk["failed"]), (8, 2))
        raw = D.parse_raw(RAW_FAIL)
        self.assertEqual(raw["outcome"], "failure")
        self.assertEqual(raw["failing_ids"], ["test_tr::t", "test_x::y"])
        self.assertTrue(D.equivalence(raw, rtk)["equivalent"])

    def test_compile_failure_distinct_from_test_failure(self):
        rtk = D.parse_rtk(RTK_COMPILE)
        raw = D.parse_raw(RAW_COMPILE)
        self.assertTrue(rtk["compile_failure"] and rtk["outcome"] == "compile_failure")
        self.assertTrue(raw["compile_failure"] and raw["outcome"] == "compile_failure")
        self.assertTrue(D.equivalence(raw, rtk)["equivalent"])
        # a compile failure is NOT equivalent to a test failure
        self.assertFalse(D.equivalence(D.parse_raw(RAW_FAIL), rtk)["equivalent"])

    def test_truncated_stream(self):
        trunc = RTK_PASS.rstrip(b"\n")[:30]  # cut mid-line, no newline
        self.assertTrue(D.parse_rtk(trunc)["truncated"])
        # truncated RTK vs complete RAW -> not equivalent
        self.assertFalse(D.equivalence(D.parse_raw(_rd("raw.canonical.rep0.bin")),
                                       D.parse_rtk(trunc))["equivalent"])

    def test_missing_summary_never_success(self):
        p = D.parse_rtk(RTK_NOSUMMARY)
        self.assertEqual(p["outcome"], "incomplete")
        self.assertFalse(p["terminal_summary_present"])

    def test_malformed_rtk_incomplete(self):
        self.assertEqual(D.parse_rtk(RTK_MALFORMED)["outcome"], "incomplete")

    def test_contradictory_totals_rtk(self):
        # a compact summary whose totals contradict the RAW -> equivalence fails
        rtk = D.parse_rtk(b"cargo test: 11 passed, 3205 filtered out (3 suites, <dur>)\n")
        raw = D.parse_raw(_rd("raw.canonical.rep0.bin"))
        self.assertFalse(D.equivalence(raw, rtk)["equivalent"])


class TestByteStreamMutations(unittest.TestCase):
    def test_rtk_byte_changed_count(self):
        raw = D.parse_raw(_rd("raw.canonical.rep0.bin"))
        rtk = D.parse_rtk(b"cargo test: 9 passed, 3205 filtered out (3 suites, <dur>)\n")
        self.assertFalse(D.equivalence(raw, rtk)["equivalent"])

    def test_failure_line_removed(self):
        # drop one failing id from the RTK failure block -> failing_ids diverge
        mutated = RTK_FAIL.replace(b"2. ---- test_x::y stdout ----\n", b"")
        rtk = D.parse_rtk(mutated)
        self.assertEqual(rtk["failing_ids"], ["test_tr::t"])
        self.assertFalse(D.equivalence(D.parse_raw(RAW_FAIL), rtk)["equivalent"])

    def test_synthetic_success_appended_after_failure(self):
        # appending a success compact line after a real failure must NOT flip to success
        mutated = RTK_FAIL + RTK_PASS
        p = D.parse_rtk(mutated)
        self.assertEqual(p["outcome"], "failure")  # FAILED summary still wins; never success

    def test_duplicate_terminal_summary_rejected(self):
        # two compact all-pass summaries is malformed -> incomplete (not a valid single terminal)
        p = D.parse_rtk(RTK_PASS + RTK_PASS)
        self.assertEqual(p["outcome"], "incomplete")

    def test_crlf_and_ansi_are_allowed_normalizations(self):
        # CRLF + ANSI colour around the SAME semantics -> identical projection (allowed noise)
        noisy = b"\x1b[32m" + RTK_PASS.rstrip(b"\n").replace(b"\n", b"\r\n") + b"\x1b[0m\r\n"
        self.assertEqual(D.parse_rtk(noisy)["outcome"], "success")
        self.assertEqual(D.parse_rtk(noisy)["passed"], 10)

    def test_out_of_grammar_duration_not_a_semantic_change(self):
        # raw RTK (0.05s) and v3-canonical (<dur>) project identically (duration is presentation)
        self.assertEqual(D.parse_rtk(b"cargo test: 10 passed, 3205 filtered out (3 suites, 0.05s)\n"),
                         D.parse_rtk(RTK_PASS))


class TestSemanticMutations(unittest.TestCase):
    def _raw(self):
        return D.parse_raw(_rd("raw.canonical.rep0.bin"))

    def test_passed_count_changed(self):
        rtk = dict(D.parse_rtk(RTK_PASS)); rtk["passed"] = 9
        self.assertFalse(D.equivalence(self._raw(), rtk)["equivalent"])

    def test_filtered_count_changed(self):
        rtk = dict(D.parse_rtk(RTK_PASS)); rtk["filtered_out"] = 3204
        self.assertFalse(D.equivalence(self._raw(), rtk)["equivalent"])

    def test_ignored_count_changed(self):
        rtk = dict(D.parse_rtk(RTK_PASS)); rtk["ignored"] = 1
        self.assertFalse(D.equivalence(self._raw(), rtk)["equivalent"])

    def test_measured_loss_when_raw_has_measured(self):
        # RTK compact omits measured; that is only lossless when RAW measured==0
        raw = dict(self._raw()); raw["measured"] = 2
        self.assertFalse(D.equivalence(raw, D.parse_rtk(RTK_PASS))["equivalent"])

    def test_failing_id_removed(self):
        rtk = dict(D.parse_rtk(RTK_FAIL)); rtk["failing_ids"] = ["test_tr::t"]
        self.assertFalse(D.equivalence(D.parse_raw(RAW_FAIL), rtk)["equivalent"])

    def test_compile_fail_reclassified_as_test_fail(self):
        raw = D.parse_raw(RAW_COMPILE)  # compile_failure
        rtk = D.parse_rtk(RTK_FAIL)     # test failure
        self.assertFalse(D.equivalence(raw, rtk)["equivalent"])

    def test_missing_summary_interpreted_as_success(self):
        raw = self._raw()                     # success, summary present
        rtk = D.parse_rtk(RTK_NOSUMMARY)      # incomplete, no summary
        self.assertFalse(D.equivalence(raw, rtk)["equivalent"])

    def test_projections_disagree_predicate_false(self):
        raw = self._raw()
        rtk = D.parse_rtk(RTK_FAIL)  # RAW success vs RTK failure
        self.assertFalse(D.equivalence(raw, rtk)["equivalent"])


if __name__ == "__main__":
    unittest.main()
