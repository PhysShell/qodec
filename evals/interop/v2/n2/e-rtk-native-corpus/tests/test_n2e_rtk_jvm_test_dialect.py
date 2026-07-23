"""Promotion P5.2A (lucene JVM): the rtk-jvm-test-summary-v1 semantics, proven against the pinned
RTK filter's OWN sample I/O (rtk-ai/rtk @5d32d07, src/cmds/jvm/gradlew_cmd.rs::filter_test). The RAW
gradle stream and the RTK-filtered stream must project to the same semantic verdict; presentation
(PASSED/SKIPPED lines, framework frames, task noise, BUILD duration) is non-semantic; a real
semantic difference (a failure the RTK stream hides, a wrong count) breaks equivalence.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_jvm_test_dialect as jvm  # noqa: E402

# ---- verbatim from gradlew_cmd.rs::test_unit_test_failures_preserved_passes_stripped ----
RAW_FAIL = b"""> Task :app:testDebugUnitTest
com.example.FooTest > test1 PASSED
com.example.FooTest > test2 PASSED
com.example.FooTest > test3 PASSED
com.example.FooTest > test4 PASSED
com.example.FooTest > test5 PASSED
com.example.FooTest > test6 PASSED
com.example.FooTest > test7 PASSED
com.example.FooTest > testBar FAILED
    java.lang.AssertionError: expected:<3> but was:<-1>
        at org.junit.Assert.fail(Assert.java:89)
        at org.junit.Assert.assertEquals(Assert.java:197)
        at com.example.FooTest.testBar(FooTest.kt:25)
com.example.FooTest > testQux PASSED

10 tests completed, 1 failed"""

# what filter_test emits for the above (PASSED stripped, framework frames dropped)
RTK_FAIL = b"""com.example.FooTest > testBar FAILED
    java.lang.AssertionError: expected:<3> but was:<-1>
        at com.example.FooTest.testBar(FooTest.kt:25)
10 tests completed, 1 failed"""

# gradle default success (no testLogging): test_unit_test_gradle_default_no_testlogging
RAW_OK = b"""> Task :app:testDebugUnitTest

BUILD SUCCESSFUL in 15s
3 actionable tasks: 1 executed, 2 up-to-date"""
RTK_OK = b"""BUILD SUCCESSFUL in 15s
3 actionable tasks: 1 executed, 2 up-to-date"""


class TestJvmDialect(unittest.TestCase):
    # ---------- projection is source-faithful ----------
    def test_fail_projection(self):
        p = jvm.parse_raw(RAW_FAIL)
        self.assertEqual(p["outcome"], "failure")
        self.assertEqual(p["tests_completed"], 10)
        self.assertEqual(p["tests_failed"], 1)
        self.assertEqual(p["failing_ids"], ["com.example.FooTest > testBar"])
        self.assertTrue(p["terminal_summary_present"])

    def test_ok_projection(self):
        p = jvm.parse_raw(RAW_OK)
        self.assertEqual(p["outcome"], "success")
        self.assertEqual(p["tests_failed"], 0)
        self.assertEqual(p["failing_ids"], [])
        self.assertTrue(p["terminal_summary_present"])

    # ---------- RAW <-> RTK equivalence over the pinned filter's own I/O ----------
    def test_fail_equivalence(self):
        eq = jvm.equivalence(jvm.parse_raw(RAW_FAIL), jvm.parse_rtk(RTK_FAIL))
        self.assertTrue(eq["equivalent"], eq["mismatches"])

    def test_ok_equivalence(self):
        eq = jvm.equivalence(jvm.parse_raw(RAW_OK), jvm.parse_rtk(RTK_OK))
        self.assertTrue(eq["equivalent"], eq["mismatches"])

    # ---------- presentation is non-semantic ----------
    def test_ansi_and_crlf_normalized(self):
        noisy = RAW_FAIL.replace(b"testBar FAILED", b"\x1b[31mtestBar FAILED\x1b[0m").replace(b"\n", b"\r\n")
        self.assertEqual(jvm.parse_raw(noisy), jvm.parse_raw(RAW_FAIL))

    def test_build_duration_normalized(self):
        a = jvm.parse_raw(RAW_OK)
        b = jvm.parse_raw(RAW_OK.replace(b"in 15s", b"in 1m 42s"))
        self.assertEqual(a, b)

    # ---------- semantic differences BREAK equivalence ----------
    def test_hidden_failure_breaks_equivalence(self):
        # RTK stream drops the failure entirely and claims all-completed -> not equivalent
        rtk_lying = b"10 tests completed"
        eq = jvm.equivalence(jvm.parse_raw(RAW_FAIL), jvm.parse_rtk(rtk_lying))
        self.assertFalse(eq["equivalent"])

    def test_wrong_count_breaks_equivalence(self):
        rtk_wrong = RTK_FAIL.replace(b"10 tests completed, 1 failed", b"9 tests completed, 1 failed")
        eq = jvm.equivalence(jvm.parse_raw(RAW_FAIL), jvm.parse_rtk(rtk_wrong))
        self.assertFalse(eq["equivalent"])

    def test_different_failing_id_breaks_equivalence(self):
        rtk_wrong = RTK_FAIL.replace(b"testBar FAILED", b"testZzz FAILED")
        eq = jvm.equivalence(jvm.parse_raw(RAW_FAIL), jvm.parse_rtk(rtk_wrong))
        self.assertFalse(eq["equivalent"])

    def test_pass_vs_fail_outcome_breaks_equivalence(self):
        eq = jvm.equivalence(jvm.parse_raw(RAW_FAIL), jvm.parse_rtk(RTK_OK))
        self.assertFalse(eq["equivalent"])

    # ---------- never manufactures a PASS ----------
    def test_no_summary_is_indeterminate_not_pass(self):
        p = jvm.parse_raw(b"> Task :app:testDebugUnitTest\nsome noise\n")
        self.assertNotEqual(p["outcome"], "success")
        self.assertFalse(p["terminal_summary_present"])


if __name__ == "__main__":
    unittest.main()
