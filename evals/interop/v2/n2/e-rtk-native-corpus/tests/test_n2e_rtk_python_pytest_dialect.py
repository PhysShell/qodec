"""Promotion P5.2A (scrapy Python): rtk-python-pytest-summary-v1 semantics, proven against the pinned
RTK pytest filter's OWN sample I/O (rtk-ai/rtk @5d32d07, src/cmds/python/pytest_cmd.rs). The RAW full
pytest output and the RTK compact `Pytest: ...` form must project the same counts + failing ids; a
hidden failure or wrong count breaks equivalence; `no tests ran` is never a manufactured PASS.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_python_pytest_dialect as py  # noqa: E402

# verbatim from test_filter_pytest_with_failures
RAW_FAIL = b"""=== test session starts ===
collected 5 items

tests/test_foo.py ..F..                                            [100%]

=== FAILURES ===
___ test_something ___

    def test_something():
>       assert False
E       assert False

tests/test_foo.py:10: AssertionError

=== short test summary info ===
FAILED tests/test_foo.py::test_something - assert False
=== 4 passed, 1 failed in 0.50s ==="""

# the RTK compact form build_pytest_summary emits for the same run
RTK_FAIL = b"""Pytest: 4 passed, 1 failed
FAILED tests/test_foo.py::test_something - assert False"""

RAW_PASS = b"""=== test session starts ===
collected 5 items

tests/test_foo.py .....                                            [100%]

=== 5 passed in 0.50s ==="""
RTK_PASS = b"Pytest: 5 passed"

RAW_QUIET = b"5 failed, 1698 passed, 2 skipped in 108.89s"


class TestPytestDialect(unittest.TestCase):
    def test_fail_projection(self):
        p = py.parse_raw(RAW_FAIL)
        self.assertEqual((p["outcome"], p["passed"], p["failed"]), ("failure", 4, 1))
        self.assertEqual(p["failing_ids"], ["tests/test_foo.py::test_something"])
        self.assertTrue(p["terminal_summary_present"])

    def test_pass_projection(self):
        p = py.parse_raw(RAW_PASS)
        self.assertEqual((p["outcome"], p["passed"], p["failed"]), ("success", 5, 0))
        self.assertEqual(p["failing_ids"], [])

    def test_quiet_mode_projection(self):
        p = py.parse_raw(RAW_QUIET)
        self.assertEqual((p["passed"], p["failed"], p["skipped"]), (1698, 5, 2))
        self.assertEqual(p["outcome"], "failure")

    def test_xpassed_xfailed_not_confused_with_passed_failed(self):
        p = py.parse_raw(b"=== 4 passed, 1 failed, 2 xfailed, 1 xpassed in 0.50s ===")
        self.assertEqual((p["passed"], p["failed"], p["xfailed"], p["xpassed"]), (4, 1, 2, 1))

    # ---- RAW <-> RTK compact equivalence ----
    def test_fail_equivalence(self):
        eq = py.equivalence(py.parse_raw(RAW_FAIL), py.parse_rtk(RTK_FAIL))
        self.assertTrue(eq["equivalent"], eq["mismatches"])

    def test_pass_equivalence(self):
        eq = py.equivalence(py.parse_raw(RAW_PASS), py.parse_rtk(RTK_PASS))
        self.assertTrue(eq["equivalent"], eq["mismatches"])

    def test_ansi_crlf_duration_non_semantic(self):
        noisy = RAW_FAIL.replace(b"FAILED", b"\x1b[31mFAILED\x1b[0m", 1).replace(b"\n", b"\r\n").replace(b"in 0.50s", b"in 12.34s")
        self.assertEqual(py.parse_raw(noisy), py.parse_raw(RAW_FAIL))

    # ---- semantic differences break equivalence ----
    def test_hidden_failure_breaks_equivalence(self):
        eq = py.equivalence(py.parse_raw(RAW_FAIL), py.parse_rtk(b"Pytest: 5 passed"))
        self.assertFalse(eq["equivalent"])

    def test_wrong_count_breaks_equivalence(self):
        eq = py.equivalence(py.parse_raw(RAW_FAIL), py.parse_rtk(b"Pytest: 3 passed, 1 failed\nFAILED tests/test_foo.py::test_something - assert False"))
        self.assertFalse(eq["equivalent"])

    def test_different_failing_id_breaks_equivalence(self):
        eq = py.equivalence(py.parse_raw(RAW_FAIL), py.parse_rtk(b"Pytest: 4 passed, 1 failed\nFAILED tests/test_foo.py::test_other - assert False"))
        self.assertFalse(eq["equivalent"])

    # ---- never manufactures a PASS ----
    def test_no_tests_ran_is_not_pass(self):
        p = py.parse_raw(b"=== test session starts ===\ncollected 0 items\n\n=== no tests ran in 0.00s ===")
        self.assertEqual(p["outcome"], "no_tests")
        self.assertEqual(p["passed"], 0)

    def test_no_summary_indeterminate(self):
        p = py.parse_raw(b"=== test session starts ===\ncollected 5 items\n")
        self.assertEqual(p["outcome"], "indeterminate")
        self.assertFalse(p["terminal_summary_present"])


if __name__ == "__main__":
    unittest.main()
