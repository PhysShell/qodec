"""Promotion P5.2A (caddy Go): rtk-go-test-summary-v1 -- PROVE the existing frozen policy's semantics
+ source identity against the pinned RTK go filter's OWN sample I/O (rtk-ai/rtk @5d32d07,
src/cmds/go/go_cmd.rs::filter_go_test_json), case-scoped to caddy. The critical go-specific rules:
package-level fail after a test fail is a cascade (no double-count); a package-level fail with no
failing test (timeout) is one failure, not "No tests".
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_go_test_dialect as go  # noqa: E402

RAW_PASS = b"""{"Action":"run","Package":"example.com/foo","Test":"TestBar"}
{"Action":"pass","Package":"example.com/foo","Test":"TestBar","Elapsed":0.5}
{"Action":"pass","Package":"example.com/foo","Elapsed":0.5}"""

RAW_FAIL = b"""{"Action":"run","Package":"example.com/foo","Test":"TestFail"}
{"Action":"output","Package":"example.com/foo","Test":"TestFail","Output":"    Error: expected 5, got 3\\n"}
{"Action":"fail","Package":"example.com/foo","Test":"TestFail","Elapsed":0.5}
{"Action":"fail","Package":"example.com/foo","Elapsed":0.5}"""

RAW_TIMEOUT = b"""{"Action":"start","Package":"example.com/foo"}
{"Action":"output","Package":"example.com/foo","Output":"*** Test killed with quit: ran too long (1m3s).\\n"}
{"Action":"fail","Package":"example.com/foo","Elapsed":63.003}"""

RTK_PASS = b"Go test: 1 passed, 1 packages"
RTK_FAIL = b"Go test: 1 failed, 1 packages\n--- FAIL: TestFail"


class TestGoDialect(unittest.TestCase):
    def test_all_pass(self):
        p = go.parse_raw(RAW_PASS)
        self.assertEqual((p["outcome"], p["passed"], p["failed"], p["packages"]), ("success", 1, 0, 1))

    def test_failure_no_double_count(self):
        # test fail + cascade package fail -> exactly 1 failed
        p = go.parse_raw(RAW_FAIL)
        self.assertEqual((p["outcome"], p["failed"]), ("failure", 1))
        self.assertEqual(p["failing_ids"], ["example.com/foo::TestFail"])

    def test_timeout_package_fail_is_one_failure_not_no_tests(self):
        p = go.parse_raw(RAW_TIMEOUT)
        self.assertEqual((p["outcome"], p["failed"]), ("failure", 1))
        self.assertNotEqual(p["outcome"], "no_tests")

    # ---- RAW json <-> RTK compact equivalence ----
    def test_pass_equivalence(self):
        eq = go.equivalence(go.parse_raw(RAW_PASS), go.parse_rtk(RTK_PASS))
        self.assertTrue(eq["equivalent"], eq["mismatches"])

    def test_fail_equivalence(self):
        eq = go.equivalence(go.parse_raw(RAW_FAIL), go.parse_rtk(RTK_FAIL))
        self.assertTrue(eq["equivalent"], eq["mismatches"])

    def test_ansi_crlf_non_semantic(self):
        noisy = RAW_FAIL.replace(b"\n", b"\r\n")
        self.assertEqual(go.parse_raw(noisy)["failed"], go.parse_raw(RAW_FAIL)["failed"])

    # ---- semantic differences break equivalence ----
    def test_hidden_failure_breaks_equivalence(self):
        eq = go.equivalence(go.parse_raw(RAW_FAIL), go.parse_rtk(RTK_PASS))
        self.assertFalse(eq["equivalent"])

    def test_wrong_count_breaks_equivalence(self):
        eq = go.equivalence(go.parse_raw(RAW_PASS), go.parse_rtk(b"Go test: 2 passed, 1 packages"))
        self.assertFalse(eq["equivalent"])

    # ---- never manufactures a PASS ----
    def test_no_json_is_indeterminate(self):
        p = go.parse_raw(b"some non-json noise\n")
        self.assertEqual(p["outcome"], "indeterminate")
        self.assertFalse(p["terminal_summary_present"])


if __name__ == "__main__":
    unittest.main()
